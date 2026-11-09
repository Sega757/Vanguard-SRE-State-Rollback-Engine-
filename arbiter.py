"""arbiter.py: жизненный цикл шага и трёхслойный откат (контекст + воркспейс/процессы + эффекты).

Протокол шага:
  1. Арбитр сам определяет класс шага по ToolSchema (флаги от агента вырезаются).
  2. Блобы (аргументы, история) пишутся ДО события STEP_STARTED.
  3. Эффекты идут через EffectLedger (Replay / UNKNOWN / approval).
  4. Терминальный шаг проверяется внешним верификатором. SUCCESS: git-коммит -> STEP_COMPLETED -> ANCHOR_COMMITTED.
  5. PATCH: ROLLBACK_TRIGGERED (WAL) -> restore воркспейса (+ убийство процессов) -> история из снапшота ->
     STATE_PRUNED -> [REPLAN_STARTED] -> [ESCALATED] -> CONSTRAINT_INJECTED. Незавершённый откат
     доводится при следующем старте.
  6. TEST (флаки/сломанный baseline) и ENV откат НЕ запускают.

Ограничение (негативный контракт) идёт отдельным user-сообщением В КОНЦЕ промпта (build_prompt), а не в
системный префикс и не в снапшоты: префикс-кэш не страдает, дублей уведомлений нет.
После перезапуска процесса арбитр возвращается к последнему якорю (наблюдения без якоря не сохраняются).
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Callable

from audit import Dag, FailureClass, LoopSignal, Node, Verdict
from blobstore import BlobStore
from effects import (ApprovalRequired, EffectLedger, ToolSchema, ToolSchemaError, UnknownEffectState,
                     canonical_json)
from transponder import Transponder, canonical
from verifier import ExternalVerifier, VerificationResult, sanitize_exc_type, sanitize_path
from workspace import WorkspaceManager

FORBIDDEN_AGENT_FLAGS = frozenset(
    {"intermediate_step", "allow_nested_probe", "skip_verification", "force_success", "step_kind",
     "idempotency_key", "effect_class", "terminal"}
)
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,40}$")
_CASE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


class ArbiterStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ESCALATED = "ESCALATED"
    ROLLBACK_PARTIAL = "ROLLBACK_PARTIAL"


class ArbiterClosed(RuntimeError):
    """Арбитр в статусе ESCALATED / ROLLBACK_PARTIAL: шаги запрещены."""


class RollbackPartialError(RuntimeError):
    """Откат прервался; ветка эскалирована."""


# ---------- фингерпринт патча (структурный хеш AST) ----------
class _Canon(ast.NodeTransformer):
    """Снимает докстринги и аннотации, локальные имена функции переименовывает в _v0, _v1..."""

    def __init__(self) -> None:
        self._map: dict[str, str] = {}

    @staticmethod
    def _strip_doc(body: list[ast.stmt]) -> list[ast.stmt]:
        if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                and isinstance(body[0].value.value, str):
            return body[1:] or [ast.Pass()]
        return body

    @staticmethod
    def _locals(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        names: list[str] = []
        declared_outer: set[str] = set()
        args = fn.args
        for a in args.posonlyargs + args.args + args.kwonlyargs + ([args.vararg] if args.vararg else []) \
                + ([args.kwarg] if args.kwarg else []):
            if a.arg not in ("self", "cls"):
                names.append(a.arg)
        stack: list[ast.AST] = list(fn.body)
        while stack:
            n = stack.pop(0)
            if isinstance(n, (ast.Global, ast.Nonlocal)):
                declared_outer.update(n.names)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
                names.append(n.id)
            if isinstance(n, ast.ExceptHandler) and n.name:
                names.append(n.name)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
                continue
            stack.extend(ast.iter_child_nodes(n))
        seen: list[str] = []
        for nm in names:
            if nm not in declared_outer and nm not in seen:
                seen.append(nm)
        return seen

    def visit_Module(self, node: ast.Module) -> ast.AST:
        node.body = self._strip_doc(node.body)
        return self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
        node.body = self._strip_doc(node.body)
        return self.generic_visit(node)

    def _func(self, node: Any) -> ast.AST:
        saved = self._map
        self._map = {nm: f"_v{i}" for i, nm in enumerate(self._locals(node))}
        node.body = self._strip_doc(node.body)
        node.returns = None
        for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs + \
                [x for x in (node.args.vararg, node.args.kwarg) if x]:
            a.annotation = None
        self.generic_visit(node)
        self._map = saved
        return node

    visit_FunctionDef = _func
    visit_AsyncFunctionDef = _func

    def visit_arg(self, node: ast.arg) -> ast.AST:
        node.arg = self._map.get(node.arg, node.arg)
        return node

    def visit_Name(self, node: ast.Name) -> ast.AST:
        node.id = self._map.get(node.id, node.id)
        return node

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> ast.AST:
        if node.name:
            node.name = self._map.get(node.name, node.name)
        return self.generic_visit(node)


def compute_patch_fingerprint(code: str) -> str:
    """sha256 канонического AST; для не-Python текста: нормализованные строки без комментариев."""
    try:
        tree = _Canon().visit(ast.parse(code))
        return hashlib.sha256(("ast:" + ast.dump(tree, include_attributes=False)).encode()).hexdigest()
    except (SyntaxError, ValueError):
        lines = [re.sub(r"\s+", " ", ln.strip()) for ln in code.splitlines()
                 if ln.strip() and not ln.strip().startswith("#")]
        return hashlib.sha256(("text:" + "\n".join(lines)).encode()).hexdigest()


# ---------- ограничение ----------
@dataclass(frozen=True)
class Constraint:
    attempt: int
    case_id: str
    file: str
    line: int
    exc_type: str
    scope: str
    fingerprint: str
    contract: str

    def render(self) -> str:
        return (
            "[ROLLBACK NOTICE]\n"
            f"Attempt {self.attempt} was reverted to the last verified state.\n"
            f"Failed check: {self.case_id} ({self.file}:{self.line}), {self.exc_type}.\n"
            f"Changed: {self.scope}.\n"
            f"Required: {self.contract}\n"
            "A change identical to a reverted one is rejected before execution."
        )

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Constraint":
        return cls(int(d["attempt"]), str(d["case_id"]), str(d["file"]), int(d["line"]), str(d["exc_type"]),
                   str(d["scope"]), str(d["fingerprint"]), str(d["contract"]))


@dataclass
class StepOutcome:
    sid: str
    status: str   # OBSERVED SUCCESS FAILED_TEST FAILED_ENV FAILED_TOOL ROLLED_BACK REJECTED_REPEAT REJECTED_DIAGNOSTIC ESCALATED
    anchor_sid: str
    replayed: bool = False
    loop: LoopSignal | None = None
    verification: VerificationResult | None = None
    escalated: bool = False


class Arbiter:
    def __init__(
        self,
        workspace: WorkspaceManager,
        transponder: Transponder,
        verifier: ExternalVerifier,
        tools: dict[str, ToolSchema],
        initial_messages: list[dict[str, str]],
        *,
        session: str = "session-1",
        approve: Callable[[str, dict[str, Any]], bool] | None = None,
        max_retries_per_anchor: int = 3,
        max_total_rollbacks: int = 8,
        max_constraints: int = 5,
        max_repeat_rejects: int = 3,
        replan_steps: int = 2,
    ) -> None:
        self.ws = workspace
        self.tp = transponder
        self.blobs: BlobStore = transponder.blobs
        self.verifier = verifier
        self.tools = dict(tools)
        self.max_retries = max_retries_per_anchor
        self.max_total = max_total_rollbacks
        self.max_constraints = max_constraints
        self.max_repeat_rejects = max_repeat_rejects
        self.replan_steps = replan_steps

        self.ledger = EffectLedger(transponder, session, approve)
        self.dag = Dag.from_events(transponder.events)
        self.messages: list[dict[str, str]] = [dict(m) for m in initial_messages]
        self.constraints: list[Constraint] = []
        self.status = ArbiterStatus.ACTIVE
        self.total_rollbacks = 0
        self.anchor_failures: dict[str, int] = {}
        self.replans_used = 0
        self.replan_left = 0
        self.repeat_rejects = 0
        self.anchor_sid = ""
        self.tip_sid = ""
        self._busy = False

        if not self.dag.nodes:
            self._bootstrap()
        else:
            self._recover()

    # ---------- события / снапшоты ----------
    def _emit(self, etype: str, sid: str, pid: str | None, payload: dict[str, Any], blobs: list[str] | None = None) -> dict[str, Any]:
        ev = self.tp.emit(etype, sid, pid, payload, blobs or [])
        self.dag.apply(ev)
        return ev

    def _store_messages(self) -> str:
        return self.blobs.put(canonical({"messages": self.messages}))

    def _load_messages(self, digest: str) -> list[dict[str, str]]:
        return [dict(m) for m in json.loads(self.blobs.get(digest).decode("utf-8"))["messages"]]

    def _snapshot_dict(self, ws_snap: Any, msg_blob: str) -> dict[str, Any]:
        return {"msg": msg_blob, "commit": ws_snap.commit, "tree": ws_snap.tree, "manifest": ws_snap.manifest,
                "env": ws_snap.env_hash, "effects": self.ledger.ref()}

    def build_prompt(self) -> list[dict[str, str]]:
        """История + (в конце) активные ограничения. Префикс истории не меняется между откатами."""
        prompt = [dict(m) for m in self.messages]
        if self.constraints:
            prompt.append({"role": "user", "content": "\n\n".join(c.render() for c in self.constraints)})
        return prompt

    # ---------- старт ----------
    def _bootstrap(self) -> None:
        snap = self.ws.snapshot("root")
        self.verifier.calibrate_baseline(snap.commit)
        msg_blob = self._store_messages()
        sid = "root_" + uuid.uuid4().hex[:10]
        sd = self._snapshot_dict(snap, msg_blob)
        self._emit("STEP_STARTED", sid, None, {"kind": "root", "snapshot": sd}, [msg_blob])
        self._emit("STEP_COMPLETED", sid, None, {"verdict": "SUCCESS", "failure_class": "NONE"})
        self._emit("ANCHOR_COMMITTED", sid, None, {"snapshot": sd}, [msg_blob])
        self.anchor_sid = self.tip_sid = sid

    def _last_anchor(self) -> Node:
        anchors = [n for n in self.dag.nodes.values() if n.anchor and not n.pruned]
        if not anchors:
            raise RuntimeError("no live anchor in the log")
        return anchors[-1]

    def _recover(self) -> None:
        events = self.tp.events
        last_trigger: int | None = None
        last_close = -1
        for i, ev in enumerate(events):
            t = ev["type"]
            if t == "ROLLBACK_TRIGGERED":
                last_trigger = i
                self.total_rollbacks += 1
                self.anchor_failures[ev["payload"]["failed_anchor"]] = \
                    self.anchor_failures.get(ev["payload"]["failed_anchor"], 0) + 1
                if ev["payload"]["replan"]:
                    self.anchor_failures[ev["payload"]["failed_anchor"]] = 0
            elif t == "CONSTRAINT_INJECTED":
                self._add_constraint(Constraint.from_dict(ev["payload"]["constraint"]))
                last_close = i
            elif t == "ROLLBACK_PARTIAL":
                last_close = i
                self.status = ArbiterStatus.ROLLBACK_PARTIAL
            elif t == "REPLAN_STARTED":
                self.replans_used += 1
            elif t == "ESCALATED" and self.status == ArbiterStatus.ACTIVE:
                self.status = ArbiterStatus.ESCALATED
        if last_trigger is not None and last_trigger > last_close:
            self._apply_rollback(events[last_trigger]["payload"], events[last_trigger + 1:])
            return
        anchor = self._last_anchor()
        self.ws.restore(anchor.snapshot["commit"])
        self.messages = self._load_messages(anchor.snapshot["msg"])
        keep = {n.sid for n in self.dag.ancestors(anchor.sid)} | {anchor.sid}
        dangling = [n.sid for n in self.dag.nodes.values()
                    if not n.pruned and not n.anchor and n.kind != "root" and n.sid not in keep]
        if dangling:
            self._emit("STATE_PRUNED", anchor.sid, None, {"pruned_sids": dangling, "reason": "restart"})
        if self.verifier.baseline(anchor.snapshot["commit"]) is None:
            self.verifier.calibrate_baseline(anchor.snapshot["commit"])
        self.anchor_sid = self.tip_sid = anchor.sid

    # ---------- ограничения ----------
    def _add_constraint(self, c: Constraint) -> None:
        self.constraints = [x for x in self.constraints if x.fingerprint != c.fingerprint] + [c]
        self.constraints = self.constraints[-self.max_constraints:]

    def _fingerprint(self, schema: ToolSchema, args: dict[str, Any]) -> str:
        path = str(args.get(schema.path_field, "")) if schema.path_field else ""
        if schema.patch_field and isinstance(args.get(schema.patch_field), str):
            base = compute_patch_fingerprint(args[schema.patch_field])
        else:
            base = hashlib.sha256(canonical(args)).hexdigest()
        return hashlib.sha256(f"{path}\0{base}".encode()).hexdigest()

    def _scope(self, schema: ToolSchema, args: dict[str, Any], anchor_commit: str) -> str:
        """Путь + имена функций/классов, которые СУЩЕСТВОВАЛИ в файле на якоре (имена из кода агента не показываем)."""
        if not schema.path_field:
            return schema.name
        raw_path = str(args.get(schema.path_field, schema.name))
        path = sanitize_path(raw_path)
        old = self.ws.read_at(anchor_commit, raw_path)
        code = args.get(schema.patch_field) if schema.patch_field else None
        names: list[str] = []
        if old is not None and isinstance(code, str):
            try:
                trusted = {n.name for n in ast.walk(ast.parse(old))
                           if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))}
                for n in ast.parse(code).body:
                    if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                            and n.name in trusted and _IDENT.match(n.name):
                        names.append(n.name)
            except (SyntaxError, ValueError):
                pass
        return path + ("::" + ",".join(names[:3]) if names else "")

    # ---------- шаг ----------
    def step(self, tool: str, raw_args: dict[str, Any], assistant_message: str = "") -> StepOutcome:
        if self._busy:
            raise RuntimeError("step already in progress")
        if self.status != ArbiterStatus.ACTIVE:
            raise ArbiterClosed(f"arbiter is {self.status.value}")
        if tool not in self.tools:
            raise KeyError(f"unknown tool {tool!r}")
        self._busy = True
        try:
            return self._step(self.tools[tool], raw_args, assistant_message)
        finally:
            self._busy = False

    def _reject(self, sid: str, reason: str, fp: str) -> None:
        self._emit("STEP_REJECTED", sid, self.tip_sid, {"reason": reason, "fingerprint": fp})

    def _step(self, schema: ToolSchema, raw_args: dict[str, Any], assistant_message: str) -> StepOutcome:
        clean = {k: v for k, v in raw_args.items() if k not in FORBIDDEN_AGENT_FLAGS}
        stripped = sorted(set(raw_args) - set(clean))
        sid = "s_" + uuid.uuid4().hex[:12]
        fp = self._fingerprint(schema, clean)

        if self.replan_left > 0:
            self.replan_left -= 1
            if schema.terminal:
                self._reject(sid, "DIAGNOSTIC_REPLAN", fp)
                return StepOutcome(sid, "REJECTED_DIAGNOSTIC", self.anchor_sid)
        if schema.terminal:
            seen = {n.fingerprint for n in self.dag.failed_below(self.anchor_sid)}
            if fp in seen:
                self.repeat_rejects += 1
                self._reject(sid, "REPEATED_FINGERPRINT", fp)
                if self.repeat_rejects >= self.max_repeat_rejects:
                    self._emit("ESCALATED", self.anchor_sid, None, {"reason": "REPEAT_REJECTS"})
                    self.status = ArbiterStatus.ESCALATED
                    return StepOutcome(sid, "ESCALATED", self.anchor_sid, escalated=True)
                return StepOutcome(sid, "REJECTED_REPEAT", self.anchor_sid)

        args_blob = self.blobs.put(canonical(clean))
        msg_blob = self._store_messages()
        self._emit("STEP_STARTED", sid, self.tip_sid,
                   {"kind": "terminal" if schema.terminal else "non_terminal",
                    "snapshot": {"msg": msg_blob}, "action": {"tool": schema.name, "args": args_blob, "fingerprint": fp},
                    "stripped_flags": stripped},
                   [args_blob, msg_blob])
        self.messages.append({"role": "assistant", "content": assistant_message or f"call {schema.name}"})
        parent = self.tip_sid
        self.tip_sid = sid

        try:
            res = self.ledger.execute(schema, clean)
            tool_text, replayed = res.response, res.replayed
        except (UnknownEffectState, ApprovalRequired) as exc:
            self._emit("STEP_COMPLETED", sid, parent, {"verdict": "FAILED", "failure_class": "UNKNOWN",
                                                       "error_sig": type(exc).__name__})
            self._emit("ESCALATED", sid, None, {"reason": type(exc).__name__})
            self.status = ArbiterStatus.ESCALATED
            return StepOutcome(sid, "ESCALATED", self.anchor_sid, escalated=True)
        except Exception as exc:  # ошибка инструмента: наружу только имя встроенного типа
            name = sanitize_exc_type(type(exc).__name__)
            self.messages.append({"role": "tool", "content": f"tool error: {name}"})
            verdict = "OBSERVED" if not schema.terminal else "FAILED"
            self._emit("STEP_COMPLETED", sid, parent, {"verdict": verdict, "failure_class": "UNKNOWN" if schema.terminal else "NONE",
                                                       "error_sig": name})
            return StepOutcome(sid, "OBSERVED" if not schema.terminal else "FAILED_TOOL", self.anchor_sid)
        self.messages.append({"role": "tool", "content": tool_text})

        if not schema.terminal:
            self._emit("STEP_COMPLETED", sid, parent, {"verdict": "OBSERVED", "failure_class": "NONE"})
            return StepOutcome(sid, "OBSERVED", self.anchor_sid, replayed=replayed)

        anchor = self.dag.nodes[self.anchor_sid]
        vres = self.verifier.verify(anchor.snapshot["commit"])
        if vres.verdict == Verdict.SUCCESS:
            return self._commit_anchor(sid, parent, replayed, vres)

        self._emit("STEP_COMPLETED", sid, parent, {"verdict": "FAILED", "failure_class": vres.failure_class.value,
                                                   "error_sig": vres.error_sig})
        if vres.failure_class == FailureClass.TEST:
            return StepOutcome(sid, "FAILED_TEST", self.anchor_sid, replayed, verification=vres)
        if vres.failure_class == FailureClass.ENV:
            self._emit("ESCALATED", sid, None, {"reason": "ENV_FAILURE", "sig": vres.error_sig})
            self.status = ArbiterStatus.ESCALATED
            return StepOutcome(sid, "FAILED_ENV", self.anchor_sid, replayed, verification=vres, escalated=True)
        return self._rollback(sid, schema, clean, fp, vres)

    def _commit_anchor(self, sid: str, parent: str, replayed: bool, vres: VerificationResult) -> StepOutcome:
        snap = self.ws.snapshot(f"anchor-{sid}")            # 1) git-коммит
        self.verifier.calibrate_baseline(snap.commit)
        msg_blob = self._store_messages()
        sd = self._snapshot_dict(snap, msg_blob)             # 2) ledger-ссылка
        self._emit("STEP_COMPLETED", sid, parent, {"verdict": "SUCCESS", "failure_class": "NONE"})
        self._emit("ANCHOR_COMMITTED", sid, None, {"snapshot": sd}, [msg_blob])   # 3) только теперь якорь
        self.anchor_sid = self.tip_sid = sid
        self.repeat_rejects = 0
        return StepOutcome(sid, "SUCCESS", sid, replayed, verification=vres)

    # ---------- откат ----------
    def _rollback(self, failed_sid: str, schema: ToolSchema, clean: dict[str, Any], fp: str,
                  vres: VerificationResult) -> StepOutcome:
        anchor = self.dag.find_rollback_anchor(failed_sid)
        self.total_rollbacks += 1
        self.anchor_failures[anchor.sid] = self.anchor_failures.get(anchor.sid, 0) + 1
        loop = self.dag.detect_loops(anchor.sid, failed_sid)

        target, replan, escalate = anchor, False, False
        if self.total_rollbacks > self.max_total:
            escalate = True
        elif self.anchor_failures[anchor.sid] >= self.max_retries or loop is not None:
            prev = self.dag.previous_anchor(anchor.sid)
            if prev is not None:
                target = prev
            elif self.replans_used < 1:
                replan = True
                self.anchor_failures[anchor.sid] = 0
            else:
                escalate = True

        trusted = self.ws.tracked_files(anchor.snapshot["commit"]) | {"workspace"}
        shown_file = sanitize_path(vres.file) if vres.file in trusted else "new_file"   # имена файлов агента не показываем
        constraint = Constraint(self.total_rollbacks, vres.case_id or "n/a", shown_file, vres.line,
                                sanitize_exc_type(vres.exc_type), self._scope(schema, clean, anchor.snapshot["commit"]), fp, vres.contract)
        payload = {
            "failed_sid": failed_sid, "failed_anchor": anchor.sid, "target_sid": target.sid,
            "target_snapshot": target.snapshot, "pruned_sids": self.dag.branch_to_prune(target.sid, failed_sid),
            "constraint": asdict(constraint), "loop": loop.kind if loop else None,
            "replan": replan, "escalate": escalate,
        }
        self._emit("ROLLBACK_TRIGGERED", failed_sid, target.sid, payload)       # WAL: намерение ДО мутаций
        try:
            self._apply_rollback(payload, [])
        except BaseException as exc:
            self._emit("ROLLBACK_PARTIAL", failed_sid, target.sid, {"error": sanitize_exc_type(type(exc).__name__)})
            self._emit("ESCALATED", failed_sid, None, {"reason": "ROLLBACK_PARTIAL"})
            self.status = ArbiterStatus.ROLLBACK_PARTIAL
            raise RollbackPartialError(f"rollback of {failed_sid} did not complete") from exc
        return StepOutcome(failed_sid, "ESCALATED" if escalate else "ROLLED_BACK", target.sid, loop=loop,
                           verification=vres, escalated=escalate)

    def _apply_rollback(self, payload: dict[str, Any], already: list[dict[str, Any]]) -> None:
        """Идемпотентно: можно вызывать повторно при доводке после падения (already = события после триггера)."""
        done = {e["type"] for e in already}
        snap = payload["target_snapshot"]
        target_sid = payload["target_sid"]
        self.ws.restore(snap["commit"])                       # внутри: убить процессы ветки -> reset -> clean
        self.messages = self._load_messages(snap["msg"])
        constraint = Constraint.from_dict(payload["constraint"])
        self._add_constraint(constraint)
        todo = [s for s in payload["pruned_sids"] if s in self.dag.nodes and not self.dag.nodes[s].pruned]
        if todo or "STATE_PRUNED" not in done:
            self._emit("STATE_PRUNED", target_sid, None, {"pruned_sids": payload["pruned_sids"]})
        if payload["replan"] and "REPLAN_STARTED" not in done:
            self._emit("REPLAN_STARTED", target_sid, None, {"steps": self.replan_steps})
            self.replans_used += 1
            self.anchor_failures[payload["failed_anchor"]] = 0
        if payload["replan"]:
            self.replan_left = self.replan_steps
        if payload["escalate"]:
            if "ESCALATED" not in done:
                self._emit("ESCALATED", target_sid, None, {"reason": payload["loop"] or "ROLLBACK_BUDGET"})
            self.status = ArbiterStatus.ESCALATED
        if "CONSTRAINT_INJECTED" not in done:
            self._emit("CONSTRAINT_INJECTED", target_sid, None, {"constraint": payload["constraint"]})
        if self.verifier.baseline(snap["commit"]) is None:
            self.verifier.calibrate_baseline(snap["commit"])
        self.anchor_sid = self.tip_sid = target_sid
