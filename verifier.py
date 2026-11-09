"""verifier.py: внешний верификатор в двух процессах.

Код агента исполняется в ОТДЕЛЬНОМ процессе-раннере, который получает только описания вызовов
(модуль, функция, аргументы) и возвращает сериализованные значения. Ожидаемые значения знает только
доверенный родительский процесс; сравнение идёт по каноническому JSON, поэтому объект с вечно-True
__eq__, ранний sys.exit(0), os._exit(0), подмена отчёта и чтение argv не дают SUCCESS.

Кейсы бывают двух видов:
  goal  (по умолчанию): то, что патч должен починить. Падение на якоре нормально; падение после патча = попытка не удалась.
  guard: должен проходить уже на якоре. Если guard падает и на чистом якоре, виноватого нет.

Классификация:
  SUCCESS: все кейсы совпали.
  TEST:    единственные падения это guard-кейсы, сломанные ещё на якоре (baseline), либо два прогона разошлись (флаки).
  ENV:     раннер не запустился, либо сбой ресурсного типа (таймаут/память/OSError/ImportError), а
           контрольный прогон ЧИСТОГО якоря тоже падает.
  PATCH:   детерминированный отказ goal/guard-кейса, а контрольный прогон якоря (если нужен) проходит.

Ограничения MVP: тот же UID. Агент теоретически может найти файл со спецификацией на диске;
для защиты от этого нужен отдельный пользователь/контейнер (следующий этап).
"""
from __future__ import annotations

import builtins
import hashlib
import json
import math
import re
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from audit import FailureClass, Verdict
from workspace import WorkspaceManager

_IDENT = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
_PATH = re.compile(r"^[A-Za-z0-9_./-]{1,80}$")
_CONTROL_KINDS = frozenset({"timeout", "resource", "env_like"})
_ENV_LIKE = frozenset({"ImportError", "ModuleNotFoundError", "OSError", "PermissionError",
                       "FileNotFoundError", "BlockingIOError", "ConnectionError", "IsADirectoryError"})
_INTERNAL_EXC = frozenset({"WrongResult", "IncompleteRun", "NonPlainResult", "NONE"})


def sanitize_exc_type(name: str) -> str:
    """Только имена встроенных исключений; пользовательские классы превращаются в хеш."""
    obj = getattr(builtins, str(name), None)
    if name in _INTERNAL_EXC or (isinstance(obj, type) and issubclass(obj, BaseException)):
        return str(name)
    return "UserDefinedException_" + hashlib.sha256(str(name).encode("utf-8", "replace")).hexdigest()[:6]


def sanitize_path(raw: str) -> str:
    s = str(raw).strip()
    if s and _PATH.match(s) and ".." not in s and not s.startswith("/"):
        return s
    return "path_" + hashlib.sha256(str(raw).encode("utf-8", "replace")).hexdigest()[:8]


def canonical_value(v: Any) -> str:
    return json.dumps(v, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


_RUNNER = r'''
import importlib, json, math, os, resource, sys, traceback

def plain(v):
    t = type(v)
    if v is None or t in (bool, int, str):
        return v
    if t is float:
        if not math.isfinite(v):
            raise TypeError("NonPlainResult")
        return v
    if t in (list, tuple):
        return [plain(x) for x in v]
    if t is dict:
        return {k: plain(x) for k, x in v.items() if type(k) is str}
    raise TypeError("NonPlainResult")

def frame_in(tb, root):
    root = os.path.realpath(root)
    best = None
    for fr in traceback.extract_tb(tb):
        p = os.path.realpath(fr.filename)
        if p.startswith(root + os.sep):
            best = (os.path.relpath(p, root).replace(os.sep, "/"), int(fr.lineno or 0))
    return best or ("workspace", 0)

def main():
    calls_path, result_path, root, cpu, mem = sys.argv[1:6]
    for res, val in ((resource.RLIMIT_CPU, int(cpu)), (resource.RLIMIT_AS, int(mem) * 1024 * 1024)):
        try:
            resource.setrlimit(res, (val, val))
        except (ValueError, OSError):
            pass
    calls = json.load(open(calls_path))
    sys.path.insert(0, root)
    out = []
    for c in calls:
        entry = {"id": c["id"]}
        try:
            fn = getattr(importlib.import_module(c["module"]), c["func"])
            entry["value"] = plain(fn(*c["args"], **c["kwargs"]))
        except BaseException as exc:
            f, l = frame_in(exc.__traceback__, root)
            entry["error"] = {"type": type(exc).__name__, "file": f, "line": l}
        out.append(entry)
    with open(result_path, "w") as fh:
        json.dump(out, fh)
        fh.flush()
        os.fsync(fh.fileno())

main()
'''


@dataclass(frozen=True)
class Case:
    id: str
    contract: str
    module: str
    func: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    expect: Any
    kind: str = "goal"


@dataclass(frozen=True)
class InvariantSpec:
    name: str
    cases: tuple[Case, ...]
    timeout_sec: float = 5.0
    cpu_sec: int = 5
    mem_mb: int = 1024

    @classmethod
    def from_file(cls, path: str | Path, workspace_root: str | Path) -> "InvariantSpec":
        p = Path(path).resolve()
        if p.is_relative_to(Path(workspace_root).resolve()):
            raise PermissionError(f"invariant spec must live OUTSIDE the workspace: {p}")
        data = json.loads(p.read_text(encoding="utf-8"))
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "InvariantSpec":
        if not _IDENT.match(str(data["name"])):
            raise ValueError("bad invariant name")
        cases: list[Case] = []
        for raw in data["cases"]:
            call = raw["call"]
            if not _IDENT.match(str(raw["id"])):
                raise ValueError(f"bad case id: {raw['id']!r}")
            contract = str(raw["contract"])
            if not contract or len(contract) > 200 or "\n" in contract or "\r" in contract:
                raise ValueError(f"bad contract in case {raw['id']}")
            kind = str(raw.get("kind", "goal"))
            if kind not in ("goal", "guard"):
                raise ValueError(f"bad case kind: {kind!r}")
            cases.append(Case(str(raw["id"]), contract, str(call["module"]), str(call["func"]),
                              tuple(call.get("args", [])), dict(call.get("kwargs", {})), raw["expect"], kind))
        if not cases:
            raise ValueError("no cases")
        return cls(str(data["name"]), tuple(cases), float(data.get("timeout_sec", 5.0)),
                   int(data.get("cpu_sec", 5)), int(data.get("mem_mb", 1024)))


@dataclass(frozen=True)
class Failure:
    case_id: str
    contract: str
    kind: str                 # logic | timeout | resource | env_like | incomplete | infra
    exc_type: str
    file: str = "workspace"
    line: int = 0


@dataclass(frozen=True)
class RunOutcome:
    failures: tuple[Failure, ...] = ()
    duration: float = 0.0

    @property
    def passed(self) -> bool:
        return not self.failures

    @property
    def infra(self) -> bool:
        return any(f.kind == "infra" for f in self.failures)

    @property
    def failed_ids(self) -> frozenset[str]:
        return frozenset(f.case_id for f in self.failures)


@dataclass(frozen=True)
class VerificationResult:
    verdict: Verdict
    failure_class: FailureClass
    invariant: str
    case_id: str
    contract: str
    exc_type: str
    file: str
    line: int
    flaky: bool = False
    control_run: bool = False

    @property
    def error_sig(self) -> str | None:
        if self.verdict == Verdict.SUCCESS:
            return None
        return f"{self.exc_type}:{self.file}:{self.line}:{self.case_id}"


class ExternalVerifier:
    def __init__(self, workspace: WorkspaceManager, spec: InvariantSpec, *, control_run: bool = True) -> None:
        self.ws = workspace
        self.spec = spec
        self.control_run = control_run
        self._baselines: dict[str, RunOutcome] = {}

    # ---- один прогон раннера ----
    def _all_failed(self, kind: str, exc: str, dur: float) -> RunOutcome:
        return RunOutcome(tuple(Failure(c.id, c.contract, kind, exc) for c in self.spec.cases), dur)

    def _run(self, root: Path) -> RunOutcome:
        scratch = Path(tempfile.mkdtemp(prefix="sre_ver_"))
        try:
            calls = [{"id": c.id, "module": c.module, "func": c.func, "args": list(c.args), "kwargs": c.kwargs}
                     for c in self.spec.cases]
            calls_path, result_path = scratch / "calls.json", scratch / "result.json"
            calls_path.write_text(json.dumps(calls), encoding="utf-8")
            t0 = time.monotonic()
            try:
                rr = self.ws.run_isolated(
                    [sys.executable, "-I", "-c", _RUNNER, str(calls_path), str(result_path), str(root),
                     str(self.spec.cpu_sec), str(self.spec.mem_mb)],
                    self.spec.timeout_sec, cwd=root,
                )
            except OSError:
                return self._all_failed("infra", "OSError", 0.0)
            dur = time.monotonic() - t0
            if rr.timed_out:
                return self._all_failed("timeout", "TimeoutError", dur)
            try:
                by_id = {r["id"]: r for r in json.loads(result_path.read_text(encoding="utf-8"))}
            except (OSError, ValueError, KeyError, TypeError):
                killed = rr.returncode is not None and rr.returncode < 0
                return self._all_failed("resource" if killed else "incomplete",
                                        "MemoryError" if killed else "IncompleteRun", dur)
            failures: list[Failure] = []
            for case in self.spec.cases:
                entry = by_id.get(case.id)
                if entry is None:
                    failures.append(Failure(case.id, case.contract, "incomplete", "IncompleteRun"))
                elif "error" in entry:
                    err = entry["error"]
                    name = str(err.get("type", "Exception"))
                    kind = "resource" if name == "MemoryError" else ("env_like" if name in _ENV_LIKE else "logic")
                    failures.append(Failure(case.id, case.contract, kind, sanitize_exc_type(name),
                                            sanitize_path(str(err.get("file", "workspace"))),
                                            max(0, int(err.get("line", 0)))))
                else:
                    try:
                        same = canonical_value(entry.get("value")) == canonical_value(case.expect)
                    except (TypeError, ValueError):
                        same = False
                    if not same:
                        failures.append(Failure(case.id, case.contract, "logic", "WrongResult",
                                                sanitize_path(case.module.replace(".", "/") + ".py")))
            return RunOutcome(tuple(failures), dur)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    # ---- API ----
    def calibrate_baseline(self, commit: str) -> RunOutcome:
        out = self._run(self.ws.root)
        self._baselines[commit] = out
        return out

    def baseline(self, commit: str) -> RunOutcome | None:
        return self._baselines.get(commit)

    def _broken_guards(self, base: RunOutcome) -> frozenset[str]:
        guards = {c.id for c in self.spec.cases if c.kind == "guard"}
        return frozenset(base.failed_ids & guards)

    def _result(self, verdict: Verdict, cls: FailureClass, f: Failure | None, **kw: Any) -> VerificationResult:
        if f is None:
            return VerificationResult(verdict, cls, self.spec.name, "", "", "NONE", "workspace", 0, **kw)
        return VerificationResult(verdict, cls, self.spec.name, f.case_id, f.contract, f.exc_type, f.file, f.line, **kw)

    @staticmethod
    def _first(out: RunOutcome, ignore: frozenset[str]) -> Failure | None:
        return next((f for f in out.failures if f.case_id not in ignore), None)

    def verify(self, anchor_commit: str) -> VerificationResult:
        base = self._baselines.get(anchor_commit)
        if base is None:
            raise RuntimeError(f"baseline for {anchor_commit} was not calibrated")
        if base.infra:
            return self._result(Verdict.FAILED, FailureClass.ENV, base.failures[0])
        broken = self._broken_guards(base)
        r1 = self._run(self.ws.root)
        if r1.passed:
            return self._result(Verdict.SUCCESS, FailureClass.NONE, None)
        if r1.infra:
            return self._result(Verdict.FAILED, FailureClass.ENV, r1.failures[0])
        blame1 = self._first(r1, broken)
        if blame1 is None:                       # падают только guard-ы, сломанные ещё на якоре
            return self._result(Verdict.FAILED, FailureClass.TEST, r1.failures[0])
        r2 = self._run(self.ws.root)
        if r2.passed or {f.case_id for f in r2.failures if f.case_id not in broken} != \
                {f.case_id for f in r1.failures if f.case_id not in broken}:
            return self._result(Verdict.FAILED, FailureClass.TEST, blame1, flaky=True)
        if r2.infra:
            return self._result(Verdict.FAILED, FailureClass.ENV, r2.failures[0])
        blame = self._first(r2, broken) or blame1
        if blame.kind in _CONTROL_KINDS and self.control_run:
            tmp = Path(tempfile.mkdtemp(prefix="sre_ctl_"))
            try:
                self.ws.export_commit(anchor_commit, tmp)
                ctl = self._run(tmp)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
            bad_ctl = [f for f in ctl.failures if f.case_id not in self._broken_guards(ctl) and f.kind in _CONTROL_KINDS]
            cls = FailureClass.ENV if (bad_ctl or ctl.infra) else FailureClass.PATCH
            return self._result(Verdict.FAILED, cls, blame, control_run=True)
        return self._result(Verdict.FAILED, FailureClass.PATCH, blame)
