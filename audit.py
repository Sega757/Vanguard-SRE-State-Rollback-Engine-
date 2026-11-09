"""audit.py: DAG выполнения, якорь отката, отсекаемая ветка, детектор циклов.

Состояние выводится реплеем событий (журнал не мутируется): PRUNED это следствие STATE_PRUNED.
Якорь это узел, на который пришло ANCHOR_COMMITTED (проверенный терминальный успех или корень).
Наблюдательные шаги (чтение файлов) якорями не бывают.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    PENDING = "PENDING"
    OBSERVED = "OBSERVED"   # non-terminal шаг отработал по контракту; НЕ якорь
    SUCCESS = "SUCCESS"     # внешний инвариант пройден
    FAILED = "FAILED"


class FailureClass(str, Enum):
    NONE = "NONE"
    PATCH = "PATCH"
    TEST = "TEST"
    ENV = "ENV"
    UNKNOWN = "UNKNOWN"


class DagError(RuntimeError):
    """Нарушена структура графа."""


@dataclass
class Node:
    sid: str
    pid: str | None
    kind: str
    snapshot: dict[str, Any] = field(default_factory=dict)
    fingerprint: str | None = None
    verdict: Verdict = Verdict.PENDING
    failure_class: FailureClass = FailureClass.NONE
    error_sig: str | None = None
    anchor: bool = False
    pruned: bool = False
    children: list[str] = field(default_factory=list)

    @property
    def is_divergent(self) -> bool:
        """D(N) = [есть действие] and [V = FAILED] and [C = PATCH]."""
        return self.kind != "root" and self.verdict == Verdict.FAILED and self.failure_class == FailureClass.PATCH


@dataclass(frozen=True)
class LoopSignal:
    kind: str  # REPEATED_FINGERPRINT | OSCILLATION | REPEATED_ERROR
    detail: str


class Dag:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}

    @classmethod
    def from_events(cls, events: list[dict[str, Any]]) -> "Dag":
        dag = cls()
        for ev in events:
            dag.apply(ev)
        return dag

    def apply(self, ev: dict[str, Any]) -> None:
        t, sid, pid, p = ev["type"], ev["sid"], ev["pid"], ev["payload"]
        if t == "STEP_STARTED":
            if sid in self.nodes:
                raise DagError(f"duplicate span {sid}")
            if pid is not None and pid not in self.nodes:
                raise DagError(f"span {sid} has unknown parent {pid}")
            node = Node(
                sid=sid, pid=pid, kind=p["kind"], snapshot=dict(p.get("snapshot", {})),
                fingerprint=p.get("action", {}).get("fingerprint"),
            )
            self.nodes[sid] = node
            if pid is not None:
                self.nodes[pid].children.append(sid)
        elif t == "STEP_COMPLETED":
            node = self._get(sid)
            node.verdict = Verdict(p["verdict"])
            node.failure_class = FailureClass(p.get("failure_class", "NONE"))
            node.error_sig = p.get("error_sig")
        elif t == "ANCHOR_COMMITTED":
            node = self._get(sid)
            node.anchor = True
            node.snapshot = dict(p["snapshot"])
        elif t == "STATE_PRUNED":
            for pruned in p["pruned_sids"]:
                if pruned in self.nodes:
                    self.nodes[pruned].pruned = True

    def _get(self, sid: str) -> Node:
        if sid not in self.nodes:
            raise DagError(f"unknown span {sid}")
        return self.nodes[sid]

    def ancestors(self, sid: str) -> list[Node]:
        out: list[Node] = []
        seen = {sid}
        cur = self._get(sid).pid
        while cur is not None:
            if cur in seen:
                raise DagError(f"cycle at {cur}")
            seen.add(cur)
            node = self._get(cur)
            out.append(node)
            cur = node.pid
        return out

    def find_rollback_anchor(self, failed_sid: str) -> Node:
        """Ближайший предок-якорь, не отсечённый. Корень всегда якорь."""
        for node in self.ancestors(failed_sid):
            if node.anchor and not node.pruned:
                return node
        raise DagError(f"no anchor above {failed_sid}")

    def previous_anchor(self, anchor_sid: str) -> Node | None:
        for node in self.ancestors(anchor_sid):
            if node.anchor and not node.pruned:
                return node
        return None

    def subtree(self, root_sid: str) -> list[str]:
        out: list[str] = []
        stack = [root_sid]
        seen: set[str] = set()
        while stack:
            sid = stack.pop()
            if sid in seen:
                continue
            seen.add(sid)
            out.append(sid)
            stack.extend(reversed(self._get(sid).children))
        return out

    def branch_to_prune(self, anchor_sid: str, failed_sid: str) -> list[str]:
        """T_fail: поддерево дочернего узла якоря на пути к сбою. Успешные сиблинги не трогаем."""
        cur = failed_sid
        while True:
            parent = self._get(cur).pid
            if parent is None:
                raise DagError(f"{failed_sid} is not below anchor {anchor_sid}")
            if parent == anchor_sid:
                return self.subtree(cur)
            cur = parent

    def failed_below(self, anchor_sid: str) -> list[Node]:
        """Все FAILED/PATCH под якорем (включая уже отсечённые) в порядке появления."""
        below = set(self.subtree(anchor_sid)) - {anchor_sid}
        return [n for n in self.nodes.values()
                if n.sid in below and n.verdict == Verdict.FAILED and n.failure_class == FailureClass.PATCH]

    def detect_loops(self, anchor_sid: str, latest_sid: str, window: int = 6,
                     repeat_error_threshold: int = 5) -> LoopSignal | None:
        attempts = self.failed_below(anchor_sid)
        fps = [n.fingerprint for n in attempts if n.fingerprint]
        if len(fps) >= 4 and fps[-4] == fps[-2] and fps[-3] == fps[-1] and fps[-4] != fps[-3]:
            return LoopSignal("OSCILLATION", f"{fps[-4][:8]}<->{fps[-3][:8]}")
        latest = self._get(latest_sid)
        if latest.fingerprint and any(n.fingerprint == latest.fingerprint for n in attempts if n.sid != latest_sid):
            return LoopSignal("REPEATED_FINGERPRINT", latest.fingerprint[:8])
        if latest.error_sig:
            same = sum(1 for n in attempts[-window:] if n.error_sig == latest.error_sig)
            if same >= repeat_error_threshold:
                return LoopSignal("REPEATED_ERROR", latest.error_sig)
        return None
