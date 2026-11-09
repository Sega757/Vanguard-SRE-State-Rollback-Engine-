"""transponder.py: журнал событий (схема 1.1) с единой HMAC-цепочкой, одним писателем и внешним якорем.

Гарантии:
  * каждое событие: prev (hash предыдущего) + hash = HMAC-SHA256(key, canonical(body));
  * все blob-ссылки событий существуют в blobstore ДО записи события;
  * один писатель (flock LOCK_NB на отдельном файле на всё время жизни Transponder);
  * рваный хвост (последняя строка без \\n или невалидная) усекается и фиксируется TAIL_TRUNCATED;
  * испорченная строка в СЕРЕДИНЕ, неверный hash/prev, удаление хвоста по якорю: ChainTamperedError.

Якорь (anchor.json) хранит (seq, tip, mac) и пишется после каждого события. Если anchor_dir лежит на
другом носителе/хосте, он защищает от отката логом целиком; в одном каталоге с логом защищает только
от усечения хвоста злоумышленником без ключа.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from blobstore import BlobStore

GENESIS = "0" * 64
SCHEMA = "1.1"

EVENT_TYPES = frozenset(
    {
        "STEP_STARTED",
        "STEP_COMPLETED",
        "STEP_REJECTED",
        "ANCHOR_COMMITTED",
        "ROLLBACK_TRIGGERED",
        "STATE_PRUNED",
        "CONSTRAINT_INJECTED",
        "ROLLBACK_PARTIAL",
        "ESCALATED",
        "REPLAN_STARTED",
        "TAIL_TRUNCATED",
        "EFFECT_INTENT",
        "EFFECT_COMMITTED",
    }
)
ROLLBACK_TYPES = frozenset(
    {"ROLLBACK_TRIGGERED", "STATE_PRUNED", "CONSTRAINT_INJECTED", "ROLLBACK_PARTIAL", "ESCALATED",
     "REPLAN_STARTED", "TAIL_TRUNCATED"}
)
_REQUIRED = frozenset({"schema", "seq", "ts", "type", "sid", "pid", "payload", "blobs", "prev", "hash"})


class ChainTamperedError(RuntimeError):
    """Нарушена целостность журнала (подмена, разрыв цепочки, усечение хвоста, битая середина)."""


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _mac(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def scan_log(
    path: Path, key: bytes, blobs: BlobStore | None = None, deep: bool = False
) -> tuple[list[dict[str, Any]], int, bytes | None]:
    """Возвращает (события, good_offset, рваный_хвост|None). Бросает ChainTamperedError при подмене."""
    raw = path.read_bytes() if path.exists() else b""
    events: list[dict[str, Any]] = []
    prev = GENESIS
    pos = 0
    while pos < len(raw):
        nl = raw.find(b"\n", pos)
        terminated = nl != -1
        end = nl + 1 if terminated else len(raw)
        is_last = end >= len(raw)
        event: dict[str, Any] | None = None
        if terminated:
            try:
                parsed = json.loads(raw[pos:nl].decode("utf-8"))
                if isinstance(parsed, dict) and _REQUIRED.issubset(parsed):
                    event = parsed
            except (UnicodeDecodeError, json.JSONDecodeError):
                event = None
        if event is None:
            if is_last:
                return events, pos, raw[pos:]
            raise ChainTamperedError(f"corrupted record in the middle of the log at byte {pos}")
        seq = len(events) + 1
        if event["seq"] != seq or event["schema"] != SCHEMA:
            raise ChainTamperedError(f"bad seq/schema at record {seq}")
        if event["prev"] != prev:
            raise ChainTamperedError(f"prev-hash link broken at record {seq}")
        body = {k: v for k, v in event.items() if k != "hash"}
        if not hmac.compare_digest(str(event["hash"]), _mac(key, canonical(body))):
            raise ChainTamperedError(f"HMAC mismatch at record {seq}")
        if blobs is not None:
            for ref in event["blobs"]:
                try:
                    if deep:
                        blobs.get(ref)
                    elif not blobs.exists(ref):
                        raise ChainTamperedError(f"record {seq} references missing blob {ref}")
                except ChainTamperedError:
                    raise
                except Exception as exc:  # BlobIntegrityError и др.
                    raise ChainTamperedError(f"record {seq}: blob check failed: {exc}") from exc
        events.append(event)
        prev = event["hash"]
        pos = end
    return events, pos, None


def _anchor_payload(key: bytes, seq: int, tip: str) -> dict[str, Any]:
    return {"seq": seq, "tip": tip, "mac": _mac(key, f"{seq}:{tip}".encode())}


def read_anchor(path: Path, key: bytes) -> tuple[int, str] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        seq, tip, mac = int(data["seq"]), str(data["tip"]), str(data["mac"])
    except (ValueError, KeyError, json.JSONDecodeError, OSError) as exc:
        raise ChainTamperedError(f"anchor unreadable: {exc}") from exc
    if not hmac.compare_digest(mac, _mac(key, f"{seq}:{tip}".encode())):
        raise ChainTamperedError("anchor MAC invalid")
    return seq, tip


def check_against_anchor(anchor: tuple[int, str] | None, seq: int, tip: str) -> None:
    if anchor is None:
        if seq > 0:
            raise ChainTamperedError("anchor missing while the log is not empty")
        return
    a_seq, a_tip = anchor
    if seq < a_seq:
        raise ChainTamperedError(f"tail truncation: log has {seq} records, anchor says {a_seq}")
    if seq == a_seq and tip != a_tip:
        raise ChainTamperedError("tip hash differs from anchor")
    if seq > a_seq + 1:
        raise ChainTamperedError(f"anchor is stale by {seq - a_seq} records (rollback of anchor?)")


def verify_log(
    log_dir: str | Path,
    key: bytes,
    blobs: BlobStore | None = None,
    anchor_dir: str | Path | None = None,
    deep: bool = True,
) -> list[dict[str, Any]]:
    """Полная проверка журнала без изменений. Рваный хвост здесь считается ошибкой (его чинит Transponder)."""
    base = Path(log_dir)
    events, _, torn = scan_log(base / "telemetry.jsonl", key, blobs, deep)
    if torn is not None:
        raise ChainTamperedError("torn tail present: open Transponder to recover")
    anchor = read_anchor(Path(anchor_dir or base) / "anchor.json", key)
    check_against_anchor(anchor, len(events), events[-1]["hash"] if events else GENESIS)
    return events


class Transponder:
    """Единственный писатель журнала."""

    def __init__(
        self,
        log_dir: str | Path,
        key: bytes | str,
        blobs: BlobStore,
        *,
        anchor_dir: str | Path | None = None,
        clock: Callable[[], str] = _now,
        stress_chunk: int = 0,
        stress_pause: float = 0.0,
    ) -> None:
        self.log_dir = Path(log_dir).resolve()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.key = key.encode("utf-8") if isinstance(key, str) else bytes(key)
        self.blobs = blobs
        self._clock = clock
        self._stress_chunk = stress_chunk
        self._stress_pause = stress_pause
        self.path = self.log_dir / "telemetry.jsonl"
        adir = Path(anchor_dir).resolve() if anchor_dir else self.log_dir
        adir.mkdir(parents=True, exist_ok=True)
        self.anchor_path = adir / "anchor.json"
        self._lock_fd: int | None = None
        self._events: list[dict[str, Any]] = []
        self._tip = GENESIS
        self._acquire_lock()
        try:
            self._recover()
        except BaseException:
            self.close()
            raise

    # ---- жизненный цикл ----
    def _acquire_lock(self) -> None:
        fd = os.open(str(self.log_dir / "transponder.lock"), os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise RuntimeError("another writer holds transponder.lock") from exc
        self._lock_fd = fd

    def close(self) -> None:
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None

    def __enter__(self) -> "Transponder":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ---- доступ ----
    @property
    def events(self) -> list[dict[str, Any]]:
        return self._events

    @property
    def seq(self) -> int:
        return len(self._events)

    @property
    def tip(self) -> str:
        return self._tip

    # ---- запись ----
    def _write_anchor(self) -> None:
        tmp = self.anchor_path.with_suffix(".tmp")
        data = canonical(_anchor_payload(self.key, self.seq, self._tip)) + b"\n"
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(str(tmp), str(self.anchor_path))
        _fsync_dir(self.anchor_path.parent)

    def _append(self, line: bytes) -> None:
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
        try:
            view = memoryview(line)
            step = self._stress_chunk or len(view)
            while view:
                written = os.write(fd, view[:step])
                view = view[written:]
                if self._stress_pause:
                    time.sleep(self._stress_pause)   # только для crash-тестов: расширяет окно рваной записи
            os.fsync(fd)
        finally:
            os.close(fd)

    def emit(
        self,
        event_type: str,
        sid: str,
        pid: str | None,
        payload: dict[str, Any],
        blobs: Iterable[str] = (),
    ) -> dict[str, Any]:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown event type: {event_type!r}")
        refs = list(blobs)
        for ref in refs:
            if not self.blobs.exists(ref):
                raise ChainTamperedError(f"cannot emit {event_type}: blob {ref} is not in the blobstore")
        body = {
            "schema": SCHEMA,
            "seq": self.seq + 1,
            "ts": self._clock(),
            "type": event_type,
            "sid": sid,
            "pid": pid,
            "payload": payload,
            "blobs": refs,
            "prev": self._tip,
        }
        event = {**body, "hash": _mac(self.key, canonical(body))}
        self._append(canonical(event) + b"\n")
        self._events.append(event)
        self._tip = event["hash"]
        self._write_anchor()
        return event

    # ---- восстановление ----
    def _recover(self) -> None:
        existed = self.path.exists()
        events, good, torn = scan_log(self.path, self.key, self.blobs)
        anchor = read_anchor(self.anchor_path, self.key)
        tip = events[-1]["hash"] if events else GENESIS
        check_against_anchor(anchor, len(events), tip)
        self._events, self._tip = events, tip
        if not existed:
            self.path.touch(mode=0o644)
            _fsync_dir(self.log_dir)
        if torn is not None:
            fd = os.open(str(self.path), os.O_RDWR)
            try:
                os.ftruncate(fd, good)
                os.fsync(fd)
            finally:
                os.close(fd)
            self.emit(
                "TAIL_TRUNCATED",
                "recovery",
                None,
                {
                    "discarded_bytes": len(torn),
                    "discarded_sha256": hashlib.sha256(torn).hexdigest(),
                    "truncated_at_offset": good,
                },
            )
        elif anchor is None or anchor[0] != self.seq:
            self._write_anchor()  # процесс умер между fsync записи и записью якоря


def rollback_index(events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Вторичный индекс операций отката: вычисляется из единой цепочки, отдельного файла нет."""
    return [e for e in events if e["type"] in ROLLBACK_TYPES]
