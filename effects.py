"""effects.py: слой 3 (внешние эффекты). Откатить мир нельзя; можно не задублировать эффект.

  * Каждый инструмент объявляет ToolSchema: класс эффекта, терминальность, БЕЛЫЙ список identity_fields.
    Всё вне списка (request_id, timestamp, пояснения модели) в ключ не входит (fail-closed: новое поле ключ не меняет).
  * Ключ идемпотентности считает арбитр: sha256(session, tool, canonical(identity args)). Модель его не видит.
    Отличие от черновика ТЗ: в ключе НЕТ anchor_sid, иначе откат на несколько якорей выше даёт дубль эффекта.
  * WAL: EFFECT_INTENT пишется и fsync-ится ДО вызова; EFFECT_COMMITTED после. Intent без commit = UNKNOWN.
  * Повтор COMMITTED-ключа: Replay (сохранённый ответ, наружу не идём). UNKNOWN: автоповтор запрещён,
    кроме idempotent_write у сервиса с поддержкой ключей. Новый irreversible-эффект требует approve().

Канонизация: для int/str/bool/None/list/dict совместима с RFC 8785 (ключи сортируются по UTF-16 code units).
Числа float печатаются через repr (кратчайшее round-trip представление), это НЕ полный JCS для экспонент.
"""
from __future__ import annotations

import hashlib
import json
import math
import unicodedata
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

from transponder import Transponder


class EffectClass(str, Enum):
    READ_ONLY = "read_only"
    IDEMPOTENT_WRITE = "idempotent_write"
    IRREVERSIBLE = "irreversible"


class ToolSchemaError(ValueError):
    """Схема инструмента нарушена или аргументы не нормализуются."""


class UnknownEffectState(RuntimeError):
    """Был intent без commit: неизвестно, выполнился ли эффект. Автоповтор запрещён."""


class ApprovalRequired(RuntimeError):
    """Новый необратимый эффект без разрешения политики."""


def normalize_value(v: Any) -> Any:
    if isinstance(v, bool) or v is None or isinstance(v, int):
        return v
    if isinstance(v, float):
        if not math.isfinite(v):
            raise ToolSchemaError("non-finite number in tool args")
        return 0.0 if v == 0.0 else v
    if isinstance(v, str):
        return unicodedata.normalize("NFC", v.strip())
    if isinstance(v, (list, tuple)):
        return [normalize_value(x) for x in v]
    if isinstance(v, dict):
        out: dict[str, Any] = {}
        for k, x in v.items():
            if not isinstance(k, str):
                raise ToolSchemaError("non-string key in tool args")
            out[unicodedata.normalize("NFC", k)] = normalize_value(x)
        return out
    raise ToolSchemaError(f"unsupported type in tool args: {type(v).__name__}")


def canonical_json(v: Any) -> str:
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        return repr(v)
    if isinstance(v, str):
        return json.dumps(v, ensure_ascii=False)
    if isinstance(v, list):
        return "[" + ",".join(canonical_json(x) for x in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + canonical_json(x) for k, x in items) + "}"
    raise ToolSchemaError(f"cannot canonicalize {type(v).__name__}")


@dataclass(frozen=True)
class ToolSchema:
    name: str
    effect_class: EffectClass
    terminal: bool
    handler: Callable[[dict[str, Any], str], Any]     # (args, idempotency_key) -> JSON-able
    identity_fields: tuple[str, ...] = ()
    idempotent_supported: bool = False
    patch_field: str | None = None                    # поле с кодом патча (для AST-фингерпринта)
    path_field: str | None = None                     # поле с путём файла (для ограничения)

    def __post_init__(self) -> None:
        if self.effect_class != EffectClass.READ_ONLY and not self.identity_fields:
            raise ToolSchemaError(f"{self.name}: write tools must declare identity_fields")

    def canonicalize(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.identity_fields:
            missing = [f for f in self.identity_fields if f not in args]
            if missing:
                raise ToolSchemaError(f"{self.name}: missing identity fields {missing}")
            projected = {f: args[f] for f in self.identity_fields}
        else:
            projected = dict(args)
        return normalize_value(projected)


def idempotency_key(session: str, tool: str, canonical_args: dict[str, Any]) -> str:
    material = f"{session}\0{tool}\0{canonical_json(canonical_args)}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class EffectResult:
    response: str
    replayed: bool
    key: str | None


class EffectLedger:
    def __init__(self, transponder: Transponder, session: str,
                 approve: Callable[[str, dict[str, Any]], bool] | None = None) -> None:
        self.tp = transponder
        self.session = session
        self.approve = approve
        self._state: dict[str, tuple[str, str | None]] = {}   # key -> (INTENT|COMMITTED, response_blob)
        for ev in transponder.events:
            self._apply(ev)

    def _apply(self, ev: dict[str, Any]) -> None:
        if ev["type"] == "EFFECT_INTENT":
            self._state.setdefault(ev["payload"]["key"], ("INTENT", None))
        elif ev["type"] == "EFFECT_COMMITTED":
            self._state[ev["payload"]["key"]] = ("COMMITTED", ev["blobs"][0])

    def state(self, key: str) -> str:
        return self._state.get(key, ("NONE", None))[0]

    def ref(self) -> str:
        lines = sorted(f"{k}:{s}" for k, (s, _) in self._state.items())
        return hashlib.sha256("\n".join(lines).encode()).hexdigest()

    def execute(self, schema: ToolSchema, args: dict[str, Any]) -> EffectResult:
        if schema.effect_class == EffectClass.READ_ONLY:
            return EffectResult(canonical_json(normalize_value(schema.handler(dict(args), ""))), False, None)
        canon = schema.canonicalize(args)
        key = idempotency_key(self.session, schema.name, canon)
        state, blob = self._state.get(key, ("NONE", None))
        if state == "COMMITTED" and blob is not None:
            return EffectResult(self.tp.blobs.get(blob).decode("utf-8"), True, key)
        if state == "INTENT":
            if not (schema.effect_class == EffectClass.IDEMPOTENT_WRITE and schema.idempotent_supported):
                raise UnknownEffectState(f"{schema.name}: effect {key[:12]} has intent without commit")
        else:
            if schema.effect_class == EffectClass.IRREVERSIBLE and not (self.approve and self.approve(schema.name, canon)):
                raise ApprovalRequired(f"{schema.name}: irreversible effect needs approval")
            args_blob = self.tp.blobs.put(canonical_json(canon))
            ev = self.tp.emit("EFFECT_INTENT", f"eff_{key[:12]}", None,
                              {"key": key, "tool": schema.name, "class": schema.effect_class.value}, [args_blob])
            self._apply(ev)
        response = canonical_json(normalize_value(schema.handler(dict(args), key)))
        resp_blob = self.tp.blobs.put(response)
        ev = self.tp.emit("EFFECT_COMMITTED", f"eff_{key[:12]}", None, {"key": key, "tool": schema.name}, [resp_blob])
        self._apply(ev)
        return EffectResult(response, False, key)
