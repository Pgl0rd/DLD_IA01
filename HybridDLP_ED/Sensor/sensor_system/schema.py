from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


ALLOWED_KEYS = {
    "ts",
    "type",
    "source",
    "severity",
    "operation",
    "context",
    "actor",
    "object",
    "metrics",
    "flags",
    "ioc_hits",
    "tags",
    "clipboard",
    "network",
    "print",
    "debug",
    "rule",
    "browser_upload",   # L1 BrowserUploadSensor extension block
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _lower_or_none(value: Optional[str], keep_case: bool = False) -> Optional[str]:
    if value is None:
        return None
    return value if keep_case else value.lower()


@dataclass
class Operation:
    op_type: str
    tool: Optional[str] = None


@dataclass
class Context:
    window_title: Optional[str] = None
    fg_app: Optional[str] = None
    fg_process: Optional[str] = None


@dataclass
class Actor:
    user: str
    process: str
    cmdline: Optional[str] = None


@dataclass
class ObjectRef:
    path: Optional[str] = None
    dst_path: Optional[str] = None
    drive: Optional[str] = None
    volume_type: str = "unknown"
    sensitivity: str = "unknown"


@dataclass
class Metrics:
    file_count: Optional[float] = None
    entropy: Optional[float] = None
    bytes_out: Optional[float] = None


@dataclass
class Flags:
    password_protected: Optional[bool] = None


@dataclass
class UnifiedEvent:
    type: str
    source: str
    severity: str
    operation: Operation
    context: Context
    actor: Actor
    object: ObjectRef
    metrics: Metrics
    flags: Flags
    ioc_hits: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    ts: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload = {
            "ts": payload["ts"],
            "type": _lower_or_none(payload["type"]) or "",
            "source": _lower_or_none(payload["source"]) or "",
            "severity": _lower_or_none(payload["severity"]) or "low",
            "operation": {
                "op_type": _lower_or_none(payload["operation"]["op_type"]) or "",
                "tool": _lower_or_none(payload["operation"]["tool"]),
            },
            "context": {
                "window_title": _lower_or_none(payload["context"]["window_title"]),
                "fg_app": _lower_or_none(payload["context"]["fg_app"]),
                "fg_process": _lower_or_none(payload["context"]["fg_process"]),
            },
            "actor": {
                "user": _lower_or_none(payload["actor"]["user"]) or "unknown",
                "process": _lower_or_none(payload["actor"]["process"]) or "unknown",
                "cmdline": _lower_or_none(payload["actor"]["cmdline"]),
            },
            "object": {
                "path": _lower_or_none(payload["object"]["path"], keep_case=True),
                "dst_path": _lower_or_none(payload["object"]["dst_path"], keep_case=True),
                "drive": _lower_or_none(payload["object"]["drive"], keep_case=True),
                "volume_type": _lower_or_none(payload["object"]["volume_type"]) or "unknown",
                "sensitivity": _lower_or_none(payload["object"]["sensitivity"]) or "unknown",
            },
            "metrics": payload["metrics"],
            "flags": payload["flags"],
            "ioc_hits": [item.lower() for item in payload["ioc_hits"]],
            "tags": [item.lower() for item in payload["tags"]],
        }
        _validate_schema(payload)
        return payload


def _validate_schema(payload: Dict[str, Any]) -> None:
    unknown = set(payload.keys()) - ALLOWED_KEYS
    if unknown:
        raise ValueError(f"Payload contains unsupported keys: {unknown}")

