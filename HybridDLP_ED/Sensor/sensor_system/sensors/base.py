from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, Optional

from ..context_provider import ContextProvider
from ..schema import Actor, Flags, Metrics, ObjectRef, Operation, UnifiedEvent


def classify_volume(path: Optional[str]) -> str:
    if not path:
        return "unknown"
    normalized = path.lower()
    if normalized.startswith("\\\\"):
        return "network"
    if "onedrive" in normalized:
        return "cloud"
    if len(path) >= 2 and path[1] == ":":
        drive = path[0].upper()
        if drive in {"C", "D"}:
            return "fixed"
        return "removable"
    return "unknown"


class SensorBase(ABC):
    source: str

    def __init__(self, context_provider: ContextProvider) -> None:
        self.context_provider = context_provider

    @abstractmethod
    async def run(self, emit) -> None:
        raise NotImplementedError

    def _build_base_event(
        self,
        *,
        event_type: str,
        severity: str,
        op_type: str,
        process: str,
        cmdline: Optional[str],
        path: Optional[str] = None,
        dst_path: Optional[str] = None,
        bytes_out: Optional[float] = None,
        file_count: Optional[float] = None,
        ioc_hits: Optional[list[str]] = None,
        tags: Optional[list[str]] = None,
    ) -> Dict:
        ctx = self.context_provider.get_context()
        actor_runtime = self.context_provider.get_actor(process, cmdline)
        event = UnifiedEvent(
            type=event_type,
            source=self.source,
            severity=severity,
            operation=Operation(op_type=op_type, tool=process),
            context=ctx,
            actor=Actor(
                user=actor_runtime.user,
                process=actor_runtime.process,
                cmdline=actor_runtime.cmdline,
            ),
            object=ObjectRef(
                path=path,
                dst_path=dst_path,
                drive=(dst_path or path or "")[:2] if (dst_path or path) else None,
                volume_type=classify_volume(dst_path or path),
                sensitivity="unknown",
            ),
            metrics=Metrics(
                file_count=file_count,
                entropy=None,
                bytes_out=bytes_out,
            ),
            flags=Flags(password_protected=None),
            ioc_hits=ioc_hits or [],
            tags=tags or [],
        )
        return event.to_dict()

