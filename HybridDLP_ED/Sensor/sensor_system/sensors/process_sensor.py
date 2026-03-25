from __future__ import annotations

import asyncio
import re
from typing import Dict

try:
    import psutil
except ImportError:  # pragma: no cover - dependency/environment specific
    psutil = None

from .base import SensorBase
from .stubs import StubSensor


SUSPICIOUS_PATTERNS = [
    (re.compile(r"\s-enc(\s|$)"), "base64_encoded_command"),
    (re.compile(r"invoke-webrequest"), "web_download_tooling"),
]


class ProcessSensor(SensorBase):
    source = "process_sensor"

    def extract_iocs(self, cmdline: str) -> list[str]:
        hits: list[str] = []
        lowered = (cmdline or "").lower()
        for pattern, tag in SUSPICIOUS_PATTERNS:
            if pattern.search(lowered):
                hits.append(tag)
        return hits

    def _snapshot(self) -> Dict[int, tuple[str, str | None]]:
        if psutil is None:
            return {}
        snapshot: Dict[int, tuple[str, str | None]] = {}
        for proc in psutil.process_iter(["pid", "name", "cmdline"]):
            try:
                cmdline_parts = proc.info.get("cmdline") or []
                cmdline = " ".join(cmdline_parts) if cmdline_parts else None
                snapshot[int(proc.info["pid"])] = (proc.info.get("name") or "unknown", cmdline)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return snapshot

    async def run(self, emit) -> None:
        if psutil is None:
            stub = StubSensor(self.context_provider)
            stub.source = self.source
            stub.reason = "process sensor requires psutil"
            await stub.run(emit)
            return
        previous = self._snapshot()
        while True:
            await asyncio.sleep(1)
            current = self._snapshot()

            started = set(current.keys()) - set(previous.keys())
            ended = set(previous.keys()) - set(current.keys())

            for pid in started:
                process_name, cmdline = current[pid]
                iocs = self.extract_iocs(cmdline or "")
                payload = self._build_base_event(
                    event_type="process_created",
                    severity="high" if iocs else "medium",
                    op_type="process_start",
                    process=process_name,
                    cmdline=cmdline,
                    ioc_hits=iocs,
                )
                await emit(payload)

            for pid in ended:
                process_name, cmdline = previous[pid]
                payload = self._build_base_event(
                    event_type="process_ended",
                    severity="low",
                    op_type="process_end",
                    process=process_name,
                    cmdline=cmdline,
                )
                await emit(payload)

            previous = current

