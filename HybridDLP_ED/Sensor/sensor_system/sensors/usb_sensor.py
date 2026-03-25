from __future__ import annotations

import asyncio

try:
    import psutil
except ImportError:  # pragma: no cover - dependency/environment specific
    psutil = None

from .base import SensorBase
from .stubs import StubSensor


class UsbSensor(SensorBase):
    source = "usb_sensor"

    def _snapshot_removable(self) -> dict[str, str]:
        if psutil is None:
            return {}
        devices: dict[str, str] = {}
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "removable" in opts:
                devices[part.device] = part.mountpoint
        return devices

    async def run(self, emit) -> None:
        if psutil is None:
            stub = StubSensor(self.context_provider)
            stub.source = self.source
            stub.reason = "usb sensor requires psutil"
            await stub.run(emit)
            return
        previous = self._snapshot_removable()
        while True:
            await asyncio.sleep(2)
            current = self._snapshot_removable()
            mounted = set(current.keys()) - set(previous.keys())
            removed = set(previous.keys()) - set(current.keys())

            for device in mounted:
                payload = self._build_base_event(
                    event_type="usb_mount",
                    severity="medium",
                    op_type="device_mount",
                    process="system",
                    cmdline=None,
                    path=current[device],
                )
                payload["object"]["volume_type"] = "removable"
                await emit(payload)

            for device in removed:
                payload = self._build_base_event(
                    event_type="usb_remove",
                    severity="medium",
                    op_type="device_remove",
                    process="system",
                    cmdline=None,
                    path=previous[device],
                )
                payload["object"]["volume_type"] = "removable"
                await emit(payload)

            previous = current

