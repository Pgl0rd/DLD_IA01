from __future__ import annotations

import asyncio

from .base import SensorBase


class StubSensor(SensorBase):
    """Explicit non-production sensor placeholder."""

    source = "stub_sensor"
    reason = "os integration not implemented"

    async def run(self, emit) -> None:
        # Stub is intentionally silent and non-emitting in production runtime.
        while True:
            await asyncio.sleep(5)

