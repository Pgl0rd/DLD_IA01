from __future__ import annotations

import asyncio
import platform

from .base import SensorBase
from .stubs import StubSensor


class PrintSensor(SensorBase):
    source = "print_sensor"

    async def run(self, emit) -> None:
        if platform.system().lower() != "windows":
            stub = StubSensor(self.context_provider)
            stub.source = self.source
            stub.reason = "print sensor requires windows spooler integration"
            await stub.run(emit)
            return
        # Explicit production stub for Windows spooler integration.
        # Separation is intentional: no fake print payloads are emitted.
        while True:
            await asyncio.sleep(5)

