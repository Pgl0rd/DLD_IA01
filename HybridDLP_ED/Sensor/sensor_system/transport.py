from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Awaitable, Callable, Dict, List

from cryptography.fernet import Fernet

from .config import QueueConfig

PublishFn = Callable[[Dict], Awaitable[None]]
logger = logging.getLogger(__name__)


class EncryptedLocalBuffer:
    def __init__(self, path: Path, key_path: Path) -> None:
        self.path = path
        self.key_path = key_path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self._cipher = Fernet(self._load_or_create_key())

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return self.key_path.read_bytes()
        key = Fernet.generate_key()
        self.key_path.write_bytes(key)
        return key

    def append(self, event: Dict) -> None:
        encrypted = self._cipher.encrypt(json.dumps(event).encode("utf-8"))
        with self.path.open("ab") as f:
            f.write(encrypted + b"\n")

    def load_all(self) -> List[Dict]:
        if not self.path.exists():
            return []
        events: List[Dict] = []
        for line in self.path.read_bytes().splitlines():
            if not line.strip():
                continue
            decrypted = self._cipher.decrypt(line)
            events.append(json.loads(decrypted.decode("utf-8")))
        return events

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()


class ReliableEventQueue:
    def __init__(self, config: QueueConfig, publisher: PublishFn) -> None:
        self.config = config
        self.publisher = publisher
        self.queue: asyncio.Queue[Dict] = asyncio.Queue()
        self.buffer = EncryptedLocalBuffer(config.local_buffer_path, config.local_buffer_key_path)
        self._worker_task: asyncio.Task | None = None

    async def start(self) -> None:
        buffered = self.buffer.load_all()
        self.buffer.clear()
        if buffered:
            logger.info("Re-queueing %d buffered events", len(buffered))
        for event in buffered:
            await self.queue.put(event)
        self._worker_task = asyncio.create_task(self._worker())

    async def stop(self) -> None:
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass

    async def emit(self, event: Dict) -> None:
        await self.queue.put(event)

    async def _worker(self) -> None:
        while True:
            event = await self.queue.get()
            delivered = False
            for attempt in range(1, self.config.retry_count + 1):
                try:
                    await self.publisher(event)
                    delivered = True
                    break
                except Exception as exc:
                    logger.warning(
                        "Publish failed (attempt %d/%d): %s",
                        attempt,
                        self.config.retry_count,
                        exc,
                    )
                    if attempt < self.config.retry_count:
                        await asyncio.sleep(self.config.retry_backoff_seconds * attempt)
            if not delivered:
                logger.error("Event buffered offline after retries exhausted")
                self.buffer.append(event)


class StdoutPublisher:
    async def __call__(self, event: Dict) -> None:
        logger.info(
            "Event emitted: type=%s source=%s severity=%s",
            event.get("type"),
            event.get("source"),
            event.get("severity"),
        )
        print(json.dumps(event, ensure_ascii=True))

