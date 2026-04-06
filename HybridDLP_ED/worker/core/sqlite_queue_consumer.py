"""
Consumer đọc từ PersistentEventQueue (SQLite) — thay JSONL khi WORKER_QUEUE_BACKEND=sqlite.
Panic mode theo độ sâu queue (Noteupdate: overload protection).
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, Optional

from loguru import logger

import sys
from pathlib import Path

# worker/ (chứa config.py)
_WORKER_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_WORKER_DIR))
# HybridDLP_ED (pacote agent = L1/L2)
sys.path.insert(0, str(_WORKER_DIR.parent))
from config import WorkerConfig

from agent.persistent_queue import PersistentEventQueue


class SQLiteQueueConsumer:
    """API tương thích JSONLQueueConsumer: get_event, get_stats, check_panic_mode."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        db_path = getattr(WorkerConfig, "AGENT_STORE_DB", None) or WorkerConfig.RUNTIME_DIR / "agent_store.db"
        self._queue = PersistentEventQueue(db_path=db_path)
        self.panic_mode = False
        self.queue_size = 0
        self._panic_on = int(getattr(WorkerConfig, "PANIC_MODE_THRESHOLD", 1000))
        self._panic_off = int(getattr(WorkerConfig, "PANIC_MODE_DISABLE_THRESHOLD", 500))
        self._last_pending_poll = 0.0
        self._cached_pending = 0
        try:
            self._pending_poll_interval = max(0.05, float(os.getenv("WORKER_QUEUE_PENDING_POLL_SEC", "0.35")))
        except ValueError:
            self._pending_poll_interval = 0.35
        try:
            self._panic_state_min_interval = max(1.0, float(os.getenv("WORKER_PANIC_STATE_WRITE_SEC", "5.0")))
        except ValueError:
            self._panic_state_min_interval = 5.0
        self._last_panic_state_write = 0.0
        self._last_panic_mode_written: Optional[bool] = None
        logger.info(
            f"[PID={self.pid}] SQLiteQueueConsumer: db={db_path}, "
            f"panic_on={self._panic_on}, panic_off={self._panic_off}"
        )

    def _refresh_panic(self, pending: int, now: float) -> None:
        changed = False
        if (not self.panic_mode) and pending >= self._panic_on:
            self.panic_mode = True
            changed = True
            logger.warning(f"[PID={self.pid}] Panic mode ON (queue depth={pending})")
        elif self.panic_mode and pending <= self._panic_off:
            self.panic_mode = False
            changed = True
            logger.info(f"[PID={self.pid}] Panic mode OFF (queue depth={pending})")

        should_write = changed or self._last_panic_mode_written is None
        should_write = should_write or (self.panic_mode != self._last_panic_mode_written)
        should_write = should_write or (now - self._last_panic_state_write >= self._panic_state_min_interval)
        if not should_write:
            return
        self._last_panic_mode_written = self.panic_mode
        self._last_panic_state_write = now
        try:
            self._queue.set_state(
                "worker_panic_mode",
                {"panic_mode": self.panic_mode, "pending": pending, "ts": now},
            )
        except Exception:
            pass

    def get_event(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        deadline = time.time() + max(0.1, float(timeout))
        while time.time() < deadline:
            now = time.time()
            if now - self._last_pending_poll >= self._pending_poll_interval:
                self._cached_pending = self._queue.pending_count()
                self._last_pending_poll = now
            self.queue_size = self._cached_pending
            self._refresh_panic(self._cached_pending, now)

            leased = self._queue.lease_next()
            if leased:
                _qid, event = leased
                event["_queue_id"] = _qid
                et = event.get("type") or event.get("event_type") or "unknown"
                logger.info(
                    f"[PID={self.pid}] Dequeued event id={_qid} type={et}"
                )
                return event
            time.sleep(0.02)
        return None

    def ack(self, queue_id: int) -> None:
        self._queue.ack(queue_id)

    def fail(self, queue_id: int, error: str, max_attempts: int = 5) -> None:
        self._queue.fail(queue_id, error, max_attempts=max_attempts)

    def get_queue_size(self) -> int:
        self.queue_size = self._queue.pending_count()
        return self.queue_size

    def is_panic_mode(self) -> bool:
        return self.panic_mode

    def check_panic_mode(self) -> bool:
        return self.panic_mode

    def get_stats(self) -> Dict[str, Any]:
        n = self.get_queue_size()
        return {
            "queue_size": n,
            "panic_mode": self.panic_mode,
            "queue_type": "sqlite",
        }
