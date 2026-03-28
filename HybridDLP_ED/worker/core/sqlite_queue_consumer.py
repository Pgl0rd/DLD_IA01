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
        logger.info(
            f"[PID={self.pid}] SQLiteQueueConsumer: db={db_path}, "
            f"panic_on={self._panic_on}, panic_off={self._panic_off}"
        )

    def _refresh_panic(self, pending: int) -> None:
        if (not self.panic_mode) and pending >= self._panic_on:
            self.panic_mode = True
            logger.warning(f"[PID={self.pid}] Panic mode ON (queue depth={pending})")
        elif self.panic_mode and pending <= self._panic_off:
            self.panic_mode = False
            logger.info(f"[PID={self.pid}] Panic mode OFF (queue depth={pending})")
        try:
            self._queue.set_state(
                "worker_panic_mode",
                {"panic_mode": self.panic_mode, "pending": pending, "ts": time.time()},
            )
        except Exception:
            pass

    def get_event(self, timeout: int = 1) -> Optional[Dict[str, Any]]:
        deadline = time.time() + max(0.1, float(timeout))
        while time.time() < deadline:
            pending = self._queue.pending_count()
            self.queue_size = pending
            self._refresh_panic(pending)

            leased = self._queue.lease_next()
            if leased:
                _qid, event = leased
                event["_queue_id"] = _qid
                et = event.get("type") or event.get("event_type") or "unknown"
                logger.info(
                    f"[PID={self.pid}] Dequeued event id={_qid} type={et}"
                )
                return event
            time.sleep(0.05)
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
