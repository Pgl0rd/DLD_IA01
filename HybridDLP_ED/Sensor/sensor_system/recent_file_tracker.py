from __future__ import annotations

from collections import deque
from copy import deepcopy
from pathlib import Path
from time import monotonic
from typing import Deque, Dict, Optional

from .classifiers import SENSITIVE_EXTENSIONS


class RecentFileTracker:
    def __init__(self, ttl_seconds: float = 15.0) -> None:
        self.ttl_seconds = ttl_seconds
        self._events: Deque[tuple[float, Dict]] = deque()

    def _cleanup(self, now_ts: float) -> None:
        while self._events and now_ts - self._events[0][0] > self.ttl_seconds:
            self._events.popleft()

    def _normalize_file_event(self, event: Dict) -> Dict:
        normalized = deepcopy(event)
        obj = normalized.get("object") or {}
        path = obj.get("dst_path") or obj.get("path")
        ext = Path(path).suffix.lower() if path else None
        sensitivity = obj.get("sensitivity") or "unknown"
        recent_staging = False
        if path:
            p = path.lower()
            recent_staging = any(token in p for token in ["\\appdata\\local\\temp\\", "\\temp\\", "\\tmp\\", "\\downloads\\"])
        if sensitivity == "unknown" and ext in SENSITIVE_EXTENSIONS:
            sensitivity = "sensitive"
        normalized["file_evidence"] = {
            "path": path,
            "extension": ext,
            "sensitivity": sensitivity,
            "is_sensitive_extension": bool(ext in SENSITIVE_EXTENSIONS) if ext else False,
            "recent_staging": recent_staging,
        }
        return normalized

    def remember(self, event: Dict) -> None:
        if event.get("type") not in {"file_create", "file_copy", "file_move", "file_rename"}:
            return
        now_ts = monotonic()
        self._cleanup(now_ts)
        self._events.append((now_ts, self._normalize_file_event(event)))

    def best_match(self, process_name: str, fg_app: str) -> Optional[Dict]:
        now_ts = monotonic()
        self._cleanup(now_ts)
        process = (process_name or "").lower()
        app = (fg_app or "").lower()
        for _, ev in reversed(self._events):
            ctx = ev.get("context") or {}
            file_fg_app = (ctx.get("fg_app") or "").lower()
            if file_fg_app and (file_fg_app == app or file_fg_app in process):
                return deepcopy(ev)
        if not self._events:
            return None
        return deepcopy(self._events[-1][1])

