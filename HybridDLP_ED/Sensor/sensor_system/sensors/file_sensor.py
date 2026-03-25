from __future__ import annotations

import asyncio
from collections import deque
from pathlib import Path
from time import monotonic

try:
    from watchdog.events import FileSystemEvent, FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - dependency/environment specific
    FileSystemEvent = object  # type: ignore[assignment]
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None

from .base import SensorBase, classify_volume
from .stubs import StubSensor

try:
    import psutil
except ImportError:  # pragma: no cover - dependency/environment specific
    psutil = None


class _FsEventHandler(FileSystemEventHandler):
    def __init__(self, sensor: "FileSensor", emit) -> None:
        self.sensor = sensor
        self.emit = emit
        super().__init__()

    def on_created(self, event: FileSystemEvent) -> None:
        asyncio.run_coroutine_threadsafe(self.sensor._handle_fs_event("file_create", event, self.emit), self.sensor.loop)

    def on_deleted(self, event: FileSystemEvent) -> None:
        asyncio.run_coroutine_threadsafe(self.sensor._handle_fs_event("file_delete", event, self.emit), self.sensor.loop)

    def on_moved(self, event: FileSystemEvent) -> None:
        src_path = getattr(event, "src_path", None)
        dst_path = getattr(event, "dest_path", None)
        op_type = self.sensor._classify_move_event(src_path, dst_path)
        asyncio.run_coroutine_threadsafe(self.sensor._handle_fs_event(op_type, event, self.emit), self.sensor.loop)

    def on_modified(self, event: FileSystemEvent) -> None:
        asyncio.run_coroutine_threadsafe(self.sensor._handle_fs_event("file_modify", event, self.emit), self.sensor.loop)


class FileSensor(SensorBase):
    source = "file_sensor"

    def __init__(self, context_provider, watch_paths: list[str] | None = None) -> None:
        super().__init__(context_provider)
        self.watch_paths = watch_paths or []
        self.loop = None
        self._suppress_modified_until: dict[str, float] = {}
        self._modified_suppress_window_seconds = 2.0
        self._pending_delete_tasks: dict[str, asyncio.Task] = {}
        self._pending_delete_meta: dict[str, tuple[float, str]] = {}
        self._delete_reconcile_window_seconds = 1.0
        self._bulk_window_seconds = 30.0
        self._bulk_threshold = 50
        self._external_events: deque[tuple[float, str]] = deque()
        self._last_bulk_emit_ts = 0.0
        self._noise_path_tokens = (
            "\\appdata\\local\\temp\\",
            "\\appdata\\local\\google\\chrome\\user data\\",
            "\\appdata\\roaming\\cursor\\",
            "\\appdata\\roaming\\zalodata\\cache\\",
            "\\cache\\",
            "\\code cache\\",
            "\\gpucache\\",
            "\\network\\",
            "\\logs\\",
            "\\indexeddb\\",
            "\\service worker\\",
        )
        self._noise_extensions = {
            ".tmp",
            ".temp",
            ".log",
            ".ldb",
            ".sqlite",
            ".journal",
            ".wal",
            ".idx",
            ".pack",
        }

    def _mark_suppress_modified(self, path: str | None) -> None:
        if path:
            self._suppress_modified_until[path] = monotonic() + self._modified_suppress_window_seconds

    def _classify_move_event(self, src_path: str | None, dst_path: str | None) -> str:
        if not src_path or not dst_path:
            return "file_move"
        src_parent = Path(src_path).parent
        dst_parent = Path(dst_path).parent
        if src_parent == dst_parent:
            return "file_rename"
        return "file_move"

    def _should_suppress_modified(self, path: str | None) -> bool:
        if not path:
            return False
        now = monotonic()
        expires = self._suppress_modified_until.get(path)
        if expires is None:
            return False
        if now <= expires:
            return True
        self._suppress_modified_until.pop(path, None)
        return False

    def _same_drive(self, src_path: str | None, dst_path: str | None) -> bool:
        if not src_path or not dst_path:
            return False
        return Path(src_path).drive.lower() == Path(dst_path).drive.lower()

    def _is_probable_move_pair(self, deleted_path: str | None, created_path: str | None) -> bool:
        if not deleted_path or not created_path:
            return False
        deleted_name = Path(deleted_path).name.lower()
        created_name = Path(created_path).name.lower()
        return deleted_name == created_name

    def _path_signature(self, path: str | None) -> str:
        if not path:
            return ""
        p = Path(path)
        return f"{p.name.lower()}|{p.suffix.lower()}"

    def _resolve_watch_paths(self) -> list[str]:
        resolved = [str(Path(p)) for p in self.watch_paths if p]
        if resolved:
            return resolved
        if psutil is None:
            return [str(Path.cwd())]
        paths: list[str] = []
        for part in psutil.disk_partitions(all=False):
            opts = (part.opts or "").lower()
            if "cdrom" in opts:
                continue
            if "fixed" in opts or "removable" in opts or "remote" in opts:
                paths.append(part.mountpoint)
        return paths or [str(Path.cwd())]

    def _is_noise_path(self, path: str | None) -> bool:
        if not path:
            return False
        lowered = path.lower()
        if any(token in lowered for token in self._noise_path_tokens):
            return True
        ext = Path(path).suffix.lower()
        if ext in self._noise_extensions:
            return True
        return False

    def _cleanup_bulk_window(self, now_ts: float) -> None:
        while self._external_events and now_ts - self._external_events[0][0] > self._bulk_window_seconds:
            self._external_events.popleft()

    def _external_candidate_destination(self, op_type: str, src_path: str | None, dst_path: str | None) -> str | None:
        if op_type == "file_move":
            return dst_path
        if op_type == "file_create":
            return src_path
        if op_type == "file_copy":
            return dst_path
        return None

    async def _track_bulk_external_copy(
        self,
        *,
        op_type: str,
        src_path: str | None,
        dst_path: str | None,
        emit,
    ) -> None:
        destination = self._external_candidate_destination(op_type, src_path, dst_path)
        volume_type = classify_volume(destination)
        if volume_type not in {"removable", "network"}:
            return

        now_ts = monotonic()
        self._external_events.append((now_ts, destination or ""))
        self._cleanup_bulk_window(now_ts)
        unique_files = {path for _, path in self._external_events if path}
        file_count = len(unique_files)
        if file_count < self._bulk_threshold:
            return
        if now_ts - self._last_bulk_emit_ts < self._bulk_window_seconds:
            return

        payload = self._build_base_event(
            event_type="file_copy",
            severity="high",
            op_type="file_copy",
            process="filesystem",
            cmdline=None,
            path=src_path,
            dst_path=destination,
            file_count=file_count,
            tags=["bulk_external_copy", volume_type],
        )
        payload["object"]["volume_type"] = volume_type
        await emit(payload)
        self._last_bulk_emit_ts = now_ts

    async def _emit_file_event(
        self,
        emit,
        *,
        op_type: str,
        src_path: str | None,
        dst_path: str | None = None,
    ) -> None:
        payload = self._build_base_event(
            event_type=op_type,
            severity="medium",
            op_type=op_type,
            process="filesystem",
            cmdline=None,
            path=src_path,
            dst_path=dst_path or None,
            file_count=1,
        )
        payload["object"]["old_ext"] = Path(src_path).suffix.lower() if src_path else None
        payload["object"]["new_ext"] = Path(dst_path).suffix.lower() if dst_path else None
        await emit(payload)

    async def _emit_delete_delayed(self, path: str, emit) -> None:
        try:
            await asyncio.sleep(self._delete_reconcile_window_seconds)
            await self._emit_file_event(emit, op_type="file_delete", src_path=path)
        finally:
            self._pending_delete_tasks.pop(path, None)
            self._pending_delete_meta.pop(path, None)

    async def _handle_fs_event(self, op_type: str, event: FileSystemEvent, emit) -> None:
        if event.is_directory:
            return
        src_path = getattr(event, "src_path", None)
        dst_path = getattr(event, "dest_path", None)
        if self._is_noise_path(src_path) and self._is_noise_path(dst_path):
            return

        if op_type == "file_delete" and src_path:
            if src_path not in self._pending_delete_tasks:
                self._pending_delete_meta[src_path] = (monotonic(), self._path_signature(src_path))
                self._pending_delete_tasks[src_path] = asyncio.create_task(self._emit_delete_delayed(src_path, emit))
            return

        if op_type == "file_create" and src_path:
            now = monotonic()
            for deleted_path, pending_task in list(self._pending_delete_tasks.items()):
                meta = self._pending_delete_meta.get(deleted_path)
                if meta is None:
                    continue
                deleted_ts, deleted_sig = meta
                created_sig = self._path_signature(src_path)
                if now - deleted_ts > self._delete_reconcile_window_seconds:
                    continue
                if deleted_sig != created_sig:
                    continue
                if self._is_probable_move_pair(deleted_path, src_path):
                    pending_task.cancel()
                    self._pending_delete_tasks.pop(deleted_path, None)
                    self._pending_delete_meta.pop(deleted_path, None)
                    await self._emit_file_event(emit, op_type="file_move", src_path=deleted_path, dst_path=src_path)
                    self._mark_suppress_modified(deleted_path)
                    self._mark_suppress_modified(src_path)
                    return

        if op_type == "file_modify" and self._should_suppress_modified(src_path):
            return
        if op_type in {"file_move", "file_rename", "file_create"}:
            self._mark_suppress_modified(src_path)
            self._mark_suppress_modified(dst_path)
        await self._emit_file_event(emit, op_type=op_type, src_path=src_path, dst_path=dst_path)
        await self._track_bulk_external_copy(
            op_type=op_type,
            src_path=src_path,
            dst_path=dst_path,
            emit=emit,
        )

    async def run(self, emit) -> None:
        if Observer is None:
            stub = StubSensor(self.context_provider)
            stub.source = self.source
            stub.reason = "file sensor requires watchdog"
            await stub.run(emit)
            return
        self.loop = asyncio.get_running_loop()
        observer = Observer()
        handler = _FsEventHandler(self, emit)
        for watch_path in self._resolve_watch_paths():
            observer.schedule(handler, watch_path, recursive=True)
        observer.start()
        try:
            while True:
                await asyncio.sleep(1)
        finally:
            for task in self._pending_delete_tasks.values():
                task.cancel()
            self._pending_delete_tasks.clear()
            observer.stop()
            observer.join()

