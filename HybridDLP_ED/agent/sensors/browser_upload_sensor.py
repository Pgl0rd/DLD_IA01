from __future__ import annotations

import json
import os
import socket
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    # Optional import: chỉ để fallback context snapshot nếu có ContextProvider.
    from agent.sensors.context import ContextProvider  # type: ignore
except Exception:
    ContextProvider = None  # type: ignore

# Extension nhớm như ảnh — resolve vào Pictures\Screenshots
_IMAGE_EXTENSIONS: frozenset = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".tiff", ".tif", ".webp", ".heic", ".heif",
})


class BrowserUploadSensor:
    """
    L1 sensor: Browser upload via local TCP server.

    Port/Host compatible with Sensor/sensor_system/sensors/browser_upload_sensor.py:
      - host: 127.0.0.1
      - port: 47266
      - newline-delimited JSON messages from native host / browser extension

    Output events:
      - type: "browser_upload"
      - operation.op_type: "upload" (so upload rules can match)
      - network.dest_domain/dest_url/method/content_type + bytes_sent_total
      - object.path/local_path (if message provides it) to enable correlator fallback
    """

    def __init__(
        self,
        queue_manager,
        host: str = "127.0.0.1",
        port: int = 47266,
        poll_timeout_sec: float = 0.5,
        max_message_bytes: int = 1024 * 1024,
    ):
        self.qm = queue_manager
        self.host = host
        self.port = int(port)
        self.poll_timeout_sec = float(poll_timeout_sec)
        self.max_message_bytes = int(max_message_bytes)

        self.known_browsers: Set[str] = {
            "chrome",
            "firefox",
            "edge",
            "brave",
            "opera",
            "safari",
            "chromium",
            "msedge",
            "vivaldi",
        }
        self.trigger_types: Set[str] = {"file_input", "drag_drop", "xhr", "fetch", "form_submit", "blocked_upload"}

        self._server_sock: Optional[socket.socket] = None

    def _emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _browser_to_exe(self, browser: str) -> str:
        b = (browser or "").lower().strip()
        if b in {"msedge", "edge"}:
            return "msedge.exe"
        if b in {"chrome", "chromium"}:
            return "chrome.exe"
        if b in {"firefox"}:
            return "firefox.exe"
        if b in {"brave"}:
            return "brave.exe"
        if b in {"opera"}:
            return "opera.exe"
        if b in {"vivaldi"}:
            return "vivaldi.exe"
        return f"{b or 'browser'}.exe"

    @staticmethod
    def _extract_domain(url: str) -> Optional[str]:
        if not url:
            return None
        try:
            no_scheme = url.split("//", 1)[-1]
            domain = no_scheme.split("/")[0].split("?")[0].split(":")[0].lower()
            return domain if domain else None
        except Exception:
            return None

    @staticmethod
    def _safe_float(v: Any) -> Optional[float]:
        try:
            if v is None:
                return None
            return float(v)
        except Exception:
            return None

    @staticmethod
    def _resolve_local_path(filename: str) -> Optional[str]:
        """
        Resolve full path từ filename khi extension không gửi local_path.

        Quy tắc:
          - Ảnh (.png, .jpg, …) → Pictures\\Screenshots
          - Các loại khác       → Downloads

        Chỉ trả về path nếu file thực sự tồn tại; nếu không trả về None.
        """
        if not filename:
            return None
        try:
            stem = Path(filename).name  # giữ nguyên tên (kể cả sub-path)
            ext = Path(filename).suffix.lower()
            home = Path.home()

            # Smart resolve: try multiple candidate locations
            candidates = []
            if ext in _IMAGE_EXTENSIONS:
                candidates.append(home / "Pictures" / "Screenshots" / stem)
                candidates.append(home / "Downloads" / stem)
                candidates.append(home / "Pictures" / stem)
            else:
                candidates.append(home / "Downloads" /  stem)
                candidates.append(home / "Documents" / stem)
                candidates.append(home / "Desktop" / stem)

            for candidate in candidates:
                if candidate.exists():
                    return str(candidate)

            # Fallback to the strict requested rule if file is not found
            if ext in _IMAGE_EXTENSIONS:
                return str(home / "Pictures" / "Screenshots" / stem)
            return str(home / "Downloads" / stem)
        except Exception:
            return None

    def _build_event(self, msg: Dict[str, Any], ctx_snapshot: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(msg, dict):
            return None
        if msg.get("type") == "ping":
            return None

        browser = str(msg.get("browser") or "unknown_browser").lower()
        tab_url = str(msg.get("tab_url") or "") or None
        destination = str(msg.get("destination") or "") or None
        if not destination and tab_url:
            destination = self._extract_domain(tab_url)

        filename = str(msg.get("filename") or "")
        size_bytes = self._safe_float(msg.get("size"))
        trigger = str(msg.get("trigger") or "unknown").lower()
        if trigger not in self.trigger_types:
            trigger = "unknown"

        confidence_score = self._safe_float(msg.get("confidence_score"))
        confidence_score = float(confidence_score) if confidence_score is not None else 0.80
        confidence_score = max(0.0, min(1.0, confidence_score))
        severity = "high" if confidence_score >= 0.85 else "medium"

        tags: List[str] = ["browser_upload", f"trigger_{trigger}"]
        if browser in self.known_browsers:
            tags.append(f"browser_{browser}")

        # If extension provides local_path, set it to object.path so correlator/rules can use it.
        local_path = msg.get("local_path") or msg.get("path") or None
        local_path = str(local_path) if local_path else None

        # Nếu không có local_path nhưng có filename, thử resolve từ các folder mặc định.
        if not local_path and filename:
            local_path = self._resolve_local_path(filename)

        ext = None
        if local_path:
            try:
                ext = Path(local_path).suffix.lower() or None
            except Exception:
                ext = None

        # Lightweight sensitivity heuristic by extension, so upload rules can fire without file_sensor evidence.
        sensitive_exts = {".xlsx", ".xls", ".csv", ".docx", ".doc", ".pdf", ".sql", ".zip", ".7z", ".env"}
        sensitivity = "Sensitive" if (ext in sensitive_exts) else "Normal"

        browser_exe = self._browser_to_exe(browser)

        method = "POST" if trigger in {"xhr", "fetch", "form_submit"} else None
        content_type = "multipart/form-data" if filename else None

        evt: Dict[str, Any] = {
            "type": "browser_upload",
            "source": "browser_upload_sensor",
            "severity": severity,
            "ts": time.time(),
            "context": ctx_snapshot,
            "actor": {
                "user": ctx_snapshot.get("user"),
                "pid": ctx_snapshot.get("fg_pid"),
                "process": browser_exe,
                "cmdline": ctx_snapshot.get("fg_cmdline"),
                "exe": ctx_snapshot.get("fg_exe_path"),
            },
            "process": {"pid": ctx_snapshot.get("fg_pid"), "name": browser_exe, "exe": ctx_snapshot.get("fg_exe_path"), "cmdline": ctx_snapshot.get("fg_cmdline")},
            "operation": {"op_type": "upload", "tool": browser_exe},
            "object": {
                "path": local_path,
                "dst_path": None,
                "name": filename or (Path(local_path).name if local_path else None),
                "ext": ext,
                "size": int(size_bytes) if size_bytes is not None else None,
                "mtime": None,
                "exists": None,
                "signature": None,
                "hash_sha256": None,
                "sensitivity": sensitivity,
            },
            "network": {
                "dest_domain": destination,
                "dest_ip": None,
                "dest_url": tab_url,
                "method": method,
                "content_type": content_type,
                "bytes_sent_total": int(size_bytes) if size_bytes is not None else None,
                "bytes_out_total": int(size_bytes) if size_bytes is not None else None,
                "bytes_in_total": 0,
                "external_dst": True,
            },
            "browser_upload": {
                "filename": filename or None,
                "size": int(size_bytes) if size_bytes is not None else None,
                "tab_url": tab_url[:1024] if tab_url else None,
                "destination": destination,
                "trigger": trigger,
                "browser": browser,
                "confidence_score": round(confidence_score, 3),
                "local_path": local_path,
            },
            "metrics": {"file_count": None, "entropy": None},
            "flags": {"password_protected": None},
            "ioc_hits": [],
            "tags": tags,
        }
        return evt

    def run_loop(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        # Build a snapshot once per loop iteration.
        def snapshot_ctx() -> Dict[str, Any]:
            if ctx_provider is None:
                return {}
            try:
                if hasattr(ctx_provider, "snapshot"):
                    return ctx_provider.snapshot() or {}
            except Exception:
                pass
            return {}

        host = self.host
        port = self.port

        self._server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_sock.bind((host, port))
        self._server_sock.listen(1)
        self._server_sock.settimeout(self.poll_timeout_sec)

        # started event (optional but useful in JSONL)
        self._emit(
            {
                "type": "browser_upload_sensor_started",
                "source": "l1",
                "severity": "info",
                "ts": time.time(),
                "context": snapshot_ctx(),
            }
        )

        buffer_per_conn: bytes = b""

        while not stop_event.is_set():
            try:
                conn, _addr = self._server_sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break

            with conn:
                conn.settimeout(self.poll_timeout_sec)
                buffer_per_conn = b""
                while not stop_event.is_set():
                    try:
                        chunk = conn.recv(4096)
                    except socket.timeout:
                        continue
                    except Exception:
                        break

                    if not chunk:
                        break

                    buffer_per_conn += chunk
                    if len(buffer_per_conn) > self.max_message_bytes:
                        buffer_per_conn = b""
                        continue

                    while b"\n" in buffer_per_conn:
                        line, buffer_per_conn = buffer_per_conn.split(b"\n", 1)
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            msg = json.loads(line.decode("utf-8", errors="replace"))
                        except Exception:
                            continue

                        evt = self._build_event(msg, snapshot_ctx())
                        if evt:
                            self._emit(evt)

        try:
            if self._server_sock:
                self._server_sock.close()
        except Exception:
            pass

