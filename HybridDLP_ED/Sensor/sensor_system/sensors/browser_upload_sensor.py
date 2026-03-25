"""
BrowserUploadSensor – L1 Sensor (TCP Server mode)
===================================================
Chạy một TCP server trên 127.0.0.1:PORT để nhận message JSON từ
Native Messaging Host. Dùng TCP thay vì Named Pipe vì:
  - asyncio hỗ trợ TCP server natively trên mọi OS
  - Không cần pywin32 hay ctypes thêm
  - Dễ debug: telnet 127.0.0.1 <port>

Native Host kết nối → gửi newline-delimited JSON → sensor nhận → emit event.

Port mặc định: 47266  (có thể cấu hình qua BrowserUploadSensorConfig)
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable, Dict, Optional

from .base import SensorBase
from ..context_provider import ContextProvider

logger = logging.getLogger(__name__)

# ── Configuration ──────────────────────────────────────────────────────────────
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 47266
MAX_MESSAGE_BYTES = 1 * 1024 * 1024   # 1 MB guard

KNOWN_BROWSERS = frozenset({
    "chrome", "firefox", "edge", "brave", "opera", "safari", "chromium",
    "msedge", "vivaldi",
})

TRIGGER_TYPES = frozenset({"file_input", "drag_drop", "xhr", "fetch", "form_submit", "blocked_upload"})


class BrowserUploadSensor(SensorBase):
    """
    L1 sensor: Browser Upload via Native Messaging Host (TCP server).

    Luồng:
        Browser Extension (content.js)
            → background.js → chrome.runtime.connectNative()
            → native_host.py (stdio ↔ TCP 127.0.0.1:47266)
            → BrowserUploadSensor TCP server (this class)
            → emit(browser_upload event)
            → UploadCorrelatorPublisher / BrowserUploadContextResolver
            → L2 Secure IPC Queue
    """

    source = "browser_upload_sensor"

    def __init__(
        self,
        context_provider: ContextProvider,
        pipe_name: str = DEFAULT_HOST,   # kept for config compat (= host)
        poll_timeout_ms: int = 200,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
    ) -> None:
        super().__init__(context_provider)
        self._host = host
        self._port = port
        self._emit: Optional[Callable[[Dict[str, Any]], Any]] = None

    # ── Main loop ──────────────────────────────────────────────────────────────

    async def run(self, emit: Callable[[Dict[str, Any]], Any]) -> None:
        """Start TCP server and handle incoming connections."""
        self._emit = emit
        logger.info(
            "[BrowserUploadSensor] Starting TCP server on %s:%d",
            self._host, self._port,
        )
        server = await asyncio.start_server(
            self._handle_connection,
            self._host,
            self._port,
            reuse_address=True,
        )
        addr = server.sockets[0].getsockname()
        logger.info("[BrowserUploadSensor] Listening on %s:%d — awaiting Native Host.", *addr)
        async with server:
            await server.serve_forever()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        logger.info("[BrowserUploadSensor] Native Host connected from %s", peer)
        buffer = b""
        try:
            while True:
                try:
                    chunk = await asyncio.wait_for(reader.read(4096), timeout=30.0)
                except asyncio.TimeoutError:
                    continue

                if not chunk:
                    logger.info("[BrowserUploadSensor] Native Host disconnected (%s).", peer)
                    break

                buffer += chunk
                if len(buffer) > MAX_MESSAGE_BYTES * 2:
                    logger.warning("[BrowserUploadSensor] Buffer overflow, resetting.")
                    buffer = b""
                    continue

                # Newline-delimited JSON
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    if len(line) > MAX_MESSAGE_BYTES:
                        logger.warning("[BrowserUploadSensor] Oversized message, dropped.")
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8", errors="replace"))
                    except json.JSONDecodeError as exc:
                        logger.warning("[BrowserUploadSensor] JSON error: %s", exc)
                        continue

                    event = self._build_browser_upload_event(msg)
                    if event and self._emit:
                        await self._emit(event)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.exception("[BrowserUploadSensor] Connection error: %s", exc)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    # ── Event building ─────────────────────────────────────────────────────────

    def _build_browser_upload_event(self, msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(msg, dict):
            return None

        # Ignore keep-alive pings from the extension's service worker
        if msg.get("type") == "ping":
            return None

        browser = str(msg.get("browser") or "unknown_browser").lower()
        tab_url = str(msg.get("tab_url") or "")
        destination = str(
            msg.get("destination") or self._extract_domain(tab_url) or "unknown"
        )
        filename = str(msg.get("filename") or "")
        size_bytes: Optional[float] = self._safe_float(msg.get("size"))
        trigger = str(msg.get("trigger") or "unknown")
        if trigger not in TRIGGER_TYPES:
            trigger = "unknown"

        confidence_score: float = float(msg.get("confidence_score") or 0.80)
        confidence_score = max(0.0, min(1.0, confidence_score))

        severity = "high" if confidence_score >= 0.85 else "medium"

        tags = ["browser_upload", f"trigger_{trigger}"]
        if browser in KNOWN_BROWSERS:
            tags.append(f"browser_{browser}")

        base = self._build_base_event(
            event_type="browser_upload",
            severity=severity,
            op_type="upload",
            process=browser,
            cmdline=None,
            path=None,
            bytes_out=size_bytes,
            tags=tags,
        )

        base["context"]["window_title"] = tab_url[:256] if tab_url else None

        base["network"] = {
            "dest_domain": destination,
            "dest_ip": None,
            "dest_url": tab_url[:1024] if tab_url else None,
            "method": "POST" if trigger in {"xhr", "fetch", "form_submit"} else None,
            "content_type": "multipart/form-data" if filename else None,
            "host_bytes_sent_total": None,
            "host_bytes_sent_delta": size_bytes,
        }

        base["browser_upload"] = {
            "filename": filename or None,
            "size": int(size_bytes) if size_bytes is not None else None,
            "tab_url": tab_url[:1024] if tab_url else None,
            "destination": destination,
            "trigger": trigger,
            "browser": browser,
            "confidence_score": round(confidence_score, 3),
            "local_path": None,
        }

        logger.info(
            "[BrowserUploadSensor] Emitting browser_upload: file=%s size=%s dest=%s trigger=%s",
            filename, size_bytes, destination, trigger,
        )
        return base

    # ── Utilities ──────────────────────────────────────────────────────────────

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
    def _safe_float(value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None
