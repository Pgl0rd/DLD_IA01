from __future__ import annotations

import asyncio
import ctypes
import ctypes.wintypes
import hashlib
import platform
import threading
from collections import deque
from time import time

try:
    import pyperclip
except ImportError:  # pragma: no cover - dependency/environment specific
    pyperclip = None

from .base import SensorBase
from .stubs import StubSensor

try:
    import win32clipboard
    import win32con
except ImportError:  # pragma: no cover - dependency/environment specific
    win32clipboard = None
    win32con = None


class ClipboardSensor(SensorBase):
    source = "clipboard_sensor"

    def __init__(self, context_provider) -> None:
        super().__init__(context_provider)
        self.copy_events = deque()
        self.paste_events = deque()
        self._events_lock = threading.Lock()
        self._pending_paste_count = 0
        self._hook_thread: threading.Thread | None = None
        self._hook_stop_event = threading.Event()
        self._hook_id = None
        self._hook_user32 = None
        self._hook_callback = None

    def _roll_count(self, q: deque, now_ts: float, window_seconds: float = 30.0) -> int:
        while q and now_ts - q[0] > window_seconds:
            q.popleft()
        return len(q)

    def _guess_content_type(self, content: str) -> str:
        if content.startswith("file://") or ("\\" in content and ":" in content[:3]):
            return "file"
        return "text"

    def _read_windows_clipboard(self) -> tuple[str, int, str]:
        if win32clipboard is None or win32con is None:
            return ("text", 0, "")
        content_type = "text"
        content_len = 0
        content_repr = ""
        try:
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32con.CF_HDROP):
                files = win32clipboard.GetClipboardData(win32con.CF_HDROP)
                if files:
                    content_type = "file"
                    joined = "\n".join(files)
                    content_repr = joined
                    content_len = len(joined.encode("utf-8"))
            elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_UNICODETEXT):
                text = win32clipboard.GetClipboardData(win32con.CF_UNICODETEXT) or ""
                content_type = self._guess_content_type(text)
                content_repr = text
                content_len = len(text.encode("utf-8"))
            elif win32clipboard.IsClipboardFormatAvailable(win32con.CF_DIB):
                content_type = "image"
                content_repr = "image_binary"
                content_len = 1
        except Exception:
            return ("text", 0, "")
        finally:
            try:
                win32clipboard.CloseClipboard()
            except Exception:
                pass
        return (content_type, content_len, content_repr)

    def _read_clipboard(self) -> tuple[str, int, str]:
        if platform.system().lower() == "windows" and win32clipboard is not None:
            return self._read_windows_clipboard()
        if pyperclip is None:
            return ("text", 0, "")
        try:
            text = pyperclip.paste() or ""
            return (self._guess_content_type(text), len(text.encode("utf-8")), text)
        except Exception:
            return ("text", 0, "")

    def _start_windows_paste_hook(self) -> None:
        if platform.system().lower() != "windows":
            return
        if self._hook_thread and self._hook_thread.is_alive():
            return
        self._hook_stop_event.clear()
        self._hook_thread = threading.Thread(target=self._keyboard_hook_loop, name="clipboard-paste-hook", daemon=True)
        self._hook_thread.start()

    def _stop_windows_paste_hook(self) -> None:
        self._hook_stop_event.set()
        if self._hook_user32 and self._hook_id:
            try:
                self._hook_user32.UnhookWindowsHookEx(self._hook_id)
            except Exception:
                pass
        if self._hook_thread and self._hook_thread.is_alive():
            self._hook_thread.join(timeout=1.0)

    def _register_paste_event(self) -> None:
        now_ts = time()
        with self._events_lock:
            self.paste_events.append(now_ts)
            self._pending_paste_count += 1

    def _consume_pending_paste_count(self) -> int:
        with self._events_lock:
            count = self._pending_paste_count
            self._pending_paste_count = 0
            return count

    def _keyboard_hook_loop(self) -> None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        self._hook_user32 = user32

        WH_KEYBOARD_LL = 13
        WM_KEYDOWN = 0x0100
        WM_SYSKEYDOWN = 0x0104
        VK_V = 0x56
        VK_CONTROL = 0x11

        class KBDLLHOOKSTRUCT(ctypes.Structure):
            _fields_ = [
                ("vkCode", ctypes.c_uint32),
                ("scanCode", ctypes.c_uint32),
                ("flags", ctypes.c_uint32),
                ("time", ctypes.c_uint32),
                ("dwExtraInfo", ctypes.c_void_p),
            ]

        LowLevelKeyboardProc = ctypes.WINFUNCTYPE(
            ctypes.c_long,
            ctypes.c_int,
            ctypes.c_ulong,
            ctypes.c_void_p,
        )

        def hook_proc(n_code, w_param, l_param):
            if n_code >= 0 and w_param in (WM_KEYDOWN, WM_SYSKEYDOWN):
                kb = ctypes.cast(l_param, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
                if kb.vkCode == VK_V:
                    ctrl_down = user32.GetAsyncKeyState(VK_CONTROL) & 0x8000
                    if ctrl_down:
                        self._register_paste_event()
            return user32.CallNextHookEx(self._hook_id, n_code, w_param, l_param)

        self._hook_callback = LowLevelKeyboardProc(hook_proc)
        module_handle = kernel32.GetModuleHandleW(None)
        self._hook_id = user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._hook_callback, module_handle, 0)
        if not self._hook_id:
            return

        msg = ctypes.wintypes.MSG()
        while not self._hook_stop_event.is_set():
            result = user32.GetMessageW(ctypes.byref(msg), 0, 0, 0)
            if result <= 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    async def run(self, emit) -> None:
        if pyperclip is None and win32clipboard is None:
            stub = StubSensor(self.context_provider)
            stub.source = self.source
            stub.reason = "clipboard sensor requires pyperclip or pywin32 clipboard"
            await stub.run(emit)
            return
        self._start_windows_paste_hook()
        last_fingerprint = ""
        try:
            while True:
                await asyncio.sleep(0.25)
                content_type, content_len, content_repr = self._read_clipboard()
                fingerprint = hashlib.sha256(content_repr.encode("utf-8")).hexdigest() if content_repr else ""
                now_ts = time()

                if fingerprint != last_fingerprint:
                    with self._events_lock:
                        self.copy_events.append(now_ts)
                    ctx = self.context_provider.get_context()
                    payload = self._build_base_event(
                        event_type="clipboard_copy",
                        severity="medium",
                        op_type="clipboard_copy",
                        process=ctx.fg_process or "unknown",
                        cmdline=None,
                        bytes_out=content_len,
                    )
                    payload["clipboard"] = {
                        "content_type": content_type,
                        "content_len": content_len,
                        "content": content_repr if content_repr else None,
                        "snapshot_linked": bool(fingerprint),
                        "dest_app": ctx.fg_app or "unknown",
                        "dest_domain": None,
                        "dest_window_title": ctx.window_title or "unknown",
                        "copy_frequency": 0,
                        "paste_frequency": 0,
                        "bulk_paste_event": False,
                    }
                    with self._events_lock:
                        copy_frequency = self._roll_count(self.copy_events, now_ts)
                        paste_frequency = self._roll_count(self.paste_events, now_ts)
                    payload["clipboard"]["copy_frequency"] = copy_frequency
                    payload["clipboard"]["paste_frequency"] = paste_frequency
                    payload["clipboard"]["bulk_paste_event"] = paste_frequency > 5
                    await emit(payload)
                    last_fingerprint = fingerprint

                pending_pastes = self._consume_pending_paste_count()
                for _ in range(pending_pastes):
                    ctx = self.context_provider.get_context()
                    paste_payload = self._build_base_event(
                        event_type="clipboard_paste",
                        severity="medium",
                        op_type="clipboard_paste",
                        process=ctx.fg_process or "unknown",
                        cmdline=None,
                        bytes_out=content_len,
                    )
                    paste_payload["clipboard"] = {
                        "content_type": content_type,
                        "content_len": content_len,
                        "content": content_repr if content_repr else None,
                        "snapshot_linked": bool(fingerprint),
                        "dest_app": ctx.fg_app or "unknown",
                        "dest_domain": None,
                        "dest_window_title": ctx.window_title or "unknown",
                        "copy_frequency": 0,
                        "paste_frequency": 0,
                        "bulk_paste_event": False,
                    }
                    with self._events_lock:
                        copy_frequency = self._roll_count(self.copy_events, now_ts)
                        paste_frequency = self._roll_count(self.paste_events, now_ts)
                    paste_payload["clipboard"]["copy_frequency"] = copy_frequency
                    paste_payload["clipboard"]["paste_frequency"] = paste_frequency
                    paste_payload["clipboard"]["bulk_paste_event"] = paste_frequency > 5
                    await emit(paste_payload)
        finally:
            self._stop_windows_paste_hook()

