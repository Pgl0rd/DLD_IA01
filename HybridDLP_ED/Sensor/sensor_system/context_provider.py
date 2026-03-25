from __future__ import annotations

import getpass
import os
import platform
from dataclasses import dataclass

try:
    import psutil
except ImportError:  # pragma: no cover - dependency/environment specific
    psutil = None

try:
    import win32gui
    import win32process
except ImportError:  # pragma: no cover - dependency/environment specific
    win32gui = None
    win32process = None

from .schema import Context


@dataclass
class RuntimeActor:
    user: str
    process: str
    cmdline: str | None


class ContextProvider:
    def get_context(self) -> Context:
        if platform.system().lower() == "windows":
            return self._get_windows_context()
        process_name = os.path.basename(os.getenv("COMSPEC", "python"))
        return Context(
            window_title="unknown_window",
            fg_app=platform.system().lower(),
            fg_process=process_name.lower() if process_name else "unknown",
        )

    def _get_windows_context(self) -> Context:
        if win32gui is None or win32process is None:
            process_name = os.path.basename(os.getenv("COMSPEC", "python"))
            return Context(
                window_title="unknown_window",
                fg_app="windows",
                fg_process=process_name.lower() if process_name else "unknown",
            )

        try:
            hwnd = win32gui.GetForegroundWindow()
            title = win32gui.GetWindowText(hwnd) or "unknown_window"
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            process_name = "unknown"
            if psutil is not None and pid:
                try:
                    process_name = psutil.Process(pid).name().lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    process_name = "unknown"
            fg_app = process_name.rsplit(".", 1)[0] if process_name != "unknown" else "windows"
            return Context(
                window_title=title.lower(),
                fg_app=fg_app.lower(),
                fg_process=process_name.lower(),
            )
        except Exception:
            return Context(window_title="unknown_window", fg_app="windows", fg_process="unknown")

    def get_actor(self, process_name: str, cmdline: str | None = None) -> RuntimeActor:
        return RuntimeActor(
            user=getpass.getuser().lower(),
            process=(process_name or "unknown").lower(),
            cmdline=cmdline.lower() if cmdline else None,
        )

