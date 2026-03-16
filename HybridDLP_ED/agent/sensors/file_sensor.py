from __future__ import annotations

import os
import time
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from collections import deque

# Optional (better rename/move support)
try:
    from watchdog.observers import Observer  # type: ignore
    from watchdog.events import FileSystemEventHandler  # type: ignore
    _HAS_WATCHDOG = True
except Exception:
    Observer = None
    FileSystemEventHandler = object
    _HAS_WATCHDOG = False


# -----------------------------
# Lightweight helpers (Windows-first)
# -----------------------------
_CLOUD_HINTS = [
    "onedrive",
    "dropbox",
    "google drive",
    "gdrive",
    "syncthing",
    "megasync",
    "box",
    "iclouddrive",
    "icloud drive",
]

_ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
_TABULAR_EXTS = {".csv", ".tsv", ".xlsx", ".xls"}
_TEXTISH_EXTS = {".txt", ".csv", ".tsv", ".json", ".log", ".env", ".ini", ".cfg", ".yaml", ".yml", ".xml"}


def _now() -> float:
    return time.time()


def _iso_utc(ts: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _norm_path(p: str) -> str:
    try:
        p2 = os.path.expandvars(os.path.expanduser(p))
        return str(Path(p2).resolve())
    except Exception:
        return p


def _default_screenshot_watch_paths() -> List[str]:
    paths: List[str] = []
    up = os.path.expandvars(os.path.expanduser(r"%USERPROFILE%"))
    if up:
        paths.append(os.path.join(up, "Pictures", "Screenshots"))
        paths.append(os.path.join(up, "Pictures"))
        paths.append(os.path.join(up, "Desktop"))
    return paths


def _get_ext(p: str) -> str:
    try:
        ext = Path(p).suffix.lower()
        return ext if ext else ""
    except Exception:
        return ""


def _get_name(p: str) -> Optional[str]:
    try:
        return Path(p).name
    except Exception:
        return None


def _maybe_drive_letter(p: str) -> Optional[str]:
    try:
        if len(p) >= 2 and p[1] == ":":
            return p[:2].upper()
    except Exception:
        pass
    return None


def _is_cloud_path(p: str) -> bool:
    s = (p or "").lower()
    return any(h in s for h in _CLOUD_HINTS)


def _entropy_bytes(b: bytes) -> float:
    if not b:
        return 0.0
    freq = [0] * 256
    for x in b:
        freq[x] += 1
    n = len(b)
    import math
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return float(ent)


def _read_head(path: str, max_bytes: int = 8192) -> bytes:
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except Exception:
        return b""


def _read_text_sample(path: str, max_chars: int = 400) -> Tuple[Optional[str], Optional[int]]:
    try:
        ext = _get_ext(path)
        if ext not in _TEXTISH_EXTS:
            return None, None
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            txt = f.read(min(4096, max_chars * 4))
        txt = txt[:max_chars]
        return txt, len(txt)
    except Exception:
        return None, None


def _file_sha256(path: str, max_bytes: Optional[int] = None) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            if max_bytes is None:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    h.update(chunk)
            else:
                remaining = int(max_bytes)
                while remaining > 0:
                    chunk = f.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
        return h.hexdigest()
    except Exception:
        return None


def _signature_from_magic(head: bytes, ext: str = "") -> Optional[str]:
    if not head:
        return None

    if head.startswith(b"\x37\x7A\xBC\xAF\x27\x1C"):
        return "7z"

    if head.startswith(b"Rar!\x1A\x07\x00") or head.startswith(b"Rar!\x1A\x07\x01\x00"):
        return "rar"

    if head.startswith(b"%PDF-"):
        return "pdf"

    if head.startswith(b"\x89PNG\r\n\x1A\n"):
        return "png"

    if head.startswith(b"\xFF\xD8\xFF"):
        return "jpg"

    if head.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        if ext == ".doc":
            return "doc"
        if ext == ".xls":
            return "xls"
        if ext == ".ppt":
            return "ppt"
        return "ole"

    if head.startswith(b"RIFF") and head[8:12] == b"AVI ":
        return "avi"

    if head.startswith(b"RIFF") and head[8:12] == b"WAVE":
        return "wav"

    if head.startswith(b"fLaC"):
        return "flac"

    if head.startswith(b"ID3"):
        return "mp3"

    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
        if ext == ".docx":
            return "docx"
        if ext == ".xlsx":
            return "xlsx"
        if ext == ".pptx":
            return "pptx"
        return "zip"

    return "bin"


def _zip_password_protected(path: str) -> Optional[bool]:
    try:
        import zipfile
        with zipfile.ZipFile(path, "r") as zf:
            for zi in zf.infolist():
                if zi.flag_bits & 0x1:
                    return True
        return False
    except Exception:
        return None


def _volume_type_windows(drive: Optional[str]) -> Optional[str]:
    if not drive:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
        GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
        GetDriveTypeW.restype = wintypes.UINT

        dtype = GetDriveTypeW(drive + "\\")
        mapping = {
            0: "Unknown",
            1: "NoRootDir",
            2: "Removable",
            3: "Fixed",
            4: "Network",
            5: "CDROM",
            6: "RAMDisk",
        }
        return mapping.get(int(dtype), "Unknown")
    except Exception:
        return None


def _is_same_parent(a: str, b: str) -> bool:
    try:
        return Path(a).parent == Path(b).parent
    except Exception:
        return False


def _infer_op_type(evt_kind: str, src_path: str, dst_path: Optional[str], effective_volume_type: Optional[str]) -> str:
    """
    Canonical-ish operation type for rules.
    """
    if evt_kind == "deleted":
        return "file_delete"

    if evt_kind == "modified":
        return "file_modify"

    if evt_kind == "moved":
        if dst_path and _is_same_parent(src_path, dst_path) and _get_name(src_path) != _get_name(dst_path):
            return "file_rename"
        return "file_move"

    if evt_kind == "created":
        # Creation on cloud/removable/network often semantically behaves like copy
        if effective_volume_type in {"Removable", "Network"}:
            return "file_copy"
        if dst_path and _is_cloud_path(dst_path):
            return "file_copy"
        if _is_cloud_path(src_path):
            return "file_copy"
        return "file_create"

    return "file_event"


def _infer_report_event_type(evt_kind: str, src_path: str, dst_path: Optional[str]) -> str:
    if evt_kind == "created":
        return "Create"
    if evt_kind == "modified":
        return "Modify"
    if evt_kind == "deleted":
        return "Delete"
    if evt_kind == "moved":
        try:
            if dst_path:
                sp = Path(src_path)
                dp = Path(dst_path)
                if sp.parent == dp.parent and sp.name != dp.name:
                    return "Rename"
        except Exception:
            pass
        return "Move"
    return "Modify"


def _infer_operation_type(evt_kind: str, src_path: str, dst_path: Optional[str], overwrite: bool = False, effective_volume_type: Optional[str] = None) -> str:
    if evt_kind == "moved":
        try:
            if dst_path and Path(src_path).parent == Path(dst_path).parent and Path(src_path).name != Path(dst_path).name:
                return "Rename"
        except Exception:
            pass
        return "Move"

    if evt_kind == "created":
        if effective_volume_type in {"Removable", "Network"} or _is_cloud_path(dst_path or src_path):
            return "Copy"
        return "Create"

    if overwrite:
        return "Overwrite"
    if evt_kind == "deleted":
        return "Delete"
    return "Modify"


def _classify_sensitivity(ext: str, signature: Optional[str], path: str) -> str:
    p = (path or "").lower()
    is_doc = (ext in {".doc", ".docx", ".pdf"}) or (signature in {"pdf", "doc", "docx"})
    is_tab = ext in {".csv", ".tsv", ".xlsx", ".xls"}
    is_office_zip = ext in {".docx", ".xlsx", ".pptx"} or (signature in {"docx", "xlsx", "pptx"})

    if ("finance" in p or "hr" in p or "customer" in p or "payroll" in p or "salary" in p or "employee" in p) and (is_tab or is_doc or is_office_zip):
        return "Highly Sensitive"
    if is_tab or is_doc or is_office_zip:
        return "Sensitive"
    return "Normal"


def _should_enrich(path: str, dst_path: Optional[str], ext: str, dest_volume_type: Optional[str], op_type: str) -> Dict[str, bool]:
    risk_dst = bool((dst_path and _is_cloud_path(dst_path)) or _is_cloud_path(path))
    risk_volume = bool(dest_volume_type is not None and dest_volume_type != "Fixed")
    rename_like = bool(op_type in {"file_move", "file_rename"} and dst_path and (_get_ext(path) != _get_ext(dst_path)))
    archive_like = (ext in _ARCHIVE_EXTS) or bool(dst_path and _get_ext(dst_path) in _ARCHIVE_EXTS)
    tabular_like = ext in _TABULAR_EXTS
    textish_like = ext in _TEXTISH_EXTS

    return {
        "need_signature": bool(risk_dst or risk_volume or rename_like or archive_like or tabular_like),
        "need_hash": bool(risk_dst or risk_volume or rename_like or op_type in {"file_copy", "file_move", "file_rename"}),
        "need_entropy": bool(archive_like or rename_like),
        "need_zip_pw": bool((ext == ".zip") or (dst_path and _get_ext(dst_path) == ".zip")),
        "need_sample": bool(tabular_like or textish_like),
    }


def _cloud_provider_from_path(p: Optional[str]) -> Optional[str]:
    s = (p or "").lower()
    if "onedrive" in s:
        return "OneDrive"
    if "dropbox" in s:
        return "Dropbox"
    if "google drive" in s or "gdrive" in s:
        return "Google Drive"
    if "box" in s:
        return "Box"
    if "iclouddrive" in s or "icloud drive" in s:
        return "iCloud Drive"
    if "megasync" in s or "\\mega" in s:
        return "MEGA"
    if "syncthing" in s:
        return "Syncthing"
    return None


@dataclass
class _StatLite:
    size: int
    mtime: float
    exists: bool


class FileSystemSensor:
    """
    FILE SYSTEM SENSOR (L1 - metadata only)

    Emits canonical fields:
      - actor.*
      - object.*
      - operation.*
      - metrics.*
      - flags.*
      - content.*

    Keeps legacy flat/report fields for backward compatibility.
    """

    def __init__(
        self,
        queue_manager,
        watch_paths: Optional[List[str]] = None,
        poll_interval_sec: float = 0.5,
        max_head_bytes: int = 8192,
        hash_max_bytes: Optional[int] = 2 * 1024 * 1024,
        sample_max_chars: int = 400,
        agg_window_sec: float = 180.0,
        auto_watch_screenshots: bool = True,
        include_exts: Optional[List[str]] = None,
        exclude_dirs: Optional[List[str]] = None,
    ):
        self.qm = queue_manager
        self.poll_interval_sec = float(poll_interval_sec)
        self.max_head_bytes = int(max_head_bytes)
        self.hash_max_bytes = hash_max_bytes
        self.sample_max_chars = int(sample_max_chars)

        self.agg_window_sec = float(agg_window_sec)
        self._recent_events: deque[Tuple[float, str]] = deque(maxlen=10000)
        self._recent_sensitive_artifacts: deque[Tuple[float, str, str]] = deque(maxlen=5000)

        self.include_exts = [e.lower() for e in (include_exts or [])] or None
        self.exclude_dirs = [s.lower() for s in (exclude_dirs or [])] or []

        self.watch_paths: List[str] = []
        for p in (watch_paths or []):
            self.add_watch_path(p)

        if auto_watch_screenshots and not self.watch_paths:
            for p in _default_screenshot_watch_paths():
                self.add_watch_path(p)

        self._snap: Dict[str, _StatLite] = {}
        self._last_meta: Dict[str, Dict[str, Any]] = {}

        self._observer = None

    def add_watch_path(self, path: str) -> None:
        p = _norm_path(path)
        try:
            if p and p not in self.watch_paths and os.path.isdir(p):
                self.watch_paths.append(p)
        except Exception:
            pass

    def _should_ignore(self, path: str) -> bool:
        lp = (path or "").lower()
        if self.exclude_dirs and any(x in lp for x in self.exclude_dirs):
            return True
        if self.include_exts is not None:
            return _get_ext(path) not in self.include_exts
        return False

    def _emit(self, evt: Dict[str, Any]) -> None:
        try:
            self.qm.enqueue_event(evt)
        except Exception:
            pass

    def _ctx_snapshot(self, ctx_provider: Optional[Any]) -> Dict[str, Any]:
        if not ctx_provider:
            return {}
        try:
            return (ctx_provider.snapshot() or {}) if hasattr(ctx_provider, "snapshot") else {}
        except Exception:
            return {}

    def _stat_best_effort(self, p: str) -> Dict[str, Any]:
        try:
            st = os.stat(p)
            return {"size": int(st.st_size), "mtime": float(st.st_mtime), "exists": True}
        except Exception:
            return {"size": None, "mtime": None, "exists": False}

    def _agg_count(self, now: float, bucket: str) -> int:
        self._recent_events.append((now, bucket))
        cutoff = now - self.agg_window_sec
        while self._recent_events and self._recent_events[0][0] < cutoff:
            self._recent_events.popleft()
        return sum(1 for _, b in self._recent_events if b == bucket)

    def _remember_sensitive_artifact(self, ts: float, path: str, sensitivity: str) -> None:
        if sensitivity not in {"Sensitive", "Highly Sensitive"}:
            return
        self._recent_sensitive_artifacts.append((ts, path, sensitivity))
        cutoff = ts - self.agg_window_sec
        while self._recent_sensitive_artifacts and self._recent_sensitive_artifacts[0][0] < cutoff:
            self._recent_sensitive_artifacts.popleft()

    def _recent_staging_count(self, ts: float) -> int:
        cutoff = ts - self.agg_window_sec
        while self._recent_sensitive_artifacts and self._recent_sensitive_artifacts[0][0] < cutoff:
            self._recent_sensitive_artifacts.popleft()
        return len(self._recent_sensitive_artifacts)

    def _build_actor(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "user": ctx.get("user"),
            "pid": ctx.get("fg_pid"),
            "process": (ctx.get("fg_process") or ctx.get("fg_app")),
            "cmdline": ctx.get("fg_cmdline"),
            "exe_path": ctx.get("fg_exe_path"),
        }

    def _build_object(
        self,
        src_path: str,
        dst_path: Optional[str],
        size: Optional[int],
        src_drive: Optional[str],
        src_volume_type: Optional[str],
        dest_drive: Optional[str],
        dest_volume_type: Optional[str],
        old_ext: Optional[str],
        new_ext: Optional[str],
        signature: Optional[str],
        sensitivity: str,
        file_name: Optional[str],
        file_ext: str,
        file_hash: Optional[str],
        cloud_provider: Optional[str],
    ) -> Dict[str, Any]:
        return {
            "path": src_path,
            "dst_path": dst_path,
            "name": file_name,
            "ext": file_ext,
            "size": size,
            "hash_sha256": file_hash,
            "signature": signature,
            "drive": dest_drive or src_drive,
            "volume_type": dest_volume_type or src_volume_type,
            "src_drive": src_drive,
            "src_volume_type": src_volume_type,
            "dest_drive": dest_drive,
            "dest_volume_type": dest_volume_type,
            "old_ext": old_ext,
            "new_ext": new_ext,
            "sensitivity": sensitivity,
            "cloud_provider": cloud_provider,
        }

    def _build_event(
        self,
        evt_kind: str,
        src_path: str,
        dst_path: Optional[str],
        ctx: Dict[str, Any],
    ) -> Dict[str, Any]:
        ts = _now()
        p = _norm_path(src_path)
        dp = _norm_path(dst_path) if dst_path else None

        if self._should_ignore(dp or p):
            raise RuntimeError("ignored")

        target_for_content = dp or p

        src_drive = _maybe_drive_letter(p)
        src_volume_type = _volume_type_windows(src_drive)

        dest_drive = _maybe_drive_letter(dp) if dp else _maybe_drive_letter(target_for_content)
        dest_volume_type = _volume_type_windows(dest_drive) if dest_drive else None

        effective_drive = dest_drive or src_drive
        effective_volume_type = dest_volume_type or src_volume_type

        op_type = _infer_op_type(evt_kind, p, dp, effective_volume_type)
        report_event_type = _infer_report_event_type(evt_kind, p, dp)
        report_op_type = _infer_operation_type(evt_kind, p, dp, overwrite=(evt_kind == "modified"), effective_volume_type=effective_volume_type)

        old_ext = None
        new_ext = None
        src_ext = _get_ext(p)
        target_ext = _get_ext(target_for_content)

        if op_type in {"file_move", "file_rename"} and dp:
            old_ext = _get_ext(p)
            new_ext = _get_ext(dp)

        enrich_flags = _should_enrich(p, dp, target_ext, effective_volume_type, op_type)

        if evt_kind == "deleted":
            size = None
            mtime = None
            exists = False
        else:
            stx = self._stat_best_effort(target_for_content)
            size = stx["size"]
            mtime = stx["mtime"]
            exists = bool(stx["exists"])

        signature = None
        hash_sha256 = None
        entropy = None
        pw_protected = None
        sample = None
        sample_len = None

        before = self._last_meta.get(p) or self._last_meta.get(target_for_content) or {}
        before_size = before.get("size")
        before_hash = before.get("hash")
        before_ext = before.get("ext")

        head = b""
        if exists and enrich_flags["need_signature"]:
            head = _read_head(target_for_content, max_bytes=self.max_head_bytes)
            signature = _signature_from_magic(head, ext=target_ext)

        if head and enrich_flags["need_entropy"]:
            try:
                entropy = _entropy_bytes(head)
            except Exception:
                entropy = None

        if exists and enrich_flags["need_zip_pw"]:
            pw_protected = _zip_password_protected(target_for_content)

        if exists and enrich_flags["need_hash"]:
            hash_sha256 = _file_sha256(target_for_content, max_bytes=self.hash_max_bytes)

        if exists and enrich_flags["need_sample"]:
            # Prefer text sample for textish files
            sample, sample_len = _read_text_sample(target_for_content, max_chars=self.sample_max_chars)

        if evt_kind != "deleted":
            self._last_meta[target_for_content] = {
                "size": size,
                "hash": hash_sha256,
                "ext": target_ext,
                "last_seen_ts": ts,
            }
            if evt_kind == "moved" and dp:
                self._last_meta.pop(p, None)

        bucket = effective_drive or "NA"
        file_count_window = self._agg_count(ts, bucket)

        sensitivity = _classify_sensitivity(target_ext, signature, target_for_content)
        self._remember_sensitive_artifact(ts, target_for_content, sensitivity)

        proc_name = ctx.get("fg_app") or ctx.get("fg_process")
        proc_id = ctx.get("fg_pid")
        cmdline = ctx.get("fg_cmdline")
        cloud_provider = _cloud_provider_from_path(dp or p)

        file_name = _get_name(target_for_content)
        object_block = self._build_object(
            src_path=p,
            dst_path=dp,
            size=size,
            src_drive=src_drive,
            src_volume_type=src_volume_type,
            dest_drive=dest_drive,
            dest_volume_type=dest_volume_type,
            old_ext=(before_ext if report_event_type == "Rename" else old_ext),
            new_ext=(target_ext if report_event_type == "Rename" else new_ext),
            signature=signature,
            sensitivity=sensitivity,
            file_name=file_name,
            file_ext=target_ext,
            file_hash=hash_sha256,
            cloud_provider=cloud_provider,
        )

        dest_like_external = bool(effective_volume_type in {"Removable", "Network"} or cloud_provider)
        rename_ext_changed = bool((before_ext or old_ext) and (target_ext or new_ext) and (before_ext or old_ext) != (target_ext or new_ext))
        recent_staging = self._recent_staging_count(ts)

        evt: Dict[str, Any] = {
            "type": f"file_{evt_kind}",
            "severity": "info",
            "source": "file",
            "ts": ts,
            "timestamp": _iso_utc(ts),
            "context": ctx,

            # canonical
            "actor": self._build_actor(ctx),
            "object": object_block,

            # legacy flat fields
            "path": p,
            "dst_path": dp,
            "ext": src_ext,
            "size": size,
            "mtime": mtime,
            "exists": exists,
            "drive": effective_drive,
            "volume_type": effective_volume_type,
            "old_ext": old_ext,
            "new_ext": new_ext,
            "signature": signature,
            "hash_sha256": hash_sha256,

            "operation": {
                "op_type": op_type,
                "tool": proc_name,
            },
            "metrics": {
                "entropy": entropy,
                "row_count": None,
                "file_count": file_count_window,
            },
            "flags": {
                "password_protected": pw_protected,
            },
            "content": {
                "sample": sample,
                "sample_len": sample_len,
            },

            # report fields
            "Event_Type": report_event_type,
            "Operation_Type": report_op_type,
            "Timestamp": _iso_utc(ts),

            "File_Name": file_name,
            "File_Extension": target_ext,
            "File_Size": size,
            "File_Path": target_for_content,
            "File_Hash": hash_sha256,
            "File_Signature": signature,
            "File_Sensitivity": sensitivity,

            "Source_Path": p,
            "Dest_Path": dp,
            "Dest_Volume_Type": dest_volume_type,
            "Dest_Drive": dest_drive,
            "Source_Volume_Type": src_volume_type,
            "Source_Drive": src_drive,
            "Cloud_Provider": cloud_provider,

            "Process_Name": proc_name,
            "Process_ID": proc_id,
            "Command_Line": cmdline,

            "File_Count": file_count_window,
            "Entropy_Value": entropy,
            "Password_Flag": pw_protected,
            "Original_File_Size": before_size,
            "New_File_Size": size,
            "File_Hash_Before": before_hash,
            "File_Hash_After": hash_sha256,
            "Old_Extension": before_ext if report_event_type == "Rename" else old_ext,
            "New_Extension": target_ext if report_event_type == "Rename" else new_ext,

            "debug": {
                "evidence": {
                    "dest_like_external": dest_like_external,
                    "rename_ext_changed": rename_ext_changed,
                    "cloud_provider": cloud_provider,
                    "recent_staging": recent_staging,
                    "sample_available": bool(sample),
                    "signature_available": bool(signature),
                    "hash_available": bool(hash_sha256),
                }
            },
        }

        # mild severity tuning
        if sensitivity == "Highly Sensitive":
            evt["severity"] = "high"
        elif sensitivity == "Sensitive" or dest_like_external or pw_protected:
            evt["severity"] = "warn"
        else:
            evt["severity"] = "info"

        return evt

    # -----------------------------
    # Watchdog mode
    # -----------------------------
    def _run_watchdog(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        class _Handler(FileSystemEventHandler):
            def __init__(self, outer: "FileSystemSensor"):
                self.outer = outer

            def on_created(self, event):
                if getattr(event, "is_directory", False):
                    return
                ctx = self.outer._ctx_snapshot(ctx_provider)
                try:
                    self.outer._emit(self.outer._build_event("created", event.src_path, None, ctx))
                except RuntimeError:
                    return

            def on_modified(self, event):
                if getattr(event, "is_directory", False):
                    return
                ctx = self.outer._ctx_snapshot(ctx_provider)
                try:
                    self.outer._emit(self.outer._build_event("modified", event.src_path, None, ctx))
                except RuntimeError:
                    return

            def on_deleted(self, event):
                if getattr(event, "is_directory", False):
                    return
                ctx = self.outer._ctx_snapshot(ctx_provider)
                try:
                    self.outer._emit(self.outer._build_event("deleted", event.src_path, None, ctx))
                except RuntimeError:
                    return

            def on_moved(self, event):
                if getattr(event, "is_directory", False):
                    return
                ctx = self.outer._ctx_snapshot(ctx_provider)
                try:
                    self.outer._emit(self.outer._build_event("moved", event.src_path, event.dest_path, ctx))
                except RuntimeError:
                    return

        try:
            handler = _Handler(self)
            observer = Observer()
            self._observer = observer

            for p in self.watch_paths:
                try:
                    observer.schedule(handler, p, recursive=True)
                except Exception:
                    pass

            observer.start()

            while not stop_event.is_set():
                time.sleep(0.25)

            try:
                observer.stop()
                observer.join(timeout=2.0)
            except Exception:
                pass

        except Exception:
            self._run_polling(stop_event, ctx_provider)

    # -----------------------------
    # Polling fallback
    # -----------------------------
    def _scan(self) -> Dict[str, _StatLite]:
        snap: Dict[str, _StatLite] = {}
        for root in self.watch_paths:
            try:
                for dirpath, _, filenames in os.walk(root):
                    for fn in filenames:
                        fp = os.path.join(dirpath, fn)
                        fp_norm = _norm_path(fp)
                        if self._should_ignore(fp_norm):
                            continue
                        try:
                            st = os.stat(fp_norm)
                            snap[fp_norm] = _StatLite(size=int(st.st_size), mtime=float(st.st_mtime), exists=True)
                        except Exception:
                            continue
            except Exception:
                continue
        return snap

    def _run_polling(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        self._snap = self._scan()

        while not stop_event.is_set():
            time.sleep(self.poll_interval_sec)

            cur = self._scan()
            prev = self._snap
            self._snap = cur

            prev_keys = set(prev.keys())
            cur_keys = set(cur.keys())

            created = cur_keys - prev_keys
            deleted = prev_keys - cur_keys
            common = cur_keys & prev_keys

            ctx = self._ctx_snapshot(ctx_provider)

            for p in created:
                try:
                    self._emit(self._build_event("created", p, None, ctx))
                except RuntimeError:
                    continue

            for p in deleted:
                try:
                    self._emit(self._build_event("deleted", p, None, ctx))
                except RuntimeError:
                    continue

            for p in common:
                if (cur[p].mtime != prev[p].mtime) or (cur[p].size != prev[p].size):
                    try:
                        self._emit(self._build_event("modified", p, None, ctx))
                    except RuntimeError:
                        continue

    def run_loop(self, stop_event, ctx_provider: Optional[Any] = None) -> None:
        if not self.watch_paths:
            while not stop_event.is_set():
                time.sleep(1.0)
            return

        if _HAS_WATCHDOG:
            self._run_watchdog(stop_event, ctx_provider)
        else:
            self._run_polling(stop_event, ctx_provider)