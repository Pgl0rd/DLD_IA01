from __future__ import annotations

from collections import deque
from copy import deepcopy
from time import monotonic
from typing import Awaitable, Callable, Deque, Dict, List, Optional

from .classifiers import SENSITIVE_EXTENSIONS, classify_domain, classify_upload_tool
from .recent_file_tracker import RecentFileTracker

PublishFn = Callable[[Dict], Awaitable[None]]


class UploadCorrelatorPublisher:
    """Emit correlated upload-suspected events from sensor stream."""

    def __init__(self, downstream: PublishFn, window_seconds: float = 15.0) -> None:
        self.downstream = downstream
        self.window_seconds = window_seconds
        self._recent_file_events: Deque[tuple[float, Dict]] = deque()
        self._tracker = RecentFileTracker(ttl_seconds=window_seconds)
        # Browser upload resolver runs in the same publisher pipeline
        # (instantiated lazily after BrowserUploadContextResolver is defined below)
        self._browser_resolver: Optional["BrowserUploadContextResolver"] = None

    def _cleanup(self, now_ts: float) -> None:
        while self._recent_file_events and now_ts - self._recent_file_events[0][0] > self.window_seconds:
            self._recent_file_events.popleft()

    def _remember_file_event(self, event: Dict, now_ts: float) -> None:
        event_type = event.get("type")
        if event_type not in {"file_create", "file_copy", "file_move", "file_rename"}:
            return
        copied = deepcopy(event)
        self._recent_file_events.append((now_ts, copied))
        self._tracker.remember(copied)

    def _match_recent_file(self, network_event: Dict) -> Optional[Dict]:
        actor_process = ((network_event.get("actor") or {}).get("process") or "").lower()
        fg_app = ((network_event.get("context") or {}).get("fg_app") or "").lower()

        # Prefer file events where foreground app matches network process/app.
        for _, file_event in reversed(self._recent_file_events):
            file_ctx = file_event.get("context") or {}
            file_fg_app = (file_ctx.get("fg_app") or "").lower()
            if file_fg_app and (file_fg_app == fg_app or file_fg_app in actor_process):
                return file_event
        # Fallback: most recent file event in window.
        if self._recent_file_events:
            return self._recent_file_events[-1][1]
        return None

    def _build_correlated_event(self, network_event: Dict, file_event: Dict) -> Dict:
        correlated = deepcopy(network_event)
        correlated["type"] = "corr_suspected_upload"
        correlated["source"] = "correlator"
        correlated["severity"] = "high"
        correlated["operation"]["op_type"] = "upload"
        correlated["tags"] = sorted(set((correlated.get("tags") or []) + ["correlated", "upload_suspected"]))
        correlated["ioc_hits"] = correlated.get("ioc_hits") or []

        file_object = file_event.get("object") or {}
        corr_object = correlated.get("object") or {}
        corr_object["path"] = file_object.get("path")
        corr_object["dst_path"] = file_object.get("dst_path")
        corr_object["drive"] = file_object.get("drive")
        corr_object["volume_type"] = file_object.get("volume_type") or "unknown"
        corr_object["sensitivity"] = (file_event.get("file_evidence") or {}).get("sensitivity") or corr_object.get("sensitivity") or "unknown"
        correlated["object"] = corr_object
        correlated["metrics"]["file_count"] = 1
        return correlated

    def _is_upload_operation(self, event: Dict) -> bool:
        event_type = (event.get("type") or "").lower()
        op_type = ((event.get("operation") or {}).get("op_type") or "").lower()
        network = event.get("network") or {}
        method = (network.get("method") or "").lower()
        content_type = (network.get("content_type") or "").lower()
        bytes_out = float(event.get("metrics", {}).get("bytes_out") or 0)
        host_delta = float(network.get("host_bytes_sent_delta") or 0)
        return bool(
            event_type
            in {
                "network_flow",
                "network_flow_summary",
                "http_request",
                "http_upload",
                "file_upload",
                "browser_upload",
                "network_upload",
                "cloud_exfiltration",
                "data_exfiltration",
                "corr_suspected_upload",
                "network_outbound_candidate",
            }
            or any(token in op_type for token in {"upload", "post", "put", "send", "exfil"})
            or method in {"post", "put", "patch"}
            or "multipart/form-data" in content_type
            or bytes_out >= 100 * 1024
            or host_delta >= 100 * 1024
        )

    def _is_external_destination(self, event: Dict, tool: Dict, domain_cls: Dict) -> bool:
        network = event.get("network") or {}
        ctx = event.get("context") or {}
        text = " ".join(
            [
                str(network.get("dest_domain") or ""),
                str(network.get("dest_url") or ""),
                str(ctx.get("window_title") or ""),
            ]
        ).lower()
        keyword_hit = any(
            k in text
            for k in {"chatgpt.com", "gmail.com", "drive.google.com", "dropbox.com", "slack.com", "pastebin.com"}
        )
        has_destination = bool(network.get("dest_domain") or network.get("dest_url") or network.get("dest_ip"))
        return bool(
            tool["is_browser"]
            or tool["is_desktop_upload_app"]
            or tool["is_cli_upload_tool"]
            or has_destination
            or domain_cls["is_sensitive_domain"]
            or keyword_hit
        )

    def _is_sensitive_content(self, event: Dict, file_event: Dict) -> bool:
        obj = event.get("object") or {}
        file_evidence = file_event.get("file_evidence") or {}
        sensitivity = str(obj.get("sensitivity") or "").lower()
        file_sensitivity = str(file_evidence.get("sensitivity") or "").lower()
        ext = str(file_evidence.get("extension") or "").lower()
        debug = event.get("debug") or {}
        evidence = debug.get("evidence") or {}
        return bool(
            sensitivity in {"sensitive", "highly_sensitive", "confidential"}
            or file_sensitivity in {"sensitive", "highly_sensitive", "confidential"}
            or bool(file_evidence.get("is_sensitive_extension"))
            or ext in SENSITIVE_EXTENSIONS
            or bool(event.get("ioc_hits"))
            or bool(evidence.get("recent_staging"))
            or (event.get("type") in {"corr_suspected_upload", "cloud_exfiltration", "http_upload", "data_exfiltration"})
        )

    def _attach_rule_output(self, correlated_event: Dict, matched_file_event: Dict) -> None:
        network = correlated_event.get("network") or {}
        actor = correlated_event.get("actor") or {}
        obj = correlated_event.get("object") or {}
        file_evidence = matched_file_event.get("file_evidence") or {}
        correlated_event["rule"] = {
            "rule_name": "Network_Upload",
            "severity": "high",
            "dest_domain": network.get("dest_domain"),
            "dest_app": actor.get("process"),
            "bytes_out": correlated_event.get("metrics", {}).get("bytes_out") or network.get("host_bytes_sent_delta"),
            "file_path": obj.get("path"),
            "sensitivity": obj.get("sensitivity"),
        }
        correlated_event["debug"] = correlated_event.get("debug") or {}
        correlated_event["debug"]["evidence"] = correlated_event["debug"].get("evidence") or {}
        correlated_event["debug"]["evidence"]["recent_staging"] = bool(file_evidence.get("recent_staging"))

    async def __call__(self, event: Dict) -> None:
        now_ts = monotonic()
        self._cleanup(now_ts)
        self._remember_file_event(event, now_ts)

        # Keep browser resolver's file tracker in sync
        if self._browser_resolver is not None:
            self._browser_resolver.remember_file_event(event, now_ts)

        # Dispatch browser_upload events to the context resolver; skip network corr logic
        if event.get("type") == "browser_upload":
            if self._browser_resolver is None:
                # Lazy init (BrowserUploadContextResolver is defined later in this module)
                self._browser_resolver = BrowserUploadContextResolver(
                    self.downstream, window_seconds=self.window_seconds
                )
            await self._browser_resolver.process(event)
            return

        await self.downstream(event)

        if event.get("type") != "network_outbound_candidate":
            return
        actor = event.get("actor") or {}
        ctx = event.get("context") or {}
        network = event.get("network") or {}
        process_name = (actor.get("process") or "").lower()
        fg_app = (ctx.get("fg_app") or "").lower()
        tool = classify_upload_tool(process_name)
        domain_cls = classify_domain(network.get("dest_domain"))
        matched_file_event = self._tracker.best_match(process_name, fg_app) or self._match_recent_file(event)
        if not matched_file_event:
            return
        upload_op = self._is_upload_operation(event)
        external_dest = self._is_external_destination(event, tool, domain_cls)
        sensitive_content = self._is_sensitive_content(event, matched_file_event)
        if not (upload_op and external_dest and sensitive_content):
            return
        correlated_event = self._build_correlated_event(event, matched_file_event)
        correlated_event["tags"] = sorted(set((correlated_event.get("tags") or []) + [str(tool["tool_family"]), str(domain_cls["category"])]))
        self._attach_rule_output(correlated_event, matched_file_event)
        await self.downstream(correlated_event)


# ── Browser Upload Context Resolver ───────────────────────────────────────────

class BrowserUploadContextResolver:
    """
    Event Correlator / Upload Context Resolver for browser_upload events.

    Role (L1 Sensor Logic layer):
      1. Chuẩn hóa event đến từ BrowserUploadSensor
      2. Ghép đa nguồn: correlate với RecentFileTracker (file_sensor events)
         để map filename → local_path
      3. Resolve confidence score cho local file path match
      4. Emit corr_browser_upload nếu match đủ confidence

    Luồng:
        BrowserUploadSensor → emit(browser_upload)
        → UploadCorrelatorPublisher.__call__
        → BrowserUploadContextResolver.process()
        → emit(corr_browser_upload) với local_path resolved
        → L2 Secure IPC Queue
    """

    #: Minimum confidence to emit a corr_browser_upload enriched event
    CORR_EMIT_THRESHOLD = 0.60

    #: Time window in seconds to look back for matching file events
    FILE_MATCH_WINDOW_SEC = 30.0

    #: Size tolerance: local file size must be within this ratio of reported browser size
    SIZE_RATIO_TOLERANCE = 0.10   # 10%

    def __init__(self, downstream: PublishFn, window_seconds: float = FILE_MATCH_WINDOW_SEC) -> None:
        self.downstream = downstream
        self.window_seconds = window_seconds
        self._tracker = RecentFileTracker(ttl_seconds=window_seconds)
        self._recent_file_events: Deque[tuple[float, Dict]] = deque()

    def remember_file_event(self, event: Dict, now_ts: float) -> None:
        """Called by the main correlator to keep this resolver's tracker in sync."""
        event_type = event.get("type")
        if event_type not in {"file_create", "file_copy", "file_move", "file_rename"}:
            return
        copied = deepcopy(event)
        self._recent_file_events.append((now_ts, copied))
        self._tracker.remember(copied)
        # Prune old entries
        while self._recent_file_events and now_ts - self._recent_file_events[0][0] > self.window_seconds:
            self._recent_file_events.popleft()

    async def process(self, event: Dict) -> None:
        """
        Process a browser_upload event:
          - Try to match with a recent file event by filename/size
          - Compute resolved confidence
          - Emit corr_browser_upload if above threshold
          - Always forward original event downstream first
        """
        if event.get("type") != "browser_upload":
            return

        await self.downstream(event)  # always forward raw event to L2

        browser_upload = event.get("browser_upload") or {}
        filename = (browser_upload.get("filename") or "").lower()
        reported_size: Optional[int] = browser_upload.get("size")
        base_confidence: float = float(browser_upload.get("confidence_score") or 0.5)

        matched_file, path_confidence = self._find_matching_file(filename, reported_size)

        # Fallback: if no recent file event matches, try a quick scan in standard user folders
        fallback_path = None
        if path_confidence < self.CORR_EMIT_THRESHOLD:
            fallback_path = self._fallback_fast_search(filename, reported_size)
            if fallback_path:
                path_confidence = 0.8  # High confidence for exact name+size match in standard folders

        resolved_confidence = round(
            min(1.0, base_confidence * 0.6 + path_confidence * 0.4), 3
        )

        if resolved_confidence < self.CORR_EMIT_THRESHOLD:
            return

        corr = self._build_corr_event(event, matched_file, fallback_path, resolved_confidence)
        await self.downstream(corr)

    def _find_matching_file(
        self, filename: str, reported_size: Optional[int]
    ) -> tuple[Optional[Dict], float]:
        """
        Search recent file events for one whose filename matches the upload filename.
        Returns (best_file_event, path_confidence) where path_confidence ∈ [0, 1].
        """
        if not filename:
            return None, 0.0

        best_event: Optional[Dict] = None
        best_score: float = 0.0

        for _, file_event in reversed(self._recent_file_events):
            obj = file_event.get("object") or {}
            file_path: str = (obj.get("path") or obj.get("dst_path") or "").lower()
            if not file_path:
                continue

            import os as _os
            file_basename = _os.path.basename(file_path)
            if filename not in file_basename and file_basename not in filename:
                continue  # name mismatch

            score = 0.6  # filename match base

            # Bonus for exact name match
            if file_basename == filename:
                score += 0.2

            # Bonus for size proximity
            if reported_size and reported_size > 0:
                try:
                    actual_size = _os.path.getsize(file_path)
                    ratio = abs(actual_size - reported_size) / reported_size
                    if ratio <= self.SIZE_RATIO_TOLERANCE:
                        score += 0.2
                    elif ratio <= 0.25:
                        score += 0.1
                except OSError:
                    pass

            if score > best_score:
                best_score = score
                best_event = file_event

        return best_event, min(1.0, best_score)

    def _fallback_fast_search(self, filename: str, reported_size: Optional[int]) -> Optional[str]:
        """
        Quick scan in user's Downloads, Desktop, and Documents folders.
        Finds a file matching the exact filename (case-insensitive) and optionally size.
        Runs purely synchronously but bounded to a shallow depth to be fast.
        """
        if not filename:
            return None
        import os
        from pathlib import Path
        try:
            home = Path.home()
            search_dirs = [home / "Downloads", home / "Desktop", home / "Documents"]
            target_lower = filename.lower()
            
            for base_dir in search_dirs:
                if not base_dir.exists():
                    continue
                # Fast shallow scan: only look at files directly in these folders (depth 1)
                for entry in os.scandir(base_dir):
                    if entry.is_file():
                        if entry.name.lower() == target_lower:
                            if reported_size and reported_size > 0:
                                try:
                                    actual_size = entry.stat().st_size
                                    ratio = abs(actual_size - reported_size) / reported_size
                                    if ratio <= self.SIZE_RATIO_TOLERANCE:
                                        return entry.path
                                except OSError:
                                    pass
                            else:
                                return entry.path
        except Exception:
            pass
        return None

    def _build_corr_event(self, browser_event: Dict, file_event: Optional[Dict], fallback_path: Optional[str], confidence: float) -> Dict:
        """
        Build corr_browser_upload event:
        {
            type: 'corr_browser_upload',
            source: 'correlator',
            browser_upload: {
                ...original fields...
                local_path: '/path/to/file',   # resolved
                confidence_score: 0.87,         # updated
            },
            object.path: resolved local path,
            rule: { rule_name, severity, ... }
        }
        """
        corr = deepcopy(browser_event)
        corr["type"] = "corr_browser_upload"
        corr["source"] = "correlator"

        bu = corr.get("browser_upload") or {}
        bu["confidence_score"] = confidence

        local_path: Optional[str] = fallback_path
        sensitivity = "unknown"
        if file_event:
            obj = file_event.get("object") or {}
            local_path = obj.get("dst_path") or obj.get("path") or fallback_path
            sensitivity = obj.get("sensitivity") or (file_event.get("file_evidence") or {}).get("sensitivity") or "unknown"

        bu["local_path"] = local_path
        corr["browser_upload"] = bu

        # Update object block with resolved path
        corr_obj = corr.get("object") or {}
        corr_obj["path"] = local_path
        corr_obj["sensitivity"] = sensitivity
        corr["object"] = corr_obj

        severity = "high" if confidence >= 0.85 else "medium"
        corr["severity"] = severity
        corr["tags"] = sorted(set((corr.get("tags") or []) + ["correlated", "browser_upload_resolved"]))

        corr["rule"] = {
            "rule_name": "Browser_Upload",
            "severity": severity,
            "dest_domain": (corr.get("network") or {}).get("dest_domain"),
            "dest_app": (corr.get("actor") or {}).get("process"),
            "bytes_out": bu.get("size"),
            "file_path": local_path,
            "sensitivity": sensitivity,
            "confidence": confidence,
        }

        return corr
