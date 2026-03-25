"""
Network outbound candidate sensor (Layer 1, DLP).

LIMITATIONS (read before interpreting events):
- Uses psutil.net_io_counters().bytes_sent which is HOST-WIDE totals only.
  host_bytes_sent_delta is NOT per-process, per-connection, or per-destination.
  It only means "in this polling interval the machine sent roughly this many bytes total".
- Does NOT observe HTTP method, content-type, request body, or attached filenames.
- Does NOT prove file upload; use L2/L3 correlation for upload/exfil rules.
- Reverse DNS (PTR) for dest_domain is weak evidence (often CDN/infrastructure hostnames).

This module emits only network_outbound_candidate events with honest semantics.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass
from pathlib import Path
from time import monotonic
from typing import Any, Dict, Optional, Tuple

try:
    import psutil
except ImportError:  # pragma: no cover - dependency/environment specific
    psutil = None

from ..classifiers import classify_domain, classify_upload_tool
from ..config import NetworkSensorConfig
from .base import SensorBase
from .stubs import StubSensor

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class _ConnectionDedupKey:
    pid: Optional[int]
    remote_ip: str
    remote_port: int


@dataclass
class _EmitState:
    last_emit_ts: float
    last_signature: str
    last_host_delta_seen: float


class NetworkSensor(SensorBase):
    """
    Production-oriented outbound candidate sensor.

    Emits `network_outbound_candidate` with operation.op_type `outbound_candidate`.
    metrics.bytes_out is always null (no per-event byte accounting at this layer).
    """

    source = "network_sensor"

    def __init__(
        self,
        context_provider,
        settings: Optional[NetworkSensorConfig] = None,
    ) -> None:
        super().__init__(context_provider)
        self._cfg = settings or NetworkSensorConfig()
        self._dedup: Dict[_ConnectionDedupKey, _EmitState] = {}

    # --- Connection / process helpers ---

    def _connection_key(self, conn) -> _ConnectionDedupKey:
        raddr = conn.raddr
        return _ConnectionDedupKey(
            pid=int(conn.pid) if conn.pid is not None else None,
            remote_ip=str(raddr.ip) if raddr else "",
            remote_port=int(raddr.port) if raddr else 0,
        )

    def _resolve_process_name(self, pid: Optional[int]) -> str:
        if not pid:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

    def _should_ignore_process(self, process_name: str) -> bool:
        name = process_name.lower()
        return name in self._cfg.denied_process_names

    def _is_external_ip(self, ip: Optional[str]) -> bool:
        if not ip:
            return False
        try:
            parsed = ipaddress.ip_address(ip)
            return not (
                parsed.is_loopback
                or parsed.is_private
                or parsed.is_link_local
                or parsed.is_multicast
                or parsed.is_reserved
            )
        except ValueError:
            return False

    def _should_ignore_destination(self, dest_ip: Optional[str], dest_domain: Optional[str]) -> bool:
        domain = (dest_domain or "").lower()
        ip = (dest_ip or "").lower()
        if domain in {"localhost", "kubernetes.docker.internal"}:
            return True
        if ip in {"127.0.0.1", "::1"}:
            return True
        return False

    def _is_infrastructure_ptr(self, domain: Optional[str]) -> bool:
        if not domain:
            return True
        d = domain.lower()
        return any(tok in d for tok in self._cfg.infrastructure_domain_tokens)

    async def _resolve_ptr_domain(self, ip: Optional[str]) -> Optional[str]:
        if not ip:
            return None
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(lambda: socket.gethostbyaddr(ip)[0]),
                timeout=0.5,
            )
        except (asyncio.TimeoutError, socket.herror, OSError):
            return None

    def _domain_confidence(self, ptr_domain: Optional[str]) -> str:
        """
        PTR/reverse-DNS is often CDN/AWS/generic infra — treat as low unless
        we later add HTTP SNI/TLS or application-level domain (not available here).
        """
        if not ptr_domain:
            return "low"
        if self._is_infrastructure_ptr(ptr_domain):
            return "low"
        return "medium"

    # --- File guess (heuristic only, never proof of upload) ---

    def _path_is_denied(self, lowered: str) -> bool:
        return any(tok in lowered for tok in self._cfg.denied_path_tokens)

    def _path_in_user_roots(self, lowered: str) -> bool:
        return any(root in lowered for root in self._cfg.allowed_user_path_roots)

    def _guess_recent_user_file(self, pid: Optional[int]) -> Tuple[Optional[str], str]:
        """
        Returns (path_or_none, confidence in {none, low, medium}).
        Aggressively returns (None, none) rather than cache/log garbage.
        """
        if not pid:
            return None, "none"
        try:
            proc = psutil.Process(pid)
            scored: list[tuple[int, float, str]] = []
            for opened in proc.open_files():
                path = opened.path
                if not path:
                    continue
                p = Path(path)
                lowered = str(p).lower()
                if self._path_is_denied(lowered):
                    continue
                if p.suffix.lower() in self._cfg.denied_file_extensions:
                    continue
                if not (p.exists() and p.is_file()):
                    continue
                try:
                    mtime = p.stat().st_mtime
                except OSError:
                    continue
                in_user = 1 if self._path_in_user_roots(lowered) else 0
                scored.append((in_user, mtime, str(p)))
            if not scored:
                return None, "none"
            scored.sort(reverse=True)
            best_in_user, _, best_path = scored[0]
            if best_in_user == 1:
                return best_path, "medium"
            return None, "none"
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            return None, "none"

    # --- Scoring & relevance (internal; does not imply upload) ---

    def _compute_relevance_score(
        self,
        tool: Dict[str, Any],
        domain_cls: Dict[str, Any],
        ptr_domain: Optional[str],
        foreground_match: bool,
        file_guess_confidence: str,
        domain_confidence: str,
    ) -> int:
        score = 0
        if tool.get("is_browser"):
            score += 2
        if tool.get("is_desktop_upload_app"):
            score += 2
        if tool.get("is_cli_upload_tool"):
            score += 1
        if domain_cls.get("is_sensitive_domain"):
            score += 2
        if foreground_match:
            score += 2
        if file_guess_confidence == "medium":
            score += 2
        elif file_guess_confidence == "low":
            score += 1
        if domain_confidence == "medium":
            score += 1
        if self._is_infrastructure_ptr(ptr_domain):
            score -= 1
        return max(0, score)

    def _evidence_strength(self, score: int, file_guess_confidence: str) -> str:
        if score >= 6 and file_guess_confidence in {"medium", "low"}:
            return "moderate"
        return "weak"

    def _should_emit_candidate(
        self,
        key: _ConnectionDedupKey,
        now_ts: float,
        signature: str,
        host_delta: float,
    ) -> bool:
        if host_delta < self._cfg.host_bytes_delta_threshold:
            return False

        prev = self._dedup.get(key)
        if prev is None:
            return True

        if signature != prev.last_signature:
            return True

        if now_ts - prev.last_emit_ts >= self._cfg.quiet_period_resend_seconds:
            if abs(host_delta - prev.last_host_delta_seen) > self._cfg.host_bytes_delta_threshold * 0.25:
                return True

        if now_ts - prev.last_emit_ts < self._cfg.min_emit_interval_seconds:
            return False

        return False

    def _record_emit(self, key: _ConnectionDedupKey, now_ts: float, signature: str, host_delta: float) -> None:
        self._dedup[key] = _EmitState(
            last_emit_ts=now_ts,
            last_signature=signature,
            last_host_delta_seen=host_delta,
        )
        if len(self._dedup) > self._cfg.max_dedup_state_entries:
            oldest = sorted(self._dedup.items(), key=lambda kv: kv[1].last_emit_ts)[: len(self._dedup) // 4]
            for k, _ in oldest:
                self._dedup.pop(k, None)

    def _build_candidate_payload(
        self,
        *,
        process_name: str,
        dest_ip: Optional[str],
        ptr_domain: Optional[str],
        host_total: float,
        host_delta: float,
        tool: Dict[str, Any],
        domain_cls: Dict[str, Any],
        domain_confidence: str,
        file_guess: Optional[str],
        file_guess_confidence: str,
        foreground_match: bool,
        relevance_score: int,
        evidence_strength: str,
    ) -> Dict[str, Any]:
        tags = [
            "outbound_candidate",
            "external_connection",
            "host_level_bytes_only",
        ]
        if tool.get("is_browser"):
            tags.append("browser_process")
        if tool.get("is_desktop_upload_app"):
            tags.append("desktop_upload_app")
        if tool.get("is_cli_upload_tool"):
            tags.append("cli_upload_tool")
        if domain_cls.get("is_sensitive_domain"):
            tags.append("sensitive_domain")
        if foreground_match:
            tags.append("foreground_match")
        if file_guess:
            tags.append("recent_open_file_guess")

        payload = self._build_base_event(
            event_type="network_outbound_candidate",
            severity="medium",
            op_type="outbound_candidate",
            process=process_name,
            cmdline=None,
            bytes_out=None,
            tags=sorted(set(tags)),
        )

        payload["network"] = {
            "dest_domain": ptr_domain,
            "dest_ip": dest_ip,
            "dest_url": None,
            "method": None,
            "content_type": None,
            "domain_confidence": domain_confidence,
            "file_guess_confidence": file_guess_confidence,
            "host_bytes_sent_total": host_total,
            "host_bytes_sent_delta": host_delta,
            "recent_open_file_guess": file_guess,
            "recent_open_dir_guess": str(Path(file_guess).parent) if file_guess else None,
        }

        payload["debug"] = {
            "evidence": {
                "sensor_model": "host_wide_counters_only",
                "host_bytes_sent_total": host_total,
                "host_bytes_sent_delta": host_delta,
                "evidence_strength": evidence_strength,
                "relevance_score": relevance_score,
                "process_classification": dict(tool),
                "domain_classification": dict(domain_cls),
                "ptr_domain_only": True,
                "domain_confidence": domain_confidence,
                "file_guess_confidence": file_guess_confidence,
                "foreground_match": foreground_match,
                "recent_open_file_guess": file_guess,
            }
        }
        return payload

    async def run(self, emit) -> None:
        if psutil is None:
            stub = StubSensor(self.context_provider)
            stub.source = self.source
            stub.reason = "network sensor requires psutil"
            logger.warning("Network sensor running in stub mode: %s", stub.reason)
            await stub.run(emit)
            return

        previous_global_sent = float(psutil.net_io_counters().bytes_sent)
        logger.info("Network outbound candidate sensor started (host-level counters; not upload detection)")

        while True:
            await asyncio.sleep(self._cfg.poll_interval_seconds)
            counters = psutil.net_io_counters()
            current_global_sent = float(counters.bytes_sent)
            host_delta = max(0.0, current_global_sent - previous_global_sent)
            previous_global_sent = current_global_sent

            try:
                connections = psutil.net_connections(kind="inet")
            except psutil.AccessDenied:
                logger.warning("Network sensor lacks permission for net_connections")
                continue

            if host_delta < self._cfg.host_bytes_delta_threshold:
                continue

            ctx = self.context_provider.get_context()
            fg_proc = (ctx.fg_process or "").lower()

            for conn in connections:
                if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                    continue
                dest_ip = conn.raddr.ip if conn.raddr else None
                if not self._is_external_ip(str(dest_ip) if dest_ip else None):
                    continue

                process_name = self._resolve_process_name(int(conn.pid) if conn.pid else None)
                if self._should_ignore_process(process_name):
                    continue

                ptr_domain = await self._resolve_ptr_domain(str(dest_ip) if dest_ip else None)
                if self._should_ignore_destination(str(dest_ip) if dest_ip else None, ptr_domain):
                    continue

                process_l = process_name.lower()
                tool = classify_upload_tool(process_l)
                domain_cls = classify_domain(ptr_domain)
                domain_conf = self._domain_confidence(ptr_domain)

                file_guess, file_conf = self._guess_recent_user_file(int(conn.pid) if conn.pid else None)
                if file_conf == "none":
                    file_guess = None

                foreground_match = bool(fg_proc and fg_proc == process_l)

                user_relevant = bool(
                    tool["is_browser"]
                    or tool["is_desktop_upload_app"]
                    or tool["is_cli_upload_tool"]
                    or domain_cls["is_sensitive_domain"]
                    or foreground_match
                )
                if not user_relevant:
                    continue

                relevance = self._compute_relevance_score(
                    tool,
                    domain_cls,
                    ptr_domain,
                    foreground_match,
                    file_conf,
                    domain_conf,
                )
                if relevance < self._cfg.relevance_score_threshold:
                    continue

                strength = self._evidence_strength(relevance, file_conf)
                sig = "|".join(
                    [
                        str(domain_cls.get("category")),
                        str(foreground_match),
                        file_conf,
                        str(file_guess or ""),
                    ]
                )

                key = self._connection_key(conn)
                now_ts = monotonic()
                if not self._should_emit_candidate(key, now_ts, sig, host_delta):
                    continue

                payload = self._build_candidate_payload(
                    process_name=process_name,
                    dest_ip=str(dest_ip) if dest_ip else None,
                    ptr_domain=ptr_domain,
                    host_total=current_global_sent,
                    host_delta=host_delta,
                    tool=tool,
                    domain_cls=domain_cls,
                    domain_confidence=domain_conf,
                    file_guess=file_guess,
                    file_guess_confidence=file_conf,
                    foreground_match=foreground_match,
                    relevance_score=relevance,
                    evidence_strength=strength,
                )
                await emit(payload)
                self._record_emit(key, now_ts, sig, host_delta)
