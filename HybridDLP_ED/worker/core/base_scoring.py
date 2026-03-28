"""
Base Score — CVSS-inspired DLP (Noteupdate §3.1).
BaseScore = 0.35*ContentSensitivity + 0.25*DataCriticality + 0.25*BehaviorAnomaly + 0.15*Confidence
"""
from __future__ import annotations

from typing import Any, Dict, Tuple

from loguru import logger

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def _clamp(v: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, float(v)))


def _event_data(ctx: Dict[str, Any]) -> Dict[str, Any]:
    ed = ctx.get("_event_data")
    return ed if isinstance(ed, dict) else {}


def compute_content_sensitivity(
    fast_scan_result: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
    event_context: Dict[str, Any],
) -> float:
    """0–100 từ YARA, IOC, deep is_sensitive."""
    score = 0.0
    event_data = _event_data(event_context)

    for match in fast_scan_result.get("yara_matches") or []:
        rule = str(match.get("rule", "")).lower()
        if any(k in rule for k in ("id", "cmnd", "cccd")):
            score += 50
        elif "credit" in rule or "card" in rule:
            score += 40
        elif "api" in rule or "key" in rule:
            score += 35
        elif "email" in rule:
            score += 20
        elif "phone" in rule:
            score += 15
        else:
            score += 28

    for ioc in event_data.get("ioc_hits") or []:
        if not isinstance(ioc, dict):
            continue
        tag = str(ioc.get("tag", "")).lower()
        if "id" in tag or "cmnd" in tag:
            score += 45
        elif "credit" in tag or "card" in tag:
            score += 38
        elif "email" in tag:
            score += 22
        elif "phone" in tag:
            score += 12
        else:
            score += 20

    if deep_analysis_result.get("is_sensitive"):
        score += 25
    if fast_scan_result.get("is_encrypted_zip"):
        score += 15
    if fast_scan_result.get("is_suspicious"):
        score += 10

    return _clamp(score)


def compute_data_criticality(event_context: Dict[str, Any]) -> float:
    """0–100 — giá trị kinh doanh ước lượng từ path / tags."""
    loc = str(event_context.get("location", "")).lower()
    obj = _event_data(event_context).get("object")
    path = loc
    if isinstance(obj, dict):
        path = str(obj.get("path") or path).lower()

    critical_kw = (
        "payroll", "salary", "luong", "hr", "nhansu", "contract", "hopdong",
        "customer", "khachhang", "source", "src", "financial", "taichinh",
        "medical", "benhan", "secret", "confidential", "mat",
    )
    s = 15.0
    for kw in critical_kw:
        if kw in path:
            s += 18.0
    tags = _event_data(event_context).get("tags") or []
    if isinstance(tags, (list, tuple)):
        for t in tags:
            if str(t).lower().startswith("corr_"):
                s += 8.0
    return _clamp(s)


def compute_behavior_anomaly(
    event_context: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
) -> float:
    """0–100 — behavioral + UEBA."""
    base = 10.0
    boost = float(event_context.get("behavioral_risk_boost") or 0)
    base = _clamp(base + boost * 0.5)

    ml = float(event_context.get("ml_anomaly_score") or 0.0)
    if ml <= 0 and deep_analysis_result.get("ml_anomaly_score") is not None:
        ml = float(deep_analysis_result.get("ml_anomaly_score") or 0.0)

    if event_context.get("ml_is_anomaly") or deep_analysis_result.get("ml_is_anomaly"):
        ml = max(ml, 55.0)

    return _clamp(max(base, ml * 0.85))


def compute_confidence(
    fast_scan_result: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
) -> float:
    """0–100 — độ tin cậy detection (YARA mạnh → cao)."""
    yara_n = len(fast_scan_result.get("yara_matches") or [])
    if yara_n == 0 and not fast_scan_result.get("is_suspicious"):
        return 35.0
    if yara_n >= 3:
        return 92.0
    if yara_n >= 1:
        return 72.0
    if deep_analysis_result.get("is_sensitive"):
        return 65.0
    return 55.0


def compute_base_score(
    fast_scan_result: Dict[str, Any],
    deep_analysis_result: Dict[str, Any],
    event_context: Dict[str, Any],
) -> Tuple[float, Dict[str, float]]:
    w = getattr(WorkerConfig, "CVSS_DLP_BASE_WEIGHTS", None) or {
        "content_sensitivity": 0.35,
        "data_criticality": 0.25,
        "behavior_anomaly": 0.25,
        "confidence": 0.15,
    }

    cs = compute_content_sensitivity(fast_scan_result, deep_analysis_result, event_context)
    dc = compute_data_criticality(event_context)
    ba = compute_behavior_anomaly(event_context, deep_analysis_result)
    cf = compute_confidence(fast_scan_result, deep_analysis_result)

    base = (
        w["content_sensitivity"] * cs
        + w["data_criticality"] * dc
        + w["behavior_anomaly"] * ba
        + w["confidence"] * cf
    )
    base = _clamp(base)

    components = {
        "content_sensitivity": round(cs, 2),
        "data_criticality": round(dc, 2),
        "behavior_anomaly": round(ba, 2),
        "confidence": round(cf, 2),
        "base_score": round(base, 2),
    }
    logger.debug(f"CVSS-DLP Base: {components}")
    return base, components
