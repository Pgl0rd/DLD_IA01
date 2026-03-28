"""
Orchestrator — CVSS-Inspired DLP Risk (Noteupdate.txt §6).
Luồng: base → exfiltration maturity → environmental → attack chain → fusion → policy.
"""
from __future__ import annotations

from typing import Any, Dict

from loguru import logger

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig

from core.base_scoring import compute_base_score
from core.exfiltration_maturity import compute_exfiltration_maturity
from core.environmental_scoring import compute_environmental_score
from core.attack_chain import compute_attack_chain_bonus
from core.final_risk_fusion import fuse_final_risk, apply_force_max_risk
from core.policy_decision import decide_recommended_action, build_reason_codes


class CVSSDLPScoringEngine:
    """Risk engine theo mô hình Base + EM + Environmental + AttackChain (Noteupdate)."""

    def calculate_score(
        self,
        fast_scan_result: Dict[str, Any],
        deep_analysis_result: Dict[str, Any],
        event_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        _, base_components = compute_base_score(
            fast_scan_result, deep_analysis_result, event_context
        )
        base_val = float(base_components["base_score"])

        em = compute_exfiltration_maturity(fast_scan_result, event_context)
        env_val, env_parts = compute_environmental_score(event_context)
        chain_bonus, chain_reasons = compute_attack_chain_bonus(
            event_context, fast_scan_result
        )

        use_f1 = getattr(WorkerConfig, "CVSS_DLP_USE_FORMULA1_EM_FACTOR", False)
        total = fuse_final_risk(
            base_val,
            float(em["maturity_numeric"]),
            env_val,
            chain_bonus,
            float(em["em_factor"]),
            use_em_factor_on_base=bool(use_f1),
        )
        total, forced = apply_force_max_risk(total, event_context)
        if forced:
            logger.warning("CVSS-DLP: force_max_risk applied")

        action, rec_label = decide_recommended_action(
            total,
            str(em["exfiltration_maturity"]),
            float(base_components["content_sensitivity"]),
        )

        reason_codes = build_reason_codes(
            base_components,
            em,
            env_parts,
            chain_reasons,
            extra=[event_context.get("force_max_risk_reason")]
            if event_context.get("force_max_risk_reason")
            else None,
        )
        reason_codes = [r for r in reason_codes if r]

        from core.risk_scoring import classify_risk_level

        cvss_payload = {
            "event_id": event_context.get("event_id"),
            "base_score": round(base_val, 2),
            "content_sensitivity": base_components["content_sensitivity"],
            "data_criticality": base_components["data_criticality"],
            "behavior_anomaly": base_components["behavior_anomaly"],
            "confidence": base_components["confidence"],
            "exfiltration_maturity": em["exfiltration_maturity"],
            "maturity_band": em["maturity_band"],
            "maturity_score": em["maturity_score"],
            "maturity_numeric": em["maturity_numeric"],
            "em_factor": em["em_factor"],
            "environmental_score": env_parts["environmental_score"],
            "environmental_breakdown": {k: v for k, v in env_parts.items() if k != "environmental_score"},
            "attack_chain_bonus": round(chain_bonus, 2),
            "attack_chain_reasons": chain_reasons,
            "final_risk": total,
            "recommended_action": rec_label,
            "reason_codes": reason_codes,
        }

        details: Dict[str, Any] = {
            "cvss_dlp": cvss_payload,
            "exfiltration_maturity_detail": em,
        }

        return {
            "total_score": total,
            "content_score": base_components["content_sensitivity"],
            "behavior_score": em["maturity_score"],
            "context_score": env_parts["environmental_score"],
            "action": action,
            "risk_level": classify_risk_level(total),
            "details": details,
            "method": "cvss_dlp",
        }
