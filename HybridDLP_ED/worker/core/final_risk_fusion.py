"""
Final Risk Fusion — Noteupdate §4 (công thức 2 khuyến nghị).
FinalRisk = min(100, 0.60*BaseScore + 0.25*MaturityNumeric + 0.15*EnvironmentalScore + AttackChainBonus)
"""
from __future__ import annotations

from typing import Any, Dict

from loguru import logger

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from config import WorkerConfig


def fuse_final_risk(
    base_score: float,
    maturity_numeric: float,
    environmental_score: float,
    attack_chain_bonus: float,
    em_factor: float,
    use_em_factor_on_base: bool = False,
) -> float:
    """
    use_em_factor_on_base: nếu True, áp dụng công thức 1 min(100, Base*EM_Factor + Env*0.3 + Chain).
    Mặc định False — dùng công thức 2 trong Noteupdate.
    """
    fw = getattr(WorkerConfig, "CVSS_DLP_FUSION_WEIGHTS", None) or {
        "base": 0.60,
        "maturity": 0.25,
        "environmental": 0.15,
    }
    b = max(0.0, min(100.0, float(base_score)))
    m = max(0.0, min(100.0, float(maturity_numeric)))
    e = max(0.0, min(100.0, float(environmental_score)))
    chain = max(0.0, min(20.0, float(attack_chain_bonus)))

    if use_em_factor_on_base:
        adj_base = b * float(em_factor)
        total = adj_base + 0.3 * e + chain
    else:
        total = (
            fw["base"] * b
            + fw["maturity"] * m
            + fw["environmental"] * e
            + chain
        )

    total = max(0.0, min(100.0, total))
    logger.debug(
        f"CVSS-DLP Fusion: base={b:.1f} mat={m:.1f} env={e:.1f} chain={chain:.1f} => {total:.1f}"
    )
    return round(total, 2)


def apply_force_max_risk(
    total: float,
    event_context: Dict[str, Any],
    floor: float = 88.0,
) -> tuple[float, bool]:
    if event_context.get("force_max_risk"):
        return max(total, floor), True
    return total, False
