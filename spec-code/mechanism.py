#!/usr/bin/env python3
"""
# spec-code/mechanism.py
mechanism.py — pick the enforcement mode, and be honest about whether it works.
"""
from __future__ import annotations

import os
import sys
from collections import defaultdict
from dataclasses import dataclass

# Ensure repository root is on sys.path
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from m1_capture.features import CONCURRENCY_FEATURES, RATE_FEATURES, STALL_FEATURES

SLOW_FEATURES = STALL_FEATURES | CONCURRENCY_FEATURES


@dataclass
class Mechanism:
    """What actually gets enforced."""
    rate_limit: int | None = None
    conn_limit: int | None = None
    timeout_s: float | None = None
    reason: str = ""
    driver: str = ""          # the feature (or group) that decided this
    driver_group: str = ""    # "stall" | "concurrency" | "rate" | "unclear"


def group_of(name: str) -> str:
    if name in STALL_FEATURES:
        return "stall"
    if name in CONCURRENCY_FEATURES:
        return "concurrency"
    if name in RATE_FEATURES:
        return "rate"
    return "other"


# ---------------------------------------------------------------------------
# The policy ladders. Four rungs, hysteresis, per-entity state.
# ---------------------------------------------------------------------------
from m4_decide.policy import LADDER, Policy

CONN_LIMIT = 20        # what we apply for a stall-class attack
RATE_LIMIT = 50        # what we apply for a rate-class attack


# ---------------------------------------------------------------------------
# Switch 1: static. The naive baseline every project starts with.
# ---------------------------------------------------------------------------
def choose_static(score: float) -> Mechanism:
    return Mechanism(rate_limit=RATE_LIMIT,
                     reason="static policy: always limit_req",
                     driver="static", driver_group="rate")


# ---------------------------------------------------------------------------
# Switch 2: trigger-driven. Does the cheap trigger already know the answer?
# ---------------------------------------------------------------------------
TRIGGER_TO_GROUP = {
    "stall": "stall",
    "connections": "concurrency",
    "rate": "rate",
    "cusum": "rate",
    "entropy": "rate",
}


def choose_by_trigger(trigger: str | None, score: float) -> Mechanism:
    grp = TRIGGER_TO_GROUP.get(trigger or "", "unclear")
    return _mechanism_for_group(grp, score,
                                f"trigger '{trigger}' indicates {grp}")


# ---------------------------------------------------------------------------
# Switch 3: SHAP top-1.
# ---------------------------------------------------------------------------
def choose_by_shap_top1(shap_top_k: list, score: float) -> Mechanism:
    if not shap_top_k:
        return choose_static(score)
    name, val = shap_top_k[0]
    grp = group_of(name)
    if val <= 0:
        return Mechanism(rate_limit=RATE_LIMIT, conn_limit=CONN_LIMIT,
                         timeout_s=10.0,
                         reason=f"top SHAP feature '{name}' is negative ({val:+.3f});"
                                f" applying both limits moderately",
                         driver=name, driver_group="unclear")
    return _mechanism_for_group(grp, score,
                                f"top SHAP feature '{name}' ({val:+.3f})")


# ---------------------------------------------------------------------------
# Switch 4: SHAP summed per group. More robust than top-1.
# ---------------------------------------------------------------------------
def shap_group_scores(shap_values: dict) -> dict:
    """Sum SHAP per feature group. Groups compete on total contribution."""
    out = defaultdict(float)
    for name, val in shap_values.items():
        out[group_of(name)] += abs(val)
    return dict(out)


def choose_by_shap_group(shap_values: dict, score: float) -> Mechanism:
    """Group-summed attribution: SHAP summed per feature group, winner takes all.
    More robust than top-1 when evidence is spread across several features —
    see test_mechanism.py for the case where top-1 flips on a tie and the sum
    does not.
    """
    if not shap_values:
        return choose_static(score)
    groups = shap_group_scores(shap_values)
    grp = max(groups, key=groups.get)
    top_feat = max(shap_values, key=lambda k: abs(shap_values[k]))
    return _mechanism_for_group(
        grp, score,
        f"SHAP group '{grp}' dominates (Σ|φ|={groups[grp]:.3f}, "
        f"leading feature '{top_feat}')")


def _mechanism_for_group(grp: str, score: float, why: str) -> Mechanism:
    if grp in ("stall", "concurrency"):
        # rate limiting is structurally useless here
        return Mechanism(conn_limit=CONN_LIMIT, timeout_s=10.0,
                         driver_group=grp, driver=why,
                         reason=f"{why} -> slow-attack class. Rate limiting cannot "
                                f"contain this; applying limit_conn + timeouts.")
    if grp == "rate":
        return Mechanism(rate_limit=max(5, int(RATE_LIMIT * (1 - score))),
                         driver_group=grp, driver=why,
                         reason=f"{why} -> rate class. Applying token-bucket rate limit.")
    # unclear: apply both, moderately. Never leave nothing enforced.
    return Mechanism(rate_limit=RATE_LIMIT, conn_limit=CONN_LIMIT,
                     timeout_s=15.0, driver_group="unclear", driver=why,
                     reason=f"{why} -> unclear. Applying moderate limits to both.")


def contains(mech: Mechanism, profile: dict) -> tuple[bool, str]:
    if mech.conn_limit is not None and mech.rate_limit is None:
        if profile["concurrent_conns"] > 1 or profile["stall"] > 5.0:
            return True, "limit_conn + timeout applied to a connection-holding attack"
        return False, "conn limit applied but attack is not connection-holding"
    if mech.rate_limit is not None and mech.conn_limit is None:
        if profile["rate"] > 20.0:
            return True, "rate limit applied to a high-rate attack"
        if profile["concurrent_conns"] > 5 or profile["stall"] > 5.0:
            return False, ("rate limit applied to a slow attack — it will never "
                           "trip the threshold")
        return True, "rate limit applied to a rate-based attack"
    if profile["rate"] > 20.0 or profile["concurrent_conns"] > 5 or profile["stall"] > 5.0:
        return True, "both limits applied to a multi-vector attack"
    return False, "both limits applied but attack below every threshold"


def precision_at_k(ranked, true_ids, k) -> float:
    if not ranked:
        return 0.0
    top = {fid for fid, *_ in ranked[:k]}
    return len(top & set(true_ids)) / float(k)
