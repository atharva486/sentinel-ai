#!/usr/bin/env python3
"""
mechanism.py — pick the enforcement mode, and be honest about whether it works.

THE CONTRIBUTION
----------------
A normal IDS detects an attack and applies a fixed response. We read *why* the
model scored it, and let the reason pick the defence.

Why that matters: a rate limit is USELESS against a slow attack, because a
slow attacker never trips a rate threshold. If the explanation says "stall",
applying a rate limit is the wrong defence entirely.

THREE SWITCHES, SO THE ATTRIBUTION CAN BE TESTED
------------------------------------------------
The obvious worry is that the cheap trigger already knows the answer. Module 2
fires a "stall" trigger on exactly the flows a SHAP top-1 would call slow, in
which case the attribution adds nothing. So the switch is implemented three
ways and all three are measured against the same workload:

  SwitchStatic     always limit_req          (the naive baseline)
  SwitchTrigger    Module 2's trigger name decides
  SwitchShapTop1   single highest-|SHAP| feature decides
  SwitchShapGroup  SHAP summed per feature GROUP decides

SwitchShapGroup is the one to watch. Top-1 is fragile: if two features tie, or
the top feature is a weak correlate, top-1 flips on noise. Summing SHAP over
a whole group is the standard robustness fix.

If SwitchTrigger matches SwitchShapGroup, that is a real and publishable
negative result, and we report it. We do not get to pick which one wins.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from features import CONCURRENCY_FEATURES, RATE_FEATURES, STALL_FEATURES


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
# The policy ladders. Three rungs, hysteresis, per-entity state.
#
# No "challenge" rung: an API client cannot solve a CAPTCHA, so challenging an
# API caller is a self-inflicted outage. The ladder is forward -> throttle ->
# quarantine -> block, which is what an API can actually honour.
# ---------------------------------------------------------------------------

LADDER = [
    (0.80, 0.70, "quarantine"),
    (0.55, 0.46, "block"),
    (0.30, 0.24, "throttle"),
    (0.00, 0.00, "forward"),
]

CONN_LIMIT = 20        # what we apply for a stall-class attack
RATE_LIMIT = 50        # what we apply for a rate-class attack


class Policy:
    """Score -> action, with hysteresis so the action cannot flap."""

    def __init__(self):
        self._state: dict[str, int] = {}

    def decide(self, entity: str, score: float) -> str:
        """LADDER is ordered MOST SEVERE FIRST: index 0 = quarantine,
        index len-1 = forward. So a fresh entity starts at the bottom and
        must walk TOWARD index 0 to escalate.

        BUG FIXED: the original looped range(current, len(LADDER)) i.e. toward
        LESS severe rungs. A fresh entity at the last index therefore only ever
        tested LADDER[-1][0] == 0.00, which every score passes -- so decide()
        returned "forward" for everything, including 0.99. Escalation was
        impossible, which silently zeroed the ablation's collateral column and
        made the hysteresis test pass vacuously.
        """
        current = self._state.get(entity, len(LADDER) - 1)

        # ESCALATE: walk toward index 0 while the score clears each enter
        # threshold (0.80 -> 0.55 -> 0.30).
        while current > 0 and score >= LADDER[current - 1][0]:
            current -= 1

        # DE-ESCALATE: walk away from index 0 only once the score falls below
        # the rung's EXIT threshold (hysteresis deadband). Without the pair,
        # a score oscillating around a boundary flips the action every call.
        while current < len(LADDER) - 1 and score < LADDER[current][1]:
            current += 1

        self._state[entity] = current
        return LADDER[current][2]


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
        # top feature argued FOR legitimacy; fall back to the score only
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


# ---------------------------------------------------------------------------
# Does a mechanism actually stop a given attack?
#
# This is the part that makes the ablation a measurement rather than a claim.
# Containment is decided by whether the mechanism matches the attack's
# structural weakness, evaluated on the observed traffic profile.
# ---------------------------------------------------------------------------
def contains(mech: Mechanism, profile: dict) -> tuple[bool, str]:
    """profile keys: rate (float), concurrent_conns (int), stall (float)."""
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
    # both applied
    if profile["rate"] > 20.0 or profile["concurrent_conns"] > 5 or profile["stall"] > 5.0:
        return True, "both limits applied to a multi-vector attack"
    return False, "both limits applied but attack below every threshold"


def precision_at_k(ranked, true_ids, k) -> float:
    """Attribution metric: of the k flows we highlight, how many were real?"""
    if not ranked:
        return 0.0
    top = {fid for fid, *_ in ranked[:k]}
    return len(top & set(true_ids)) / float(k)
