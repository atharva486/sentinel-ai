
from collections import defaultdict
from dataclasses import dataclass

from capture.features import CONCURRENCY_FEATURES, RATE_FEATURES, STALL_FEATURES

SLOW_FEATURES = STALL_FEATURES | CONCURRENCY_FEATURES


@dataclass
class Mechanism:
    rate_limit: int | None = None
    conn_limit: int | None = None
    timeout_s: float | None = None
    reason: str = ""
    driver: str = ""
    driver_group: str = ""


def group_of(name: str) -> str:
    if name in STALL_FEATURES:
        return "stall"
    if name in CONCURRENCY_FEATURES:
        return "concurrency"
    if name in RATE_FEATURES:
        return "rate"
    return "other"


LADDER = [
    (0.80, 0.70, "quarantine"),
    (0.55, 0.46, "block"),
    (0.30, 0.24, "throttle"),
    (0.00, 0.00, "forward"),
]

QUARANTINE_THRESHOLD = LADDER[0][0]
BLOCK_THRESHOLD = LADDER[1][0]
THROTTLE_THRESHOLD = LADDER[2][0]
DETECT_THRESHOLD = min(t for t, _exit, action in LADDER if action != "forward")

CONN_LIMIT = 20
RATE_LIMIT = 50


class Policy:
    def __init__(self):
        self._state: dict[str, int] = {}

    def decide(self, entity: str, score: float) -> str:
        current = self._state.get(entity, len(LADDER) - 1)

        while current > 0 and score >= LADDER[current - 1][0]:
            current -= 1

        while current < len(LADDER) - 1 and score < LADDER[current][1]:
            current += 1

        self._state[entity] = current
        return LADDER[current][2]


def choose_static(score: float) -> Mechanism:
    return Mechanism(rate_limit=RATE_LIMIT,
                     reason="static policy: always limit_req",
                     driver="static", driver_group="rate")


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


def shap_group_scores(shap_values: dict) -> dict:
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
        return Mechanism(conn_limit=CONN_LIMIT, timeout_s=10.0,
                         driver_group=grp, driver=why,
                         reason=f"{why} -> slow-attack class. Rate limiting cannot "
                                f"contain this; applying limit_conn + timeouts.")
    if grp == "rate":
        return Mechanism(rate_limit=max(5, int(RATE_LIMIT * (1 - score))),
                         driver_group=grp, driver=why,
                         reason=f"{why} -> rate class. Applying token-bucket rate limit.")
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


def apply_profile_guard(mech: Mechanism, profile: dict) -> Mechanism:
    contained, _why = contains(mech, profile)
    if contained:
        return mech
    rate = mech.rate_limit
    conn = mech.conn_limit
    if rate is None and profile.get("rate", 0.0) > 20.0:
        rate = RATE_LIMIT
    if conn is None and (profile.get("concurrent_conns", 0) > 1
                         or profile.get("stall", 0.0) > 5.0):
        conn = CONN_LIMIT
    if (rate, conn) == (mech.rate_limit, mech.conn_limit):
        return mech
    return Mechanism(
        rate_limit=rate,
        conn_limit=conn,
        timeout_s=max(mech.timeout_s or 0.0, 10.0) if conn is not None else mech.timeout_s,
        driver=f"profile guard on {mech.driver_group}",
        driver_group=mech.driver_group,
        reason=(f"{mech.reason} | profile guard: the chosen mechanism cannot "
                f"contain the observed profile, so the missing limit was added."),
    )


def precision_at_k(ranked, true_ids, k) -> float:
    if not ranked:
        return 0.0
    top = {fid for fid, *_ in ranked[:k]}
    return len(top & set(true_ids)) / float(k)
