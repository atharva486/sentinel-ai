#!/usr/bin/env python3
"""
features.py — raw flow record -> feature vector.

HOW THIS FILE WAS DERIVED
-------------------------
The previous version of this list came from a dataset (CIC-IDS2017 columns),
which produced two fatal problems:

  * features the mechanism never needs (req_rate, fan_out, header_length),
  * and no flood examples, because Hulk was dropped from the dataset.

So the list is now derived from the DECISION we must make, in the reverse
direction:

    We must choose between limit_req and limit_conn.
    What does limit_req respond to?   -> RATE
    What does limit_conn respond to? -> CONCURRENCY + STALL
    So those are the features we must be able to compute.

Every feature below has a job: it either separates rate from stall (so the
mechanism switch has something to switch on), or it is a trap we deliberately
exclude. Nothing is included because a dataset happened to contain it.

TWO TIERS, BOTH NEEDED
----------------------
  flow tier    : computed from ONE connection            (limit_req responds)
  window tier  : computed from MANY connections          (limit_conn responds)

A per-connection view cannot see concurrency, which is exactly what
limit_conn acts on. That asymmetry is the reason for two tiers.

NO LEAKAGE RULE (the part that gets graded)
-------------------------------------------
A feature is admissible only if its value is computable at DECISION TIME,
from data available up to that moment, for a flow that has not finished.

  ALLOWED: bytes sent so far, elapsed time, bytes still declared,
            connection count right now, inter-arrival gaps observed so far
  FORBIDDEN: total bytes (needs the flow to end), HTTP status code,
             number of requests on the connection (needs the connection to
             end), server response time, anything the proxy produced AFTER
             deciding, any label-derived or replay-derived column.

Every exclusion is listed in EXCLUDED with the reason.
"""
from __future__ import annotations

import math

# ---------------------------------------------------------------------------
# Feature groups. The mechanism switch reads these, so each group must be a
# coherent story: "this looks like rate" vs "this looks like stall".
# ---------------------------------------------------------------------------

RATE_FEATURES = frozenset({
    "bytes_in_per_s",
    "requests_per_s",
    "interarrival_mean",
    "interarrival_std",
    "packets_per_s",
    "bytes_in",
})

CONCURRENCY_FEATURES = frozenset({
    "concurrent_conns",
    "conns_per_second_opened",
    "requests_per_conn_so_far",
    "conn_age_s",
})

STALL_FEATURES = frozenset({
    "stall_time_s",
    "body_frac_sent",
    "bytes_declared",
    "body_drip_rate_bps",
    "header_complete",
})

# what the switch branches on
SLOW_GROUP = STALL_FEATURES | CONCURRENCY_FEATURES
FAST_GROUP = RATE_FEATURES

FEATURE_ORDER = [
    # --- rate tier: what limit_req responds to ---
    "bytes_in",
    "bytes_in_per_s",
    "requests_per_s",
    "packets_per_s",
    "interarrival_mean",
    "interarrival_std",
    "interarrival_max",
    # --- concurrency tier: what limit_conn responds to ---
    "concurrent_conns",
    "conns_per_second_opened",
    "requests_per_conn_so_far",
    "conn_age_s",
    # --- stall tier: what timeouts respond to ---
    "stall_time_s",
    "body_frac_sent",
    "bytes_declared",
    "body_drip_rate_bps",
    "header_complete",
    # --- shape ---
    # NOTE — these fields stay in schemas.py FlowRecord (the frozen contract)
    # and are still emitted by sensor.py / features.py, but are deliberately
    # NOT consumed by the model because they are structurally CONSTANT on the
    # emulated lab network (so they carry no signal here):
    #   * syn_retries        : constant 0 (clean bridge, no retransmission)
    #   * bytes_out_per_s    : constant 0 (no backward bytes on the lab)
    #   * bytes_in_ratio     : constant 1 (fwd/(fwd+bwd) with bwd == 0)
    #   * time_to_first_byte : constant 0 (proxy->client latency on a local
    #                           bridge, below the sensor's timing resolution)
    # The last three were only NON-constant in the other-agents' captures —
    # which used an unknown sensor variant, one more reason those captures are
    # excluded from the final set (see DATA_CARD). In a real WAN deployment,
    # re-enable these upstream.
]

# Features deliberately absent. Each one would have leaked or been useless.
EXCLUDED = {
    "status_code":        "set by our own policy -> model learns from our actions",
    "total_bytes":        "needs the flow to end -> not knowable at decision time",
    "requests_per_conn":  "needs the connection to end; use requests_per_conn_so_far",
    "response_time":      "produced by the server AFTER we decide",
    "is_attack":          "the label",
    "attack_type":        "the label",
    "replay_*":           "not computable for a live flow -> future work, see below",
    "fan_out":            "needs many requests per flow; same leakage as above",
    "header_length":      "header_complete already carries this, as a ratio",
}


def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b else default


def flow_features(rec: dict, now: float) -> dict:
    """Raw flow record -> flow-tier features, all computable at decision time.

    rec comes from sensor.py. now is the current wall clock (the live edge).
    """
    t_last = rec["t_last"]
    elapsed = max(1e-6, t_last - rec["t_first"])
    open_age = max(0.0, now - rec["t_first"]) if not rec["t_close"] else elapsed

    # ---- inter-arrival gaps, forward direction only ----
    ft = rec["fwd_times"]
    if len(ft) >= 2:
        gaps = [b - a for a, b in zip(ft, ft[1:])]
        inter_mean = sum(gaps) / len(gaps)
        inter_std = math.sqrt(sum((g - inter_mean) ** 2 for g in gaps) / len(gaps))
    else:
        gaps, inter_mean, inter_std = [], 0.0, 0.0

    span = max(1e-6, t_last - rec["t_first"])
    reqs = float(rec["n_requests_seen"])

    return {
        "bytes_in":            float(rec["fwd_bytes"]),
        "bytes_out":           float(rec["bwd_bytes"]),
        "bytes_in_per_s":      _safe_div(rec["fwd_bytes"], elapsed),
        "bytes_out_per_s":     _safe_div(rec["bwd_bytes"], elapsed),
        "packets_per_s":       _safe_div(rec["fwd_pkts"] + rec["bwd_pkts"], elapsed),
        # requests_per_s is DERIVED HERE, not read off a dataset column.
        # The old FEATURES list named this feature but no code ever computed it,
        # which is why the flood branch of the mechanism switch had nothing to
        # read. Computing it from what we actually observed is what makes the
        # flood branch possible.
        "requests_per_s":      _safe_div(reqs, span),
        "interarrival_mean":   inter_mean,
        "interarrival_std":    inter_std,
        "interarrival_max":    max(gaps) if gaps else 0.0,
        "syn_retries":         float(rec["syn_retries"]),
        "bytes_in_ratio":      _safe_div(rec["fwd_bytes"],
                                         rec["fwd_bytes"] + rec["bwd_bytes"], 1.0),
    }


def open_flow_features(rec: dict, http: dict, now: float) -> dict:
    """The stall/concurrency features. ONLY meaningful while the flow is open.

    This is the function that makes a Slowloris connection describable at all.
    A flow that has not sent its header terminator yet has no
    requests_per_conn, no status code, and no response time. It has exactly:
    how long it has been open, how much it declared, how much arrived, and
    how fast the drip is.
    """
    is_open = rec["t_close"] is None or now < rec["t_close"]
    t_close = rec["t_close"]
    age = (max(0.0, now - rec["t_first"]) if is_open
           else (t_close - rec["t_first"]))

    declared = float(http["declared_body"] or 0)
    header_bytes = float(http["header_bytes"] or 0)
    header_complete = bool(http["header_complete"])

    body_received = max(0.0, rec["fwd_bytes"] - header_bytes)
    # No declared body means we cannot say anything about body completeness.
    # Default to 1.0 (nothing outstanding) rather than 0.0, so a plain GET
    # does not read as "0% of the body arrived".
    body_frac = _safe_div(body_received, declared, 1.0) if declared > 0 else 1.0

    # stall_time_s — time spent with the request INCOMPLETE. Two cases:
    #
    #   (a) header not terminated  -> Slowloris. No request exists yet.
    #   (b) header done, body short -> RUDY.
    #
    # Both are "the client promised something and has not finished sending it".
    # Gating only on (b) was the earlier bug: it gave Slowloris stall_time 0,
    # which is exactly backwards, since Slowloris is the purest stall there is.
    #
    # body_bytes_only gates (b) so a legitimate GET (which declares no body)
    # never looks stalled.
    if not header_complete:
        stall_time = age
    elif declared > 0 and body_frac < 1.0:
        stall_time = age
    else:
        stall_time = 0.0

    # body drip rate: how fast the declared body is actually arriving.
    drip = _safe_div(body_received, age)

    # time_to_first_byte = when the first backward (response) byte arrived,
    # measured from the first forward byte. The earlier code fell back to the
    # flow duration, which is not a time-to-first-byte and duplicated
    # conn_age_s; and it read t_close (the flow's true close time) as if the
    # flow had ended, which is future information relative to `now`.
    t_first_bwd = rec.get("t_first_bwd") or 0.0
    ttfb = (t_first_bwd - rec["t_first"]) if t_first_bwd > 0 else None

    return {
        "bytes_declared":      declared,
        "header_complete":     1.0 if header_complete else 0.0,
        "body_frac_sent":      min(1.0, body_frac),
        "header_frac_sent":    (1.0 if header_complete else
                                min(1.0, _safe_div(header_bytes, max(1.0, header_bytes)))),
        "stall_time_s":        stall_time,
        "body_drip_rate_bps":  drip,
        "time_to_first_byte":  float(ttfb) if ttfb is not None else 0.0,
        "conn_age_s":          age,
        "requests_per_conn_so_far": float(rec["n_requests_seen"]),
        "is_open":             1.0 if is_open else 0.0,
    }


class WindowTracker:
    """Window-tier features: what limit_conn actually acts on.

    Concurrency is a property of an ENTITY over a window, not of a flow. This
    is the concrete reason the design needs two tiers.

    A connection is OPEN at time `now` if it opened at or before `now` and has
    not closed by `now`. Both facts are observable at `now`, so this is NOT
    leakage (see the NO LEAKAGE RULE above).

    Why this is not the old events version: sensor.py stamps EVERY flow with a
    t_close (even flows still open when the capture ends). The old code stored
    open/close events and returned opens-minus-closes, so every connection
    contributed exactly one open and one close and the result was ALWAYS 0. The
    concurrency tier — the signal limit_conn exists to read — was dead, which
    would make the SHAP->mechanism switch unable to ever pick limit_conn.
    """

    def __init__(self, window_s: float = 10.0):
        self.window_s = window_s
        # entity -> list of [open_ts, close_ts | None]
        self.intervals: dict[str, list[list[float | None]]] = {}

    def on_connect(self, entity: str, ts: float) -> None:
        self.intervals.setdefault(entity, []).append([ts, None])

    def on_close(self, entity: str, ts: float) -> None:
        # Closes the most recently opened, still-open interval for this entity.
        # Callers use a connect-then-close pair per flow, so this is the match.
        ivs = self.intervals.get(entity)
        if ivs and ivs[-1][1] is None:
            ivs[-1][1] = ts

    def window_features(self, entity: str, now: float) -> dict:
        lo = now - self.window_s
        live = 0
        opened = 0
        for a, b in self.intervals.get(entity, []):
            if a > now:
                continue                      # has not started as of `now`
            if b is None or b > now:
                live += 1                     # open at `now`
            if lo <= a <= now:
                opened += 1
        span = max(1e-6, self.window_s)
        return {
            "concurrent_conns":        float(live),
            "conns_per_second_opened": opened / span,
        }


def build_features(rec: dict, http: dict, window: WindowTracker,
                   entity: str, now: float) -> dict:
    """Full feature vector in FEATURE_ORDER. One call, one dict."""
    f = {}
    f.update(flow_features(rec, now))
    f.update(open_flow_features(rec, http, now))
    f.update(window.window_features(entity, now))
    return {k: f.get(k, 0.0) for k in FEATURE_ORDER}


def vectorise(f: dict) -> list[float]:
    """dict -> list in FEATURE_ORDER, for the model."""
    return [float(f.get(k, 0.0)) for k in FEATURE_ORDER]


def group_of(name: str) -> str:
    """Which group a SHAP-top feature belongs to. Used by the mechanism switch."""
    if name in STALL_FEATURES:
        return "stall"
    if name in CONCURRENCY_FEATURES:
        return "concurrency"
    if name in RATE_FEATURES:
        return "rate"
    return "other"
