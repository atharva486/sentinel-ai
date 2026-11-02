#!/usr/bin/env python3
from __future__ import annotations

import math

RATE_FEATURES = frozenset({
    "bytes_in_per_s",
    "requests_per_s",
    "interarrival_mean",
    "interarrival_std",
    "interarrival_max",
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

SLOW_GROUP = STALL_FEATURES | CONCURRENCY_FEATURES
FAST_GROUP = RATE_FEATURES

FEATURE_ORDER = [
    "bytes_in",
    "bytes_in_per_s",
    "requests_per_s",
    "packets_per_s",
    "interarrival_mean",
    "interarrival_std",
    "interarrival_max",
    "concurrent_conns",
    "conns_per_second_opened",
    "requests_per_conn_so_far",
    "conn_age_s",
    "stall_time_s",
    "body_frac_sent",
    "bytes_declared",
    "body_drip_rate_bps",
    "header_complete",
]

EXCLUDED = {
    "status_code":        "set by our own policy",
    "total_bytes":        "needs the flow to end",
    "requests_per_conn":  "needs the connection to end",
    "response_time":      "produced by the server after we decide",
    "is_attack":          "the label",
    "attack_type":        "the label",
    "replay_*":           "not computable for a live flow",
    "fan_out":            "needs many requests per flow",
    "header_length":      "header_complete already carries this",
}


def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b else default


def flow_features(rec: dict, now: float) -> dict:
    t_last = rec["t_last"]
    elapsed = max(1e-6, t_last - rec["t_first"])
    open_age = max(0.0, now - rec["t_first"]) if not rec["t_close"] else elapsed

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
        "requests_per_s":      _safe_div(reqs, span),
        "interarrival_mean":   inter_mean,
        "interarrival_std":    inter_std,
        "interarrival_max":    max(gaps) if gaps else 0.0,
        "syn_retries":         float(rec["syn_retries"]),
        "bytes_in_ratio":      _safe_div(rec["fwd_bytes"],
                                         rec["fwd_bytes"] + rec["bwd_bytes"], 1.0),
    }


def open_flow_features(rec: dict, http: dict, now: float) -> dict:
    is_open = rec["t_close"] is None or now < rec["t_close"]
    t_close = rec["t_close"]
    age = (max(0.0, now - rec["t_first"]) if is_open
           else (t_close - rec["t_first"]))

    declared = float(http["declared_body"] or 0)
    header_bytes = float(http["header_bytes"] or 0)
    header_complete = bool(http["header_complete"])

    body_received = max(0.0, rec["fwd_bytes"] - header_bytes)
    body_frac = _safe_div(body_received, declared, 1.0) if declared > 0 else 1.0

    if not header_complete:
        stall_time = age
    elif declared > 0 and body_frac < 1.0:
        stall_time = age
    else:
        stall_time = 0.0

    drip = _safe_div(body_received, age)

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
    def __init__(self, window_s: float = 10.0):
        self.window_s = window_s
        self.intervals: dict[str, list[list[float | None]]] = {}

    def on_connect(self, entity: str, ts: float) -> None:
        self.intervals.setdefault(entity, []).append([ts, None])

    def on_close(self, entity: str, ts: float) -> None:
        ivs = self.intervals.get(entity)
        if ivs and ivs[-1][1] is None:
            ivs[-1][1] = ts

    def window_features(self, entity: str, now: float) -> dict:
        lo = now - self.window_s
        live = 0
        opened = 0
        for a, b in self.intervals.get(entity, []):
            if a > now:
                continue
            if b is None or b > now:
                live += 1
            if lo <= a <= now:
                opened += 1
        span = max(1e-6, self.window_s)
        return {
            "concurrent_conns":        float(live),
            "conns_per_second_opened": opened / span,
        }


def build_features(rec: dict, http: dict, window: WindowTracker,
                   entity: str, now: float) -> dict:
    f = {}
    f.update(flow_features(rec, now))
    f.update(open_flow_features(rec, http, now))
    f.update(window.window_features(entity, now))
    return {k: f.get(k, 0.0) for k in FEATURE_ORDER}


def vectorise(f: dict) -> list[float]:
    return [float(f.get(k, 0.0)) for k in FEATURE_ORDER]


def group_of(name: str) -> str:
    if name in STALL_FEATURES:
        return "stall"
    if name in CONCURRENCY_FEATURES:
        return "concurrency"
    if name in RATE_FEATURES:
        return "rate"
    return "other"
