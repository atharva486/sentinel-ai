#!/usr/bin/env python3
from __future__ import annotations

import math

# ---------------------------------------------------------------------------
# Feature groups
# ---------------------------------------------------------------------------
# Base per-connection features: computable from a single connection's state
# at decision time ``now``.  No IP-level context required.
BASE_FEATURES = frozenset({
    "bytes_in",
    "bytes_in_per_s",
    "requests_per_s",
    "packets_per_s",
    "interarrival_mean",
    "interarrival_std",
    "interarrival_max",
    "requests_per_conn_so_far",
    "conn_age_s",
    "stall_time_s",
    "body_frac_sent",
    "bytes_declared",
    "body_drip_rate_bps",
    "header_complete",
    "idle_s",
})

# IP-level context features: require knowledge of other connections on the
# same source IP.  Used only for escalation (Phase 5), never for the base
# per-connection score.
IPCONTEXT_FEATURES = frozenset({
    "concurrent_conns",
    "conns_per_second_opened",
    "stalled_fraction",
})

# Full feature order for the new (base-only) model: 15 per-connection features.
FEATURE_ORDER = [
    "bytes_in",
    "bytes_in_per_s",
    "requests_per_s",
    "packets_per_s",
    "interarrival_mean",
    "interarrival_std",
    "interarrival_max",
    "requests_per_conn_so_far",
    "conn_age_s",
    "stall_time_s",
    "body_frac_sent",
    "bytes_declared",
    "body_drip_rate_bps",
    "header_complete",
    "idle_s",
]

# Legacy 16-feature order used by the shipped (old) model artifact.
LEGACY_FEATURE_ORDER = [
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

SLOW_GROUP = {"stall_time_s", "body_frac_sent", "bytes_declared",
              "body_drip_rate_bps", "header_complete"}
RATE_GROUP = {"bytes_in", "bytes_in_per_s", "requests_per_s",
              "packets_per_s", "interarrival_mean", "interarrival_std",
              "interarrival_max"}

# Backwards-compatible aliases for legacy code (mechanism.py, dashboard).
# These mirror the original pre-Phase-2 groupings.
STALL_FEATURES = {"stall_time_s", "body_frac_sent", "bytes_declared",
                  "body_drip_rate_bps", "header_complete"}
CONCURRENCY_FEATURES = {"concurrent_conns", "conns_per_second_opened",
                        "requests_per_conn_so_far", "conn_age_s"}
RATE_FEATURES = {"bytes_in", "bytes_in_per_s", "requests_per_s",
                 "packets_per_s", "interarrival_mean", "interarrival_std",
                 "interarrival_max"}


def _safe_div(a: float, b: float, default: float = 0.0) -> float:
    return a / b if b else default


# ---------------------------------------------------------------------------
# Connection state helpers
# ---------------------------------------------------------------------------
def _conn_fields(fs) -> dict:
    """Pull common fields from a FlowState object or a dict."""
    if hasattr(fs, "t_first"):
        return {
            "t_first": fs.t_first or 0.0,
            "t_last": fs.t_last or 0.0,
            "t_close": fs.t_close,
            "fwd_bytes": fs.fwd_bytes,
            "bwd_bytes": fs.bwd_bytes,
            "fwd_pkts": fs.fwd_pkts,
            "bwd_pkts": fs.bwd_pkts,
            "fwd_times": list(fs.fwd_times),
            "n_requests_seen": fs.n_requests_seen,
            "client_ip": fs.client_ip,
            "flow_id": fs.flow_id,
        }
    return {
        "t_first": fs.get("t_first", 0.0) or 0.0,
        "t_last": fs.get("t_last", 0.0) or 0.0,
        "t_close": fs.get("t_close"),
        "fwd_bytes": fs.get("fwd_bytes", 0),
        "bwd_bytes": fs.get("bwd_bytes", 0),
        "fwd_pkts": fs.get("fwd_pkts", 0),
        "bwd_pkts": fs.get("bwd_pkts", 0),
        "fwd_times": list(fs.get("fwd_times", [])),
        "n_requests_seen": fs.get("n_requests_seen", 0),
        "client_ip": fs.get("client_ip", ""),
        "flow_id": fs.get("flow_id", ""),
    }


# ---------------------------------------------------------------------------
# Base per-connection features
# ---------------------------------------------------------------------------
def features(conn_state, now: float) -> dict:
    """Compute base per-connection features at decision time ``now``.

    Denominators use (now - t_first), NOT (t_last - t_first), so a connection
    that burst then went silent sees a decaying bytes_in_per_s and a rising
    idle_s.  Returns exactly the keys in BASE_FEATURES.
    """
    f = _conn_fields(conn_state)
    t_first = f["t_first"]
    t_last = f["t_last"]
    t_close = f["t_close"]

    # Open age: now - t_first (capped at flow close for closed flows)
    if t_close is not None:
        age = max(0.0, t_close - t_first)
        is_open = False
    else:
        age = max(0.0, now - t_first)
        is_open = True

    # idle_s: time since last packet (0 for closed flows)
    idle_s = 0.0 if not is_open else max(0.0, now - t_last)

    # elapsed for rates: now - t_first (never t_last - t_first)
    elapsed = max(1e-6, now - t_first) if is_open else max(1e-6, age)

    ft = f["fwd_times"]
    if len(ft) >= 2:
        gaps = [b - a for a, b in zip(ft, ft[1:])]
        inter_mean = sum(gaps) / len(gaps)
        inter_std = math.sqrt(sum((g - inter_mean) ** 2 for g in gaps) / len(gaps))
    else:
        gaps, inter_mean, inter_std = [], 0.0, 0.0

    reqs = float(f["n_requests_seen"])

    return {
        "bytes_in":             float(f["fwd_bytes"]),
        "bytes_in_per_s":       _safe_div(f["fwd_bytes"], elapsed),
        "requests_per_s":       _safe_div(reqs, elapsed),
        "packets_per_s":        _safe_div(f["fwd_pkts"] + f["bwd_pkts"], elapsed),
        "interarrival_mean":    inter_mean,
        "interarrival_std":     inter_std,
        "interarrival_max":     max(gaps) if gaps else 0.0,
        "requests_per_conn_so_far": reqs,
        "conn_age_s":           age,
        "stall_time_s":         0.0,      # filled by http-aware wrapper below
        "body_frac_sent":       0.0,      # filled by http-aware wrapper below
        "bytes_declared":       0.0,      # filled by http-aware wrapper below
        "body_drip_rate_bps":   0.0,      # filled by http-aware wrapper below
        "header_complete":      0.0,      # filled by http-aware wrapper below
        "idle_s":               idle_s,
    }


def features_http(conn_state, http: dict, now: float) -> dict:
    """Base features + HTTP-aware stall/body fields (requires parse_http output).

    Returns exactly the keys in BASE_FEATURES.
    """
    base = features(conn_state, now)

    f = _conn_fields(conn_state)
    t_first = f["t_first"]
    t_close = f["t_close"]
    if t_close is not None:
        age = max(0.0, t_close - t_first)
    else:
        age = max(0.0, now - t_first)

    declared = float(http.get("declared_body") or 0)
    header_bytes = float(http.get("header_bytes") or 0)
    header_complete = bool(http.get("header_complete"))

    body_received = max(0.0, f["fwd_bytes"] - header_bytes)
    body_frac = _safe_div(body_received, declared, 1.0) if declared > 0 else 1.0

    if not header_complete:
        stall_time = age
    elif declared > 0 and body_frac < 1.0:
        stall_time = age
    else:
        stall_time = 0.0

    drip = _safe_div(body_received, age)

    base["stall_time_s"] = stall_time
    base["body_frac_sent"] = min(1.0, body_frac)
    base["bytes_declared"] = declared
    base["body_drip_rate_bps"] = drip
    base["header_complete"] = 1.0 if header_complete else 0.0
    return base


# ---------------------------------------------------------------------------
# IP-level context features (escalation only, Phase 5)
# ---------------------------------------------------------------------------
def ip_context(conn_state, now: float, entity: str,
               window: "WindowTracker",
               stalled_ips: dict[str, set] | None = None) -> dict:
    """IP-level context features at decision time ``now``.

    Requires knowledge of other connections on the same source IP.  The base
    per-connection score must be computable without these; they are used only
    for escalation (Phase 5).

    ``stalled_ips`` maps ip -> set of flow_ids currently stalled (header or
    body incomplete at ``now``).  Used to compute stalled_fraction.
    """
    f = _conn_fields(conn_state)
    t_first = f["t_first"]
    t_close = f["t_close"]

    win = window.window_features(entity, now)

    # stalled_fraction: share of this IP's live connections that are stalled
    if stalled_ips is not None:
        stalled_for_ip = stalled_ips.get(entity, set())
        live_conns = max(1, int(win["concurrent_conns"]))
        stalled_frac = len(stalled_for_ip) / live_conns
    else:
        stalled_frac = 0.0

    return {
        "concurrent_conns":        win["concurrent_conns"],
        "conns_per_second_opened": win["conns_per_second_opened"],
        "stalled_fraction":        stalled_frac,
    }


# ---------------------------------------------------------------------------
# Legacy 16-feature vector (for scoring the shipped old model)
# ---------------------------------------------------------------------------
def legacy_features(conn_state, http: dict, window: "WindowTracker",
                    entity: str, now: float) -> dict:
    """Build the legacy 16-feature vector expected by the shipped model.

    Combines base features + ip_context so the old model (trained on 16
    features including concurrent_conns/conns_per_second_opened) can be
    scored on new snapshot data.
    """
    base = features_http(conn_state, http, now)
    ctx = ip_context(conn_state, now, entity, window)
    merged = {**base, **ctx}
    return {k: merged.get(k, 0.0) for k in LEGACY_FEATURE_ORDER}


# ---------------------------------------------------------------------------
# WindowTracker (unchanged: tracks connect/close intervals per IP)
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Backwards-compatible aliases (old names, deprecated)
# ---------------------------------------------------------------------------
def flow_features(rec: dict, now: float) -> dict:
    """Deprecated: use features() or features_http()."""
    return features(rec, now)


def open_flow_features(rec: dict, http: dict, now: float) -> dict:
    """Deprecated: use features_http()."""
    base = features_http(rec, http, now)
    ctx = {"concurrent_conns": 0.0, "conns_per_second_opened": 0.0,
           "stalled_fraction": 0.0}
    merged = {**base, **ctx}
    out = {}
    for k in LEGACY_FEATURE_ORDER:
        out[k] = merged.get(k, 0.0)
    out["is_open"] = 1.0 if (rec.get("t_close") is None or now < (rec.get("t_close") or 0)) else 0.0
    out["time_to_first_byte"] = 0.0
    out["header_frac_sent"] = base["header_complete"]
    out["bytes_out"] = float(rec.get("bwd_bytes", 0))
    out["bytes_out_per_s"] = 0.0
    out["syn_retries"] = float(rec.get("syn_retries", 0))
    out["bytes_in_ratio"] = 0.0
    return out


def build_features(rec: dict, http: dict, window: WindowTracker,
                   entity: str, now: float) -> dict:
    """Deprecated: use legacy_features() for the old model or
    features_http() + ip_context() for the new split."""
    return legacy_features(rec, http, window, entity, now)


def vectorise(f: dict, order: list | None = None) -> list[float]:
    order = order or FEATURE_ORDER
    return [float(f.get(k, 0.0)) for k in order]


def group_of(name: str) -> str:
    if name in BASE_FEATURES:
        return "base"
    if name in IPCONTEXT_FEATURES:
        return "ip_context"
    return "other"
