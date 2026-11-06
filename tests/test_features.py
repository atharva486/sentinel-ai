"""Unit tests for capture/features.py feature engineering (Phase 2).

Covers:
- base vs ip_context feature groups are disjoint and cover FEATURE_ORDER
- group_of returns base / ip_context / other
- vectorise returns 15 elements for the new base order
- legacy_features (16 features) works for scoring the old model
- features_http computes correct per-connection values
- base features computable WITHOUT ip_context columns (acceptance C)
- burst-then-silent: falling bytes_in_per_s, rising idle_s (acceptance 2)
"""
import math
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from capture.features import (
    BASE_FEATURES, IPCONTEXT_FEATURES, LEGACY_FEATURE_ORDER,
    FEATURE_ORDER, EXCLUDED,
    features, features_http, ip_context, legacy_features,
    WindowTracker, vectorise, group_of,
)


def test_base_and_ipcontext_disjoint():
    """BASE_FEATURES and IPCONTEXT_FEATURES must not overlap."""
    assert BASE_FEATURES & IPCONTEXT_FEATURES == set(), \
        f"overlap: {BASE_FEATURES & IPCONTEXT_FEATURES}"


def test_feature_order_is_base_only():
    """FEATURE_ORDER lists exactly the base per-connection features (15)."""
    assert set(FEATURE_ORDER) == BASE_FEATURES, \
        f"mismatch: {set(FEATURE_ORDER) ^ BASE_FEATURES}"
    assert len(FEATURE_ORDER) == 15


def test_group_of():
    """group_of returns base / ip_context / other."""
    for name in FEATURE_ORDER:
        assert group_of(name) == "base", f"{name} should be base"
    for name in IPCONTEXT_FEATURES:
        assert group_of(name) == "ip_context", f"{name} should be ip_context"
    assert group_of("nonexistent") == "other"


def test_vectorise_returns_15_elements():
    """vectorise over FEATURE_ORDER returns 15 floats."""
    fs = {"t_first": 0.0, "t_last": 10.0, "t_close": None,
          "fwd_bytes": 1000, "bwd_bytes": 0, "fwd_pkts": 10,
          "bwd_pkts": 0, "fwd_times": [1.0, 2.0, 4.0],
          "n_requests_seen": 5, "client_ip": "10.0.0.1",
          "flow_id": "f1"}
    http = {"header_complete": True, "header_bytes": 200, "declared_body": 0}
    f = features_http(fs, http, 10.0)
    vec = vectorise(f)
    assert len(vec) == 15, f"Expected 15 elements, got {len(vec)}"


def test_legacy_features_returns_16_elements():
    """legacy_features returns the old 16-feature vector for the old model."""
    fs = {"t_first": 0.0, "t_last": 10.0, "t_close": None,
          "fwd_bytes": 1000, "bwd_bytes": 0, "fwd_pkts": 10,
          "bwd_pkts": 0, "fwd_times": [1.0, 2.0, 4.0],
          "n_requests_seen": 5, "client_ip": "10.0.0.1",
          "flow_id": "f1"}
    http = {"header_complete": True, "header_bytes": 200, "declared_body": 0}
    win = WindowTracker(window_s=10.0)
    f = legacy_features(fs, http, win, "10.0.0.1", 10.0)
    assert len(f) == 16, f"Expected 16 elements, got {len(f)}"
    for k in LEGACY_FEATURE_ORDER:
        assert k in f, f"Missing legacy key {k}"


def test_base_computable_without_ipcontext():
    """Base per-connection score can be computed with ip_context columns
    completely absent (acceptance C)."""
    fs = {"t_first": 0.0, "t_last": 5.0, "t_close": None,
          "fwd_bytes": 500, "bwd_bytes": 0, "fwd_pkts": 5,
          "bwd_pkts": 0, "fwd_times": [1.0, 3.0],
          "n_requests_seen": 3, "client_ip": "10.0.0.1",
          "flow_id": "f1"}
    http = {"header_complete": False, "header_bytes": 150, "declared_body": 0}
    # features_http needs NO window tracker, no entity, no stalled_ips
    f = features_http(fs, http, 10.0)
    for k in BASE_FEATURES:
        assert k in f, f"Missing base key {k}"
    # ip_context keys must NOT appear in base output
    for k in IPCONTEXT_FEATURES:
        assert k not in f, f"ip_context key {k} leaked into base output"
    # ip_context() itself can be called independently (returns zeros if no
    # stalled info)
    ctx = ip_context(fs, 10.0, "10.0.0.1", WindowTracker(window_s=10.0))
    for k in IPCONTEXT_FEATURES:
        assert k in ctx


def test_features_http_stall_and_body():
    """features_http computes stall_time, body_frac, drip correctly."""
    fs = {"t_first": 0.0, "t_last": 10.0, "t_close": None,
          "fwd_bytes": 500, "bwd_bytes": 0, "fwd_pkts": 5,
          "bwd_pkts": 0, "fwd_times": [1.0, 5.0],
          "n_requests_seen": 2, "client_ip": "10.0.0.1",
          "flow_id": "f1"}

    # Incomplete header -> stall_time == age
    http = {"header_complete": False, "header_bytes": 100, "declared_body": 0}
    f = features_http(fs, http, 10.0)
    assert f["stall_time_s"] == 10.0, f"stall_time should be age=10, got {f['stall_time_s']}"
    assert f["header_complete"] == 0.0

    # Complete header, no body -> stall_time == 0
    http = {"header_complete": True, "header_bytes": 200, "declared_body": 0}
    f = features_http(fs, http, 10.0)
    assert f["stall_time_s"] == 0.0
    assert f["header_complete"] == 1.0

    # Complete header, body incomplete -> stall_time == age
    http = {"header_complete": True, "header_bytes": 200, "declared_body": 1000}
    f = features_http(fs, http, 10.0)
    assert f["stall_time_s"] == 10.0
    assert f["body_frac_sent"] == 0.3  # (500-200)/1000


def test_burst_then_silent_falling_rate_rising_idle():
    """A burst-then-silent connection has falling bytes_in_per_s and
    rising idle_s as ``now`` advances (acceptance 2)."""
    fs_base = {"t_first": 0.0, "t_last": 2.0, "t_close": None,
               "fwd_bytes": 10000, "bwd_bytes": 0, "fwd_pkts": 10,
               "bwd_pkts": 0, "fwd_times": [0.1, 0.2, 0.3, 0.4, 0.5,
                                            0.6, 0.7, 0.8, 0.9, 1.0],
               "n_requests_seen": 1, "client_ip": "10.0.0.1",
               "flow_id": "burst-silent"}
    http = {"header_complete": True, "header_bytes": 200, "declared_body": 0}

    # At now=5s (3s silent): bytes_in_per_s = 10000/5 = 2000, idle_s = 3
    f5 = features_http(fs_base, http, 5.0)
    # At now=20s (18s silent): bytes_in_per_s = 10000/20 = 500, idle_s = 18
    f20 = features_http(fs_base, http, 20.0)

    assert f20["bytes_in_per_s"] < f5["bytes_in_per_s"], \
        f"bytes_in_per_s should fall: {f5['bytes_in_per_s']} -> {f20['bytes_in_per_s']}"
    assert f20["idle_s"] > f5["idle_s"], \
        f"idle_s should rise: {f5['idle_s']} -> {f20['idle_s']}"
    assert f5["idle_s"] == 3.0
    assert f20["idle_s"] == 18.0
    assert abs(f5["bytes_in_per_s"] - 2000.0) < 1e-6
    assert abs(f20["bytes_in_per_s"] - 500.0) < 1e-6


def test_denominator_is_now_minus_t_first_not_t_last_minus_t_first():
    """Rates use (now - t_first) so a silent connection's rate decays."""
    fs = {"t_first": 0.0, "t_last": 1.0, "t_close": None,
          "fwd_bytes": 1000, "bwd_bytes": 0, "fwd_pkts": 1,
          "bwd_pkts": 0, "fwd_times": [0.5],
          "n_requests_seen": 1, "client_ip": "10.0.0.1",
          "flow_id": "f1"}
    http = {"header_complete": True, "header_bytes": 200, "declared_body": 0}
    # Old (buggy) formula: t_last - t_first = 1 -> 1000/1 = 1000
    # New formula: now - t_first = 10 -> 1000/10 = 100
    f = features_http(fs, http, 10.0)
    assert abs(f["bytes_in_per_s"] - 100.0) < 1e-6, \
        f"Expected 1000/(10-0)=100, got {f['bytes_in_per_s']}"


def test_as_of_header_completeness():
    """header_complete/body_frac_sent/stall_time_s are as-of values.

    Slowloris flow: header never completes → header_complete=0 at every as_of.
    Benign flow: header completes at t=3 → header_complete=0 at as_of=1,2 and
    1 at as_of=5.  At intermediate as_of times only the payload received by
    that time is parsed (no final-state leakage).
    """
    base_conn = {"t_first": 0.0, "t_last": 0.0, "t_close": None,
                 "fwd_bytes": 0, "bwd_bytes": 0, "fwd_pkts": 0,
                 "bwd_pkts": 0, "fwd_times": [],
                 "n_requests_seen": 0, "client_ip": "10.0.0.1",
                 "flow_id": "test"}

    # --- Slowloris: header never complete at any as_of ---
    for as_of in (1.0, 5.0, 20.0):
        conn = dict(base_conn)
        conn["t_last"] = as_of
        conn["fwd_bytes"] = 500  # partial header, no \r\n\r\n
        conn["fwd_times"] = [as_of * 0.5]
        http = {"header_complete": False, "header_bytes": 500, "declared_body": 0}
        f = features_http(conn, http, as_of)
        assert f["header_complete"] == 0.0, \
            f"slowloris as_of={as_of}: header_complete should be 0, got {f['header_complete']}"
        assert f["stall_time_s"] == as_of, \
            f"slowloris as_of={as_of}: stall_time should be age={as_of}, got {f['stall_time_s']}"

    # --- Benign: header incomplete at as_of=1,2; complete at as_of=5 ---
    # Header is 200 bytes, completes at t=3. Body declared 1000, partially sent.
    conn1 = dict(base_conn)
    conn1["t_last"] = 1.0
    conn1["fwd_bytes"] = 50  # partial header only
    conn1["fwd_times"] = [0.5]
    http1 = {"header_complete": False, "header_bytes": 50, "declared_body": 1000}
    f1 = features_http(conn1, http1, 1.0)
    assert f1["header_complete"] == 0.0, f"benign as_of=1: header_complete should be 0"
    assert f1["stall_time_s"] == 1.0, f"benign as_of=1: stall_time should be age=1"
    assert f1["body_frac_sent"] == 0.0, f"benign as_of=1: body_frac should be 0 (no body yet)"

    conn2 = dict(base_conn)
    conn2["t_last"] = 2.0
    conn2["fwd_bytes"] = 150  # still partial header
    conn2["fwd_times"] = [0.5, 1.5]
    http2 = {"header_complete": False, "header_bytes": 150, "declared_body": 1000}
    f2 = features_http(conn2, http2, 2.0)
    assert f2["header_complete"] == 0.0, f"benign as_of=2: header_complete should be 0"
    assert f2["stall_time_s"] == 2.0, f"benign as_of=2: stall_time should be age=2"

    conn5 = dict(base_conn)
    conn5["t_last"] = 5.0
    conn5["fwd_bytes"] = 700  # header (200) + 500 body bytes
    conn5["fwd_times"] = [0.5, 1.0, 2.5, 4.0]
    http5 = {"header_complete": True, "header_bytes": 200, "declared_body": 1000}
    f5 = features_http(conn5, http5, 5.0)
    assert f5["header_complete"] == 1.0, f"benign as_of=5: header_complete should be 1"
    assert f5["stall_time_s"] == 5.0, f"benign as_of=5: body incomplete → stall_time=age=5"
    assert f5["body_frac_sent"] == 0.5, f"benign as_of=5: body_frac should be 0.5 (500/1000)"
    assert f5["body_drip_rate_bps"] == 100.0, f"benign as_of=5: drip should be 500/5=100"


def test_final_lifetime_one_row_per_flow():
    """Each flow contributes one row at its final lifetime (acceptance 4)."""
    conn = {"t_first": 0.0, "t_last": 42.0, "t_close": 42.0,
            "fwd_bytes": 1000, "bwd_bytes": 0, "fwd_pkts": 5,
            "bwd_pkts": 0, "fwd_times": [1.0, 5.0, 10.0],
            "n_requests_seen": 3, "client_ip": "10.0.0.1",
            "flow_id": "final-flow"}
    http = {"header_complete": True, "header_bytes": 200, "declared_body": 0}
    f = features_http(conn, http, 42.0)
    assert f["conn_age_s"] == 42.0, f"final age should be flow lifetime=42"
    assert f["idle_s"] == 0.0, f"final idle_s should be 0 (closed flow)"
    assert f["stall_time_s"] == 0.0, f"final stall_time should be 0 (header complete)"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
