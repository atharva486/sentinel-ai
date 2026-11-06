"""Unit tests for capture/features.py feature engineering."""
import pandas as pd
import numpy as np
from pathlib import Path

# Add repo to path
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from capture.features import (
    FEATURE_ORDER, STALL_FEATURES, RATE_FEATURES, CONCURRENCY_FEATURES,
    flow_features, open_flow_features, build_features, group_of,
    WindowTracker, vectorise
)


def test_feature_groups_cover_all_features():
    """All 16 features should belong to exactly one group."""
    all_features = set(FEATURE_ORDER)
    stall = set(STALL_FEATURES)
    rate = set(RATE_FEATURES)
    conc = set(CONCURRENCY_FEATURES)
    assert stall | rate | conc == all_features, "Groups don't cover all features"
    assert stall & rate == set(), "Stall and rate overlap"
    assert stall & conc == set(), "Stall and concurrency overlap"
    assert rate & conc == set(), "Rate and concurrency overlap"


def test_group_of():
    """group_of returns correct group for each feature."""
    for name in FEATURE_ORDER:
        g = group_of(name)
        assert g in ("stall", "rate", "concurrency", "other"), f"Unknown group {g} for {name}"
    # Test known features
    assert group_of("stall_time_s") == "stall"
    assert group_of("body_frac_sent") == "stall"
    assert group_of("header_complete") == "stall"
    assert group_of("bytes_in_per_s") == "rate"
    assert group_of("requests_per_s") == "rate"
    assert group_of("concurrent_conns") == "concurrency"
    assert group_of("conn_age_s") == "concurrency"


def test_feaure_order_length():
    """FEATURE_ORDER should have exactly 16 features."""
    assert len(FEATURE_ORDER) == 16


def test_vectorise_returns_16_elements():
    """vectorise should return a list of 16 floats."""
    rec = {"fwd_bytes": 100, "fwd_pkts": 1, "fwd_times": [1.0, 2.0], "t_first": 0, "t_last": 1,
           "n_requests_seen": 1, "syn_retries": 0, "bwd_bytes": 50, "bwd_pkts": 0, "bwd_payload": b"",
           "t_first_bwd": 0, "syn_retries": 0, "closed_by": "", "finalized": False,
           "client_ip": "172.18.1.1", "server_ip": "172.18.0.1", "server_port": 80,
           "client_port": 12345, "flow_id": "test", "t_close": None}
    vec = vectorise(rec)
    assert len(vec) == 16, f"Expected 16 elements, got {len(vec)}"


def test_build_features_returns_dict():
    """build_features should return a dict with all FEATURE_ORDER keys."""
    rec = {"fwd_bytes": 100, "fwd_pkts": 1, "fwd_times": [1.0, 2.0], "t_first": 0, "t_last": 1,
           "n_requests_seen": 1, "syn_retries": 0, "bwd_bytes": 50, "bwd_pkts": 0, "bwd_payload": b"",
           "t_first_bwd": 0, "syn_retries": 0, "closed_by": "", "finalized": False,
           "client_ip": "172.18.1.1", "server_ip": "172.18.0.1", "server_port": 80,
           "client_port": 12345, "flow_id": "test", "t_close": None}
    http = {"method": "GET", "path": "/", "header_complete": True, "header_bytes": 0,
            "declared_body": 0, "req_count": 1, "ground_truth": None}
    win = WindowTracker(window_s=10.0)
    feats = build_features(rec, http, win, "172.18.1.1", 10.0)
    for k in FEATURE_ORDER:
        assert k in feats, f"Missing key {k} in build_features output"


if __name__ == "__main__":
    test_feature_groups_cover_all_features()
    test_group_of()
    test_feaure_order_length()
    test_vectorise_returns_16_elements()
    test_build_features_returns_dict()
    print("All feature tests passed!")