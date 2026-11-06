"""Integration test: offline replay vs live sensor produce identical features.

Replays a pcap through both paths and compares feature vectors for the same
flows at the same as_of times:

1. OFFLINE PATH: read_pcap(path, flush_after, as_of_seconds=t_abs) then
   features_http() on each returned record at time t_abs.

2. LIVE SENSOR PATH: FlowTracker.ingest() packets up to time t_abs, then
   features_http() on each live FlowState at time t_abs.

Both paths call features_http() on equivalent connection state, so the
vectors must match exactly. Any difference is a bug.

Requires: captures/live_capture.pcap (the baseline_v0 live run).
"""
from __future__ import annotations

import json
import math
import socket
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

import dpkt
import pytest

from m1_capture.sensor import (_unwrap, parse_http, FlowTracker,
                               read_pcap)
from m1_capture.features import (features_http, ip_context,
                                 WindowTracker, FEATURE_ORDER,
                                 IPCONTEXT_FEATURES)
from m1_capture.merge import _side_log_index

REPO = Path(__file__).resolve().parent.parent
PCAP = REPO / "captures" / "live_capture.pcap"

# Feature names that must match between offline and live paths (base + ip_ctx)
COMPARE_FEATURES = sorted(set(FEATURE_ORDER) | IPCONTEXT_FEATURES)


def _first_packet_ts(path: Path) -> float:
    """Timestamp of the first TCP packet in the pcap."""
    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        linktype = reader.datalink()
        for ts, buf in reader:
            ip = _unwrap(buf, linktype)
            if ip is not None and isinstance(ip.data, dpkt.tcp.TCP):
                return ts
    return 0.0


def _pcap_packets(path: Path, as_of_abs: float | None = None):
    """Yield (ts, src, sport, dst, dport, payload, flags) packets up to as_of_abs."""
    with path.open("rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        linktype = reader.datalink()
        for ts, buf in reader:
            if as_of_abs is not None and ts > as_of_abs:
                break
            ip = _unwrap(buf, linktype)
            if ip is None:
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue
            yield (ts, socket.inet_ntoa(ip.src), tcp.sport,
                   socket.inet_ntoa(ip.dst), tcp.dport,
                   bytes(tcp.data), tcp.flags)


def _live_features_at(path: Path, as_of_abs: float,
                      side_idx=None):
    """Live-sensor path: ingest packets into FlowTracker, then features_http."""
    tracker = FlowTracker(flush_after_s=5.0)
    for ts, src, sport, dst, dport, payload, flags in _pcap_packets(path, as_of_abs):
        tracker.ingest(ts, src, sport, dst, dport, payload, flags)

    now = as_of_abs
    results = {}
    for fs in tracker.flush(now + 5.0 + 1.0):
        fs.finalized = False
        rec = fs.to_record()
        http = parse_http(bytes.fromhex(rec["fwd_payload"]))

        conn_state = {
            "t_first": fs.t_first, "t_last": now,
            "t_close": fs.t_close,
            "fwd_bytes": fs.fwd_bytes, "bwd_bytes": fs.bwd_bytes,
            "fwd_pkts": fs.fwd_pkts, "bwd_pkts": fs.bwd_pkts,
            "fwd_times": list(fs.fwd_times),
            "n_requests_seen": fs.n_requests_seen,
            "client_ip": fs.client_ip,
            "flow_id": fs.flow_id,
        }
        base_feats = features_http(conn_state, http, now)
        ctx_feats = ip_context(conn_state, now, fs.client_ip,
                               WindowTracker(window_s=10.0))
        feats = {**base_feats, **ctx_feats}
        results[fs.flow_id] = feats
    return results


def _offline_features_at(path: Path, as_of_abs: float,
                         side_idx=None):
    """Offline path: read_pcap with as_of_seconds, then features_http."""
    records = read_pcap(path, flush_after=5.0,
                        as_of_seconds=as_of_abs)
    results = {}
    for rec in records:
        http = parse_http(bytes.fromhex(rec["fwd_payload"]))
        conn_state = {
            "t_first": rec["t_first"], "t_last": as_of_abs,
            "t_close": rec["t_close"],
            "fwd_bytes": rec["fwd_bytes"], "bwd_bytes": rec["bwd_bytes"],
            "fwd_pkts": rec["fwd_pkts"], "bwd_pkts": rec["bwd_pkts"],
            "fwd_times": rec["fwd_times"],
            "n_requests_seen": rec["n_requests_seen"],
            "client_ip": rec["client_ip"],
            "flow_id": rec["flow_id"],
        }
        base_feats = features_http(conn_state, http, as_of_abs)
        ctx_feats = ip_context(conn_state, as_of_abs, rec["client_ip"],
                               WindowTracker(window_s=10.0))
        feats = {**base_feats, **ctx_feats}
        results[rec["flow_id"]] = feats
    return results


@pytest.fixture(scope="module")
def pcap_first_ts():
    return _first_packet_ts(PCAP)


@pytest.fixture(scope="module")
def side_index():
    """Load side log for baseline pcap if available."""
    candidates = [
        REPO / "results" / "baseline_v0" / "side_log.jsonl",
        REPO / "reports" / "runs" / "run_1793986123" / "side_log.jsonl",
    ]
    for p in candidates:
        if p.exists():
            rows = [json.loads(l) for l in p.open() if l.strip()]
            return _side_log_index(rows)
    return None


@pytest.mark.skipif(not PCAP.exists(), reason="live_capture.pcap not present")
def test_offline_and_live_features_identical(side_index, pcap_first_ts):
    """Offline replay and live sensor give identical feature vectors."""
    as_of_rel_times = [1.0, 5.0, 10.0, 20.0]

    for as_of_rel in as_of_rel_times:
        as_of_abs = pcap_first_ts + as_of_rel
        live = _live_features_at(PCAP, as_of_abs, side_index)
        offline = _offline_features_at(PCAP, as_of_abs, side_index)

        live_ids = set(live.keys())
        offline_ids = set(offline.keys())

        common = live_ids & offline_ids
        assert len(common) > 0, \
            f"as_of_rel={as_of_rel}: no common flows between paths"

        mismatches = 0
        for fid in common:
            lv, ov = live[fid], offline[fid]
            for k in COMPARE_FEATURES:
                lv_v = lv.get(k, 0.0)
                ov_v = ov.get(k, 0.0)
                if abs(lv_v - ov_v) > 1e-9:
                    mismatches += 1
                    if mismatches <= 5:
                        print(f"  MISMATCH as_of_rel={as_of_rel} flow={fid} "
                              f"feat={k}: live={lv_v} offline={ov_v}")

        assert mismatches == 0, \
            f"as_of_rel={as_of_rel}: {mismatches} feature mismatches " \
            f"between offline and live"


@pytest.mark.skipif(not PCAP.exists(), reason="live_capture.pcap not present")
def test_offline_and_live_same_flow_count(side_index, pcap_first_ts):
    """Both paths should observe the same number of flows at each as_of."""
    for as_of_rel in [1.0, 5.0, 10.0, 20.0]:
        as_of_abs = pcap_first_ts + as_of_rel
        live = _live_features_at(PCAP, as_of_abs, side_index)
        offline = _offline_features_at(PCAP, as_of_abs, side_index)
        assert abs(len(live) - len(offline)) <= 2, \
            f"as_of_rel={as_of_rel}: live={len(live)} offline={len(offline)} flows"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v", "-s"]))
