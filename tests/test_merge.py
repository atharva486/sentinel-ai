"""Unit tests for capture/merge.py label generation (labels off the wire).

Labels come from the per-connection side log written by gen/generate.py, joined
to flow records on (src_ip, src_port, time overlap).  The IP-prefix fallback and
the X-Ground-Truth header are removed.
"""
import json
import pandas as pd
import numpy as np
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from capture.merge import label_generated, load_side_log, VALID_ROLES


def _write_flow(path, flow_id, client_ip, client_port, t_first, t_last,
                t_close=None, fwd_bytes=100, fwd_pkts=1, fwd_times=None,
                payload=b"GET /api/txn HTTP/1.1\r\nHost: api\r\n\r\n"):
    if fwd_times is None:
        fwd_times = [t_first + 0.1, t_first + 0.2]
    rec = {
        "flow_id": flow_id,
        "client_ip": client_ip,
        "client_port": client_port,
        "server_ip": "172.18.0.1",
        "server_port": 80,
        "t_first": t_first,
        "t_last": t_last,
        "t_close": t_close,
        "fwd_bytes": fwd_bytes,
        "fwd_pkts": fwd_pkts,
        "bwd_bytes": 50,
        "bwd_pkts": 1,
        "fwd_times": fwd_times,
        "fwd_payload": payload.hex(),
        "bwd_payload": b"".hex(),
        "syn_retries": 0,
        "closed_by": "",
        "finalized": t_close is not None,
        "n_requests_seen": 1,
        "t_first_bwd": 0.0,
    }
    with path.open("a") as f:
        f.write(json.dumps(rec) + "\n")


def _write_side_log(path, rows):
    with path.open("w") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


def test_valid_roles():
    """VALID_ROLES contains the two classes the side log can emit."""
    assert VALID_ROLES == ("benign", "attack")


def test_load_side_log_reads_rows(tmp_path):
    """load_side_log reads per-connection rows."""
    p = tmp_path / "side.jsonl"
    _write_side_log(p, [
        {"src_ip": "10.0.0.1", "src_port": 50001, "start_ts": 0.0, "end_ts": 10.0,
         "role": "benign", "attack_type": "benign"},
        {"src_ip": "10.0.0.2", "src_port": 50002, "start_ts": 5.0, "end_ts": 100.0,
         "role": "attack", "attack_type": "slowloris"},
    ])
    rows = load_side_log(p)
    assert len(rows) == 2
    assert rows[0]["role"] == "benign"
    assert rows[1]["attack_type"] == "slowloris"


def test_side_log_join_covers_matched_flows(tmp_path):
    """Joined flows get role/attack_type/y from the side log."""
    flows = tmp_path / "flows.jsonl"
    side = tmp_path / "side.jsonl"
    _write_side_log(side, [
        {"src_ip": "10.0.0.1", "src_port": 50001, "start_ts": 0.0, "end_ts": 10.0,
         "role": "benign", "attack_type": "benign"},
        {"src_ip": "10.0.0.2", "src_port": 50002, "start_ts": 5.0, "end_ts": 100.0,
         "role": "attack", "attack_type": "slowloris"},
    ])
    # Flow 1 overlaps side-log row 1 (same ip:port, time overlap) -> benign.
    _write_flow(flows, "f1", "10.0.0.1", 50001, 1.0, 9.0, t_close=9.0)
    # Flow 2 overlaps side-log row 2 -> attack slowloris.
    _write_flow(flows, "f2", "10.0.0.2", 50002, 10.0, 90.0, t_close=90.0)

    df = label_generated(flows, side)
    assert not df.empty
    assert set(df.columns) >= {"role", "attack_type", "y", "entity", "flow_id"}
    f1 = df[df.flow_id == "f1"]
    f2 = df[df.flow_id == "f2"]
    assert len(f1) >= 1 and len(f2) >= 1
    assert (f1.role == "benign").all() and (f1.y == 0).all()
    assert (f2.role == "attack").all() and (f2.y == 1).all()
    assert (f2.attack_type == "slowloris").all()


def test_unlabelled_flow_excluded_and_listed(tmp_path):
    """A flow with no side-log match is excluded but listed in _unlabelled."""
    flows = tmp_path / "flows.jsonl"
    side = tmp_path / "side.jsonl"
    _write_side_log(side, [
        {"src_ip": "10.0.0.1", "src_port": 50001, "start_ts": 0.0, "end_ts": 10.0,
         "role": "benign", "attack_type": "benign"},
    ])
    # f1 matches; f2 has same ip but no port/time match -> unlabelled.
    _write_flow(flows, "f1", "10.0.0.1", 50001, 1.0, 9.0, t_close=9.0)
    _write_flow(flows, "f2", "10.0.0.9", 59999, 1.0, 9.0, t_close=9.0)

    df = label_generated(flows, side)
    by_id = df.set_index("flow_id") if not df.empty else df
    assert "f1" in by_id.index
    assert "f2" not in by_id.index
    unlabelled = df.attrs.get("unlabelled", [])
    assert "f2" in unlabelled, f"f2 should be listed unlabelled, got {unlabelled}"


def test_no_side_log_yields_no_labels(tmp_path):
    """Without a side log, no flow can be labelled (no IP-prefix fallback)."""
    flows = tmp_path / "flows.jsonl"
    _write_flow(flows, "f1", "10.0.0.1", 50001, 1.0, 9.0, t_close=9.0)
    df = label_generated(flows, None)
    assert df.empty, "Expected no labelled flows without a side log"


def test_join_coverage_reported(tmp_path, capsys):
    """Join coverage % is computable and unlabelled flows are listed."""
    flows = tmp_path / "flows.jsonl"
    side = tmp_path / "side.jsonl"
    _write_side_log(side, [
        {"src_ip": "10.0.0.1", "src_port": 50001, "start_ts": 0.0, "end_ts": 10.0,
         "role": "benign", "attack_type": "benign"},
        {"src_ip": "10.0.0.2", "src_port": 50002, "start_ts": 5.0, "end_ts": 100.0,
         "role": "attack", "attack_type": "flood"},
    ])
    _write_flow(flows, "f1", "10.0.0.1", 50001, 1.0, 9.0, t_close=9.0)
    _write_flow(flows, "f2", "10.0.0.2", 50002, 10.0, 90.0, t_close=90.0)
    _write_flow(flows, "f3", "10.0.0.3", 50003, 1.0, 9.0, t_close=9.0)  # no match

    df = label_generated(flows, side)
    total = 3
    labelled_flows = df.flow_id.nunique() if not df.empty else 0
    coverage = 100.0 * labelled_flows / total
    print(f"JOIN COVERAGE: {labelled_flows}/{total} = {coverage:.1f}%")
    print(f"UNLABELLED: {df.attrs.get('unlabelled', [])}")
    assert coverage == 100.0 * 2 / 3
    assert "f3" in df.attrs.get("unlabelled", [])


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v", "-s"]))
