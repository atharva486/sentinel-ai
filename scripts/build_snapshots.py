#!/usr/bin/env python3
"""Build per-flow snapshot datasets at decision times as_of = 1,2,3,5,10,20,final.

Replays each pcap once, recording per-flow packet events with correct
client/server direction (from the SYN).  Then extracts real features at each
as_of time (relative to that flow's t_first) by filtering that flow's packets.
No linear scaling or simulated values.

Outputs a Parquet with one row per (flow, as_of) snapshot, including flow_id
so rows from one flow stay in the same split, plus a label_source column:

  - "side_log"  : live_capture.pcap, joined to results/baseline_v0/side_log.jsonl
  - "legacy"    : runA..runG pcaps, labelled by pre-Phase-1 mechanism.  Never
                  mixed with side_log labels in one metric.

Usage:
    python3 scripts/build_snapshots.py
"""

from __future__ import annotations

import re
import socket
from collections import defaultdict
from pathlib import Path

import dpkt
import pandas as pd

sys_path = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(sys_path))

from m1_capture.sensor import _unwrap, parse_http
from m1_capture.features import (
    features_http, ip_context, FEATURE_ORDER,
    IPCONTEXT_FEATURES, WindowTracker,
)
from m1_capture.merge import load_side_log, _side_log_index, _match_side_log

REPO = Path(__file__).resolve().parent.parent
CAPTURES = REPO / "captures"
RUNS = REPO / "reports" / "runs"
OUT = REPO / "data" / "features_snapshots.parquet"

AS_OF_SECONDS = [1.0, 2.0, 3.0, 5.0, 10.0, 20.0]
PAYLOAD_CAP = 65536


def find_matching_side_log(pcap_path: Path) -> Path | None:
    """Find the side_log whose time range overlaps with the pcap.

    Returns the side_log.jsonl path for the run directory whose start/end
    timestamps overlap with the pcap's first/last packet timestamps.
    """
    # Get pcap time range
    pcap_first = None
    pcap_last = None
    with pcap_path.open("rb") as fh:
        try:
            reader = dpkt.pcap.Reader(fh)
        except (ValueError, dpkt.dpkt.UnpackError):
            return None
        for ts, buf in reader:
            if pcap_first is None:
                pcap_first = ts
            pcap_last = ts

    if pcap_first is None:
        return None

    # Check each run directory
    if not RUNS.exists():
        return None
    for run_dir in sorted(RUNS.iterdir()):
        side_log = run_dir / "side_log.jsonl"
        if not side_log.exists():
            continue
        try:
            import json
            rows = [json.loads(l) for l in side_log.open() if l.strip()]
            if not rows:
                continue
            sl_first = min(r["start_ts"] for r in rows)
            sl_last = max(r["end_ts"] for r in rows)
            # Check overlap
            if sl_first <= pcap_last + 5 and sl_last >= pcap_first - 5:
                return side_log
        except Exception:
            continue
    return None

# --- Legacy labeling (historical data only; never used for new traffic) ---
# These are the pre-Phase-1 mappings, used solely to label old pcaps as
# "legacy_label".  New traffic is labelled exclusively via the side log.
LEGACY_CONTAINER_ROLE = {
    "172.18.0.5": "benign",
    "172.18.0.6": "attack",
    "172.18.0.7": "attack",
}
LEGACY_BENIGN_PREFIXES = (
    "172.18.15.", "172.18.25.", "172.18.35.", "172.18.45.",
)
LEGACY_ATTACK_PREFIXES = (
    "172.18.16.", "172.18.26.", "172.18.36.", "172.18.46.",
    "172.18.17.", "172.18.27.", "172.18.37.", "172.18.47.",
)


def _legacy_role_for_ip(ip: str) -> str | None:
    if ip in LEGACY_CONTAINER_ROLE:
        return LEGACY_CONTAINER_ROLE[ip]
    for p in LEGACY_BENIGN_PREFIXES:
        if ip.startswith(p):
            return "benign"
    for p in LEGACY_ATTACK_PREFIXES:
        if ip.startswith(p):
            return "attack"
    return None


_GT_RE = re.compile(rb"X-Ground-Truth:\s*(\S+)")


def _legacy_label_from_payload(fwd_payload: bytes) -> str | None:
    """Extract X-Ground-Truth from historical payload (legacy only)."""
    m = _GT_RE.search(fwd_payload)
    if m:
        gt = m.group(1).decode("latin-1", errors="replace").lower()
        if gt in ("benign", "slow", "flood"):
            return "benign" if gt == "benign" else "attack"
    return None


def label_legacy(fwd_payload: bytes, client_ip: str) -> tuple[str, str, str]:
    """Return (role, attack_type, label_source) for a legacy flow.

    Tries X-Ground-Truth header first, then IP-prefix fallback.
    Never used for new traffic — only for labelling old pcaps.
    """
    gt_role = _legacy_label_from_payload(fwd_payload)
    if gt_role is not None:
        at = "benign" if gt_role == "benign" else "slowloris"
        return gt_role, at, "legacy_label"
    ip_role = _legacy_role_for_ip(client_ip)
    if ip_role is not None:
        at = "benign" if ip_role == "benign" else "slowloris"
        return ip_role, at, "legacy_label"
    return "legacy", "legacy", "legacy_label"


def load_side_truth():
    rows = load_side_log(SIDE_LOG)
    return _side_log_index(rows)


def _norm_key(src, sport, dst, dport):
    a, b = (src, sport), (dst, dport)
    return (a, b) if a <= b else (b, a)


def replay_pcap(pcap_path, side_idx, is_baseline):
    """Replay one pcap, returning snapshot rows for all flows.

    Single pass: record per-flow packet events, determine client/server from
    the first SYN, then compute features at each as_of time by filtering.
    """
    # flow_key -> list of (ts, direction, payload_bytes, flags)
    flow_events: dict[tuple, list] = defaultdict(list)
    # flow_key -> client metadata (from first SYN)
    flow_client: dict[tuple, dict] = {}
    # flow_key -> t_close
    flow_close: dict[tuple, float | None] = {}

    with pcap_path.open("rb") as fh:
        try:
            reader = dpkt.pcap.Reader(fh)
        except (ValueError, dpkt.dpkt.UnpackError):
            return []
        linktype = reader.datalink()

        for ts, buf in reader:
            ip = _unwrap(buf, linktype)
            if ip is None or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            sport, dport = tcp.sport, tcp.dport
            flags = tcp.flags
            payload = bytes(tcp.data)

            key = _norm_key(src, sport, dst, dport)
            is_syn = bool(flags & 0x02) and not (flags & 0x10)

            if is_syn and key not in flow_client:
                # First SYN: src is client
                flow_client[key] = {
                    "client_ip": src, "client_port": sport,
                    "server_ip": dst, "server_port": dport,
                }

            # Determine direction
            meta = flow_client.get(key)
            if meta and src == meta["client_ip"] and sport == meta["client_port"]:
                direction = "fwd"
            else:
                direction = "bwd"

            # Truncate payload for storage
            if len(payload) > PAYLOAD_CAP:
                payload = payload[:PAYLOAD_CAP]

            flow_events[key].append({
                "ts": ts, "direction": direction,
                "payload": payload, "flags": flags,
            })

            if flags & 0x01 or flags & 0x04:  # FIN or RST
                flow_close[key] = ts

    # Build per-flow snapshots
    rows: list[dict] = []
    for key, events in flow_events.items():
        events.sort(key=lambda e: e["ts"])
        t_first = events[0]["ts"]
        meta = flow_client.get(key)
        if meta is None:
            continue  # no SYN seen, skip

        t_close = flow_close.get(key)
        t_last = events[-1]["ts"]
        flow_age = (t_close - t_first) if t_close else (t_last - t_first)
        if flow_age <= 0:
            continue

        c_ip = meta["client_ip"]
        c_port = meta["client_port"]

        # Full fwd payload (all events) for legacy HTTP-header extraction
        fwd_payload = b"".join(
            e["payload"] for e in events if e["direction"] == "fwd"
        )

        # Label: side_log for baseline pcap, legacy_label for old pcaps
        if side_idx is not None and is_baseline:
            row = _match_side_log(side_idx, c_ip, c_port, t_first,
                                  t_close or t_last)
            if row is not None:
                role = row.get("role", "legacy")
                attack_type = row.get("attack_type", "legacy")
                label_source = "side_log"
            else:
                # Side log exists but no match for this flow → legacy fallback
                role, attack_type, label_source = label_legacy(fwd_payload, c_ip)
        else:
            # Legacy labeling from payload + IP prefix (historical data only)
            role, attack_type, label_source = label_legacy(fwd_payload, c_ip)

        # Which as_of times to compute
        as_of_times = list(AS_OF_SECONDS)
        if flow_age > max(AS_OF_SECONDS):
            as_of_times.append("final")
        else:
            as_of_times.append("final")

        for as_of in as_of_times:
            if as_of == "final":
                now = t_first + flow_age
                ev = events
            else:
                now = t_first + as_of
                if now > (t_close or t_last):
                    continue
                ev = [e for e in events if e["ts"] <= now]

            if not ev:
                continue

            fwd = [e for e in ev if e["direction"] == "fwd"]
            bwd = [e for e in ev if e["direction"] == "bwd"]
            fwd_bytes = sum(len(e["payload"]) for e in fwd)
            bwd_bytes = sum(len(e["payload"]) for e in bwd)
            fwd_pkts = len(fwd)
            bwd_pkts = len(bwd)
            fwd_times = [e["ts"] for e in fwd]

            # Reconstruct HTTP from concatenated fwd payload
            fwd_payload = b"".join(e["payload"] for e in fwd)
            http = parse_http(fwd_payload)

            conn_state = {
                "t_first": t_first, "t_last": now,
                "t_close": t_close if as_of == "final" else None,
                "fwd_bytes": fwd_bytes, "bwd_bytes": bwd_bytes,
                "fwd_pkts": fwd_pkts, "bwd_pkts": bwd_pkts,
                "fwd_times": fwd_times,
                "n_requests_seen": http.get("req_count", 0),
                "client_ip": c_ip,
                "flow_id": f"{c_ip}:{c_port}-{key[0][0]}:{key[0][1]}",
            }

            feats = features_http(conn_state, http, now)
            ctx = ip_context(conn_state, now, c_ip,
                             WindowTracker(window_s=10.0))

            rows.append({
                "flow_id": conn_state["flow_id"],
                "as_of": str(as_of),
                "as_of_seconds": float(as_of) if as_of != "final" else flow_age,
                "entity": c_ip,
                "client_port": c_port,
                "t_first": t_first,
                "t_now": now,
                "role": role,
                "attack_type": attack_type,
                "label_source": label_source,
                "y": 1 if role == "attack" else 0,
                **feats,
                **ctx,
            })

    return rows


def main():
    all_rows: list[dict] = []
    pcaps = sorted(CAPTURES.glob("*.pcap"))
    print(f"Found {len(pcaps)} pcaps")

    for pcap in pcaps:
        is_baseline = pcap.name == "live_capture.pcap"
        side_log_path = find_matching_side_log(pcap) if is_baseline else None
        side_idx = None
        if side_log_path:
            side_rows = load_side_log(side_log_path)
            side_idx = _side_log_index(side_rows)
            print(f"  Side log: {side_log_path} ({len(side_rows)} rows)")
        else:
            print(f"  Side log: NOT available (legacy labels)")
        print(f"Replaying {pcap.name} (baseline={is_baseline}, side_log={side_idx is not None}) ...")
        rows = replay_pcap(pcap, side_idx, is_baseline)
        print(f"  {len(rows):,} snapshot rows")
        all_rows.extend(rows)

    df = pd.DataFrame(all_rows)
    if df.empty:
        print("No snapshots produced.")
        return

    df.to_parquet(OUT, index=False)
    print(f"\nWrote {OUT}: {len(df):,} rows, {df.flow_id.nunique()} unique flows")
    print(f"Label sources: {df.label_source.value_counts().to_dict()}")
    print(f"as_of values: {sorted(df.as_of.unique(), key=str)}")
    print(f"y distribution: {df.y.value_counts().to_dict()}")


if __name__ == "__main__":
    main()
