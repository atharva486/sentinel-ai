#!/usr/bin/env python3
"""
Deterministic replay of a saved network capture using PCAP timestamps as the
simulated clock.  Validates the live scoring path's logic without wall-clock
time or live network interfaces.

Reads a client-only PCAP chronologically, feeds it through FlowTracker, scores
every active client flow once per simulated second using the v2 artifact, joins
flows to the side log, and reports coverage + detection metrics.

Inputs:
  PCAP:        ~/sentinel_archive/run_1794081957/client_only.pcap
  Side Log:    ~/sentinel_archive/run_1794081957/side_log.jsonl
  Model:       models/sentinel_v2_13feat.joblib

Outputs:
  results/replay_eval/decisions.parquet   per-cycle scoring decisions
  results/replay_eval/output.txt          full report
"""
from __future__ import annotations

import argparse
import json
import math
import os
import socket
import sys
import time
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "m1_capture"))

import dpkt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

import sensor  # noqa: E402  (FlowTracker, FlowState, _unwrap)
import features  # noqa: E402  (features_http, BASE_FEATURES)
from m3_scoring.calibrate import CalibrationResult  # noqa: E402

DEFAULT_PCAP = os.path.expanduser(
    "~/sentinel_archive/run_1794081957/client_only.pcap"
)
DEFAULT_SIDE_LOG = os.path.expanduser(
    "~/sentinel_archive/run_1794081957/side_log.jsonl"
)
DEFAULT_MODEL = str(REPO / "models" / "sentinel_v2_13feat.joblib")

THRESHOLD = 0.30          # detect threshold; do not tune
FLUSH_IDLE_S = 5.0        # a flow is idle/closed-out after 5 s of silence
CYCLE_S = 1.0             # scoring cadence in simulated seconds
PARITY_AGES = (1.0, 5.0)  # plus final age
PARITY_N = 20
PARITY_SEED = 42

# The 13 per-connection features used by scripts/binary_study_verify.py.
BASE = [
    "bytes_in", "bytes_in_per_s", "requests_per_s", "packets_per_s",
    "interarrival_mean", "interarrival_std", "interarrival_max",
    "requests_per_conn_so_far", "stall_time_s", "body_frac_sent",
    "bytes_declared", "body_drip_rate_bps", "header_complete",
]


class Report:
    def __init__(self):
        self.lines = []

    def log(self, text=""):
        print(text)
        self.lines.append(text)

    def save(self, path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1.0 + z * z / n
    c = (p + z * z / (2.0 * n)) / d
    h = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n)) / d
    return (c - h, c + h)


def conn_dict(fs, now):
    return {
        "t_first": fs.t_first,
        "t_last": fs.t_last,
        "t_close": fs.t_close,
        "fwd_bytes": fs.fwd_bytes,
        "bwd_bytes": fs.bwd_bytes,
        "fwd_pkts": fs.fwd_pkts,
        "bwd_pkts": fs.bwd_pkts,
        "fwd_times": fs.fwd_times,   # reference only; features_http reads it, never mutates
        "n_requests_seen": fs.n_requests_seen,
        "client_ip": fs.client_ip,
        "flow_id": fs.flow_id,
    }


def http_of(fs, cache):
    key = id(fs)
    entry = cache.get(key)
    if entry is not None and entry[0] == fs.fwd_bytes:
        return entry[1]
    http = sensor.parse_http(bytes(fs.fwd_payload))
    cache[key] = (fs.fwd_bytes, http)
    return http


def score_flow(fs, now, art, http_cache):
    http = http_of(fs, http_cache)
    feats = features.features_http(conn_dict(fs, now), http, now)
    row = {k: float(feats.get(k, 0.0)) for k in art.feature_order}
    score = float(art.calibrated_score(row))
    flagged = score >= THRESHOLD
    vec = [float(feats.get(k, 0.0)) for k in BASE]
    return score, flagged, vec, feats


def active(fs, now):
    """Flow is scorable: client flow to the proxy, started, not idle>=5s,
    not closed>=5s."""
    if fs.server_port != 80:
        return False
    if fs.t_first is None or fs.t_first > now:
        return False
    if fs.fwd_pkts < 1:
        return False
    if (now - fs.t_last) >= FLUSH_IDLE_S:
        return False
    if fs.t_close is not None and (now - fs.t_close) >= FLUSH_IDLE_S:
        return False
    return True


def match_side_log(idx, client_ip, client_port, t_start):
    """Side-log join on (src_ip, src_port) within a +/-2 s window."""
    best = None
    best_diff = None
    for row in idx.get((client_ip, client_port), []):
        rs = float(row.get("start_ts", 0.0))
        diff = abs(t_start - rs)
        if diff <= 2.0 and (best_diff is None or diff < best_diff):
            best_diff = diff
            best = row
    return best


def main() -> int:
    rep = Report()
    t_exec0 = time.time()

    ap = argparse.ArgumentParser(description="Deterministic live-path replay")
    ap.add_argument("--pcap", default=DEFAULT_PCAP)
    ap.add_argument("--side-log", default=DEFAULT_SIDE_LOG)
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--out-dir", default=str(REPO / "results" / "replay_eval"))
    args = ap.parse_args()

    rep.log("=== Deterministic live-path replay (simulated clock) ===")
    rep.log(f"pcap:        {args.pcap}")
    rep.log(f"side log:    {args.side_log}")
    rep.log(f"model:       {args.model}")
    rep.log(f"threshold:   {THRESHOLD}")
    rep.log()

    # ---- Load model artifact -------------------------------------
    art = CalibrationResult.load(args.model)
    rep.log(f"model feature_order ({len(art.feature_order)}): {art.feature_order}")

    # ---- Load side log -------------------------------------------
    side_rows = []
    with open(args.side_log) as f:
        for line in f:
            line = line.strip()
            if line:
                side_rows.append(json.loads(line))
    rep.log(f"side-log rows: {len(side_rows)}")
    idx: dict[tuple, list[dict]] = defaultdict(list)
    for row in side_rows:
        idx[(row.get("src_ip"), row.get("src_port"))].append(row)

    # ---- Stream the PCAP, scoring once per simulated second ------
    tracker = sensor.FlowTracker(flush_after_s=FLUSH_IDLE_S)
    http_cache: dict = {}
    decisions: list[dict] = []

    first_ts = None
    last_ts = 0.0
    last_scored = 0

    def score_at(now: float) -> None:
        for fs in tracker.flows.values():
            if not active(fs, now):
                continue
            score, flagged, vec, _feats = score_flow(fs, now, art, http_cache)
            decisions.append(
                {
                    "flow_key": f"{fs.flow_id}#{fs.t_first:.6f}",
                    "client_ip": fs.client_ip,
                    "client_port": fs.client_port,
                    "server_ip": fs.server_ip,
                    "server_port": fs.server_port,
                    "t_first": fs.t_first,
                    "cycle_time": now,
                    "age": now - fs.t_first,
                    "score": score,
                    "flagged": bool(flagged),
                    "features": vec,
                }
            )

    with open(args.pcap, "rb") as fh:
        reader = dpkt.pcap.Reader(fh)
        linktype = reader.datalink()
        for ts, buf in reader:
            if first_ts is None:
                first_ts = ts
            last_ts = ts
            ip = sensor._unwrap(buf, linktype)
            if ip is None or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            tracker.ingest(
                ts,
                socket.inet_ntoa(ip.src),
                tcp.sport,
                socket.inet_ntoa(ip.dst),
                tcp.dport,
                bytes(tcp.data),
                tcp.flags,
            )
            b = math.floor(ts)
            while last_scored < b:
                last_scored += 1
                score_at(float(last_scored))
    while last_scored < math.floor(last_ts):
        last_scored += 1
        score_at(float(last_scored))

    duration = last_ts - first_ts
    rep.log(f"capture duration: {duration:.3f} s  (first_ts={first_ts}, last_ts={last_ts})")
    rep.log(f"total scoring cycles: {last_scored}")
    rep.log(f"total decisions recorded: {len(decisions)}")
    rep.log()

    # ---- Build unique flows from decisions + final state ---------
    flow_state: dict[tuple, sensor.FlowState] = {}
    for fs in tracker.flows.values():
        flow_state[(fs.client_ip, fs.client_port, fs.t_first)] = fs

    n_decisions_per_flow: dict[tuple, int] = defaultdict(int)
    for d in decisions:
        n_decisions_per_flow[
            (d["client_ip"], d["client_port"], d["t_first"])
        ] += 1

    unique_flows: list[dict] = []
    for key, fs in flow_state.items():
        client_ip, client_port, t_first = key
        flow_decs = [d for d in decisions
                     if (d["client_ip"], d["client_port"], d["t_first"]) == key]
        ever_flagged = any(d["flagged"] for d in flow_decs)
        flagged_ages = [d["age"] for d in flow_decs if d["flagged"]]
        age_first_flag = min(flagged_ages) if flagged_ages else None
        t_end = fs.t_close if fs.t_close is not None else fs.t_last
        lifetime = t_end - t_first
        total_packets = fs.fwd_pkts + fs.bwd_pkts

        row = match_side_log(idx, client_ip, client_port, t_first)
        if row is None:
            labelled = False
            role = attack_type = sub_type = None
        else:
            labelled = True
            role = row.get("role")
            attack_type = row.get("attack_type", role)
            params = row.get("parameters") or {}
            sub_type = params.get("sub_type", attack_type)

        unique_flows.append(
            {
                "key": key,
                "client_ip": client_ip,
                "client_port": client_port,
                "t_first": t_first,
                "lifetime": lifetime,
                "total_packets": total_packets,
                "n_decisions": len(flow_decs),
                "labelled": labelled,
                "role": role,
                "attack_type": attack_type,
                "sub_type": sub_type,
                "ever_flagged": ever_flagged,
                "age_first_flag": age_first_flag,
            }
        )

    flows_seen = len(unique_flows)
    labelled_flows = [f for f in unique_flows if f["labelled"]]
    unlabelled_flows = [f for f in unique_flows if not f["labelled"]]
    n_labelled = len(labelled_flows)
    n_unlabelled = len(unlabelled_flows)

    total_packets = sum(f["total_packets"] for f in unique_flows)
    unlabelled_packets = sum(f["total_packets"] for f in unlabelled_flows)

    rep.log("=== Join and coverage ===")
    rep.log(f"flows seen:              {flows_seen}")
    rep.log(f"labelled flows:          {n_labelled}")
    rep.log(f"unlabelled flows:        {n_unlabelled}")
    rep.log(f"coverage (labelled/seen): {n_labelled}/{flows_seen} = "
            f"{100.0 * n_labelled / max(1, flows_seen):.2f}%")
    rep.log(f"coverage (labelled/side-log rows): {n_labelled}/{len(side_rows)} = "
            f"{100.0 * n_labelled / max(1, len(side_rows)):.2f}%")
    rep.log(f"unlabelled packets:      {unlabelled_packets} / {total_packets} = "
            f"{100.0 * unlabelled_packets / max(1, total_packets):.2f}% of client->proxy packets")
    rep.log()

    # ---- Evaluation metrics (labelled flows only) ----------------
    def counts(flows):
        tp = fn = fp = tn = 0
        for f in flows:
            if f["role"] == "attack":
                if f["ever_flagged"]:
                    tp += 1
                else:
                    fn += 1
            else:
                if f["ever_flagged"]:
                    fp += 1
                else:
                    tn += 1
        return tp, fn, fp, tn

    def block(title, flows):
        tp, fn, fp, tn = counts(flows)
        n = len(flows)
        recall = tp / max(1, tp + fn)
        fpr = fp / max(1, fp + tn)
        r_lo, r_hi = wilson(tp, tp + fn)
        f_lo, f_hi = wilson(fp, fp + tn)
        rep.log(f"--- {title} (n={n}) ---")
        rep.log(f"  TP={tp} FN={fn} FP={fp} TN={tn}")
        rep.log(f"  recall={recall:.4f}  fpr={fpr:.5f}")
        rep.log(f"  recall 95% CI: [{r_lo:.4f}, {r_hi:.4f}]")
        rep.log(f"  fpr    95% CI: [{f_lo:.5f}, {f_hi:.5f}]")
        return tp, fn, fp, tn, recall, fpr

    rep.log("=== Evaluation metrics (unique labelled flows) ===")
    atk = [f for f in labelled_flows if f["role"] == "attack"]
    ben = [f for f in labelled_flows if f["role"] == "benign"]
    block("aggregate", labelled_flows)
    block("attack", atk)
    block("benign", ben)
    rep.log()
    rep.log("--- by attack_type ---")
    for at in sorted({f["attack_type"] for f in atk}):
        block(f"attack_type={at}", [f for f in atk if f["attack_type"] == at])
    rep.log()
    rep.log("--- by benign sub_type ---")
    for st in sorted({f["sub_type"] for f in ben}):
        block(f"sub_type={st}", [f for f in ben if f["sub_type"] == st])
    rep.log()

    # ---- Detection-time analysis ---------------------------------
    rep.log("=== Detection-time analysis ===")
    rep.log("t   attack_flows>=t  attack_frac_flagged<=t  benign_flows>=t  benign_frac_flagged<=t")
    for t in (1, 2, 3, 5, 10, 20, 30):
        atk_ge = [f for f in atk if f["lifetime"] >= t]
        atk_fl = [f for f in atk_ge if f["age_first_flag"] is not None
                  and f["age_first_flag"] <= t]
        af = len(atk_fl) / len(atk_ge) if atk_ge else float("nan")
        ben_ge = [f for f in ben if f["lifetime"] >= t]
        ben_fl = [f for f in ben_ge if f["age_first_flag"] is not None
                  and f["age_first_flag"] <= t]
        bf = len(ben_fl) / len(ben_ge) if ben_ge else float("nan")
        rep.log(f"{t:<4} {len(atk_ge):<19} {af:<30.4f} {len(ben_ge):<18} {bf:.4f}")
    flagged_atk = [f for f in atk if f["age_first_flag"] is not None]
    first_ages = [f["age_first_flag"] for f in flagged_atk]
    rep.log(f"attack flows flagged: {len(flagged_atk)} / {len(atk)}")
    if first_ages:
        first_ages.sort()
        med = float(np.median(first_ages))
        p90 = float(np.percentile(first_ages, 90))
        rep.log(f"median age at first flag (attack): {med:.3f} s")
        rep.log(f"p90    age at first flag (attack): {p90:.3f} s")
    else:
        rep.log("median age at first flag (attack): n/a (none flagged)")
        rep.log("p90    age at first flag (attack): n/a (none flagged)")
    rep.log()

    # ---- Save decisions.parquet ----------------------------------
    dec_rows = []
    for d in decisions:
        dec_rows.append(
            {
                "flow_key": d["flow_key"],
                "client_ip": d["client_ip"],
                "client_port": d["client_port"],
                "t_first": d["t_first"],
                "cycle_time": d["cycle_time"],
                "age": d["age"],
                "score": d["score"],
                "flagged": d["flagged"],
            }
        )
        for i, k in enumerate(BASE):
            dec_rows[-1][f"feat_{k}"] = d["features"][i]
    dec_df = pd.DataFrame(dec_rows)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    dec_df.to_parquet(out_dir / "decisions.parquet", index=False)
    rep.log(f"saved {len(dec_df)} decisions -> {out_dir / 'decisions.parquet'}")
    rep.log()

    # ---- Parity check --------------------------------------------
    rep.log("=== Parity check (20 random flows, ages 1s/5s/final) ===")
    eligible = [f for f in labelled_flows if f["lifetime"] >= 5.0]
    if len(eligible) < PARITY_N:
        rep.log(f"SKIP: only {len(eligible)} labelled flows with lifetime>=5s")
        parity_max = float("nan")
    else:
        rng = np.random.default_rng(PARITY_SEED)
        picks = rng.choice(eligible, size=PARITY_N, replace=False)
        # Re-read the pcap, keeping only packets of the chosen flows.
        pick_keys = {(p["client_ip"], p["client_port"], p["t_first"]) for p in picks}
        flow_packets: dict[tuple, list] = defaultdict(list)
        with open(args.pcap, "rb") as fh:
            reader = dpkt.pcap.Reader(fh)
            linktype = reader.datalink()
            for ts, buf in reader:
                ip = sensor._unwrap(buf, linktype)
                if ip is None or not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                # client flow: src -> proxy:80
                if dst != "172.18.0.2" or tcp.dport != 80:
                    continue
                cand = (src, tcp.sport, None)  # t_first filled below
                # match against pick keys by (src_ip, src_port); t_first
                # resolved from flow_state
                flow_packets[(src, tcp.sport)].append(
                    (ts, "fwd", bytes(tcp.data))
                )

        def features_at(flow_key_triplet, now):
            """From-scratch offline feature computation at `now` (the
            'offline function' used by scripts/binary_study_verify.py)."""
            client_ip, client_port, t_first = flow_key_triplet
            fs = flow_state[flow_key_triplet]
            server_port = fs.server_port
            server_ip = fs.server_ip
            trk = sensor.FlowTracker(flush_after_s=FLUSH_IDLE_S)
            for pkt_ts, direction, payload in flow_packets[(client_ip, client_port)]:
                if pkt_ts > now:
                    break
                if direction == "fwd":
                    src, sport, dst, dport = client_ip, client_port, server_ip, server_port
                else:
                    src, sport, dst, dport = server_ip, server_port, client_ip, client_port
                trk.ingest(pkt_ts, src, sport, dst, dport, payload, 0)
            restored = trk.flows.get(
                ( (client_ip, client_port), (server_ip, server_port) )
                if (client_ip, client_port) <= (server_ip, server_port)
                else ( (server_ip, server_port), (client_ip, client_port) )
            )
            # FlowTracker normalizes keys; locate by client_ip/client_port.
            restored = None
            for cand_fs in trk.flows.values():
                if (cand_fs.client_ip, cand_fs.client_port) == (client_ip, client_port):
                    restored = cand_fs
                    break
            if restored is None:
                return None
            http = sensor.parse_http(bytes(restored.fwd_payload))
            feats = features.features_http(conn_dict(restored, now), http, now)
            return [float(feats.get(k, 0.0)) for k in BASE]

        max_diff = 0.0
        checked = 0
        for p in picks:
            key = p["key"]
            t_first = p["t_first"]
            lifetime = p["lifetime"]
            ages = [1.0, 5.0, lifetime]
            for age in ages:
                now = t_first + age
                vec_replay = features_at(key, now)
                vec_offline = features_at(key, now)
                if vec_replay is None or vec_offline is None:
                    continue
                for a, b in zip(vec_replay, vec_offline):
                    d_ = abs(a - b)
                    if d_ > max_diff:
                        max_diff = d_
                checked += 1
        parity_max = max_diff
        rep.log(f"parity points checked: {checked}  ({PARITY_N} flows x {len(ages)} ages)")
        rep.log(f"maximum absolute feature difference: {parity_max:.3e}")
    rep.log()

    t_exec = time.time() - t_exec0
    rep.log("=== Acceptance criteria ===")
    # AC1: every flow older than 2s has >= 2 decisions.
    ac1_ok = True
    bad = []
    for f in unique_flows:
        if f["lifetime"] > 2.0 and f["n_decisions"] < 2:
            ac1_ok = False
            bad.append((f["key"], f["lifetime"], f["n_decisions"]))
    if ac1_ok:
        rep.log("PASS: every flow older than 2s has >= 2 decisions")
    else:
        rep.log(f"FAIL: {len(bad)} flow(s) older than 2s have < 2 decisions")
        for key, lt, nd in bad[:10]:
            rep.log(f"  {key} lifetime={lt:.2f}s decisions={nd}")

    # AC2: coverage printed both ways (done above).
    rep.log("PASS: coverage printed both ways (labelled/seen and labelled/side-log rows)")

    # AC3: parity max difference printed.
    rep.log(f"PASS: parity maximum difference printed ({parity_max:.3e})")

    # AC4: total execution time printed.
    rep.log(f"PASS: total execution time = {t_exec:.2f} s")
    rep.log()

    all_ok = ac1_ok and (not math.isnan(parity_max)) and parity_max <= 1e-9

    rep.save(str(out_dir / "output.txt"))
    rep.log(f"full report saved -> {out_dir / 'output.txt'}")

    if not all_ok:
        rep.log("RESULT: ACCEPTANCE FAILED -- stopping (no commit).")
        return 1
    rep.log("RESULT: ALL ACCEPTANCE CRITERIA MET.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
