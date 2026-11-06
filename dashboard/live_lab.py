#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

DASH_DIR = Path(__file__).resolve().parent
REPO_ROOT = DASH_DIR.parent
for _p in (DASH_DIR, REPO_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from live import (
    CONN_CONF_ON,
    FEED_PATH,
    LAB_STATUS_PATH,
    RATE_CONF_ON,
    LabRunner,
    LiveEngine,
    LiveSensor,
    append_feed,
    flow_signature,
    mechanism_kind,
    nginx_directives,
)
from mechanism import (
    CONN_LIMIT,
    DETECT_THRESHOLD,
    LADDER,
    Mechanism,
    apply_profile_guard,
)
from m1_capture.features import WindowTracker, build_features
from m1_capture.merge import load_side_log, _side_log_index, _match_side_log
from m1_capture.sensor import parse_http
from m2_triggers.stall import STALL_THRESHOLD_S, detect as detect_stall
from schemas import FlowRecord

ON_THRESHOLD = LADDER[1][0]
OFF_THRESHOLD = LADDER[2][0]

COUNT_THRESHOLD = DETECT_THRESHOLD

OBSERVE_MIN_S = STALL_THRESHOLD_S

STALL_REASONS_USED = ("header_incomplete", "body_incomplete", "slow_drip")

CAPTURE = "live.pcap"

def log(msg: str) -> None:
    print(f"[live_lab {time.strftime('%H:%M:%S')}] {msg}", flush=True)

def write_status(**kw) -> None:
    LAB_STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {"updated": time.time()}
    if LAB_STATUS_PATH.exists():
        try:
            old = json.loads(LAB_STATUS_PATH.read_text())
            if old.get("pid") == os.getpid():
                payload.update(old)
        except Exception:
            pass
    payload.update(kw)
    LAB_STATUS_PATH.write_text(json.dumps(payload, indent=2))

def stall_evidence(feats: dict, entity: str, flow_id: str, now: float):
    rec = FlowRecord(
        flow_id=str(flow_id),
        entity_key=entity,
        ts_start=0.0,
        ts_end=now,
        src_ip=entity,
        src_port=0,
        dst_ip="",
        dst_port=0,
        bytes_in=int(feats.get("bytes_in", 0) or 0),
        req_count=int(feats.get("requests_per_conn_so_far", 0) or 0),
        bytes_in_per_s=float(feats.get("bytes_in_per_s", 0.0)),
        requests_per_s=float(feats.get("requests_per_s", 0.0)),
        packets_per_s=float(feats.get("packets_per_s", 0.0)),
        interarrival_mean=float(feats.get("interarrival_mean", 0.0)),
        interarrival_std=float(feats.get("interarrival_std", 0.0)),
        interarrival_max=float(feats.get("interarrival_max", 0.0)),
        concurrent_conns=float(feats.get("concurrent_conns", 0.0)),
        conns_per_second_opened=float(feats.get("conns_per_second_opened", 0.0)),
        requests_per_conn_so_far=float(feats.get("requests_per_conn_so_far", 0.0)),
        conn_age_s=float(feats.get("conn_age_s", 0.0)),
        stall_time_s=float(feats.get("stall_time_s", 0.0)),
        body_frac_sent=float(feats.get("body_frac_sent", 1.0)),
        bytes_declared=float(feats.get("bytes_declared", 0.0)),
        body_drip_rate_bps=float(feats.get("body_drip_rate_bps", 0.0)),
        time_to_first_byte=float(feats.get("time_to_first_byte", 0.0)),
        header_complete=float(feats.get("header_complete", 1.0)),
    )
    event = detect_stall(rec)
    if event is None:
        return None
    used = [r for r in event.detail.get("reasons", []) if r in STALL_REASONS_USED]
    if not used:
        return None
    return event, used

def _stall_mechanism(reasons: list[str]) -> Mechanism:
    return Mechanism(
        conn_limit=CONN_LIMIT,
        timeout_s=10.0,
        driver=f"m2 stall rule: {','.join(reasons)}",
        driver_group="stall",
        reason=(f"Module 2 stall rule fired ({', '.join(reasons)}): an unfinished "
                f"request has been open past {STALL_THRESHOLD_S:.0f}s. The model "
                f"needs ~30s of flow age to see this; the rule sees it now."),
    )

def main() -> int:
    ap = argparse.ArgumentParser(description="Real-time packet scoring in the lab")
    ap.add_argument("--duration", type=int, default=120,
                    help="total seconds to run")
    ap.add_argument("--mode", choices=["benign", "slow", "flood", "mixed"],
                    default="mixed")
    ap.add_argument("--ip-count", type=int, default=40,
                    help="attack source IPs per attack container")
    ap.add_argument("--benign-count", type=int, default=20)
    ap.add_argument("--no-up", action="store_true",
                    help="assume the lab is already running")
    ap.add_argument("--keep-traffic", action="store_true",
                    help="do not stop the generators at the end")
    ap.add_argument("--no-enforce", action="store_true",
                    help="shadow mode: detect and score only, never touch nginx "
                         "limits (used as the 'without defence' baseline)")
    ap.add_argument("--also-benign", action="store_true",
                    help="run benign load alongside the chosen attack mode")
    ap.add_argument("--req-per-conn", type=int, default=200,
                    help="flood: requests written per burst (lower = smaller pcap)")
    ap.add_argument("--conns-per-ip", type=int, default=1,
                    help="flood: connections opened per attacker IP (raise this to "
                         "exercise limit_conn, which caps concurrent connections/IP)")
    ap.add_argument("--no-backstop", action="store_true",
                    help="disable the profile cross-check. By default, if a flagged "
                         "flow is clearly rate-shaped but the explanation chose "
                         "limit_conn (or vice-versa), the missing limit is added too "
                         "so a mis-attributed attack cannot slip through")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))

    if not LabRunner.docker_available():
        print("Docker is not available — cannot run the live lab.")
        write_status(running=False, error="docker unavailable")
        return 2

    runner = LabRunner()
    engine = LiveEngine()

    FEED_PATH.write_text("")
    write_status(running=True, mode=args.mode, started=time.time(),
                 duration=args.duration, pid=os.getpid(),
                 no_enforce=args.no_enforce,
                 decisions=0, flows_seen=0, counters={}, limits={"rate": False,
                 "conn": False})

    # Fresh run id and side-log path (off-the-wire labels, Phase 1).
    # Mounted volume ./reports/runs -> /reports/runs in generator containers.
    run_id = f"run_{int(time.time())}"
    run_dir = REPO_ROOT / "reports" / "runs" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    side_log_container = f"/reports/runs/{run_id}/side_log.jsonl"
    side_log_host = run_dir / "side_log.jsonl"
    side_log_host.write_text("")
    side_log_arg = ["--side-log", side_log_container]

    # Flow metadata + all decisions for post-run side-log join.
    flow_meta: dict[str, tuple[str, int, float, float]] = {}
    all_decisions: list[dict] = []
    side_idx: dict = {}
    matched_count = 0
    decision_count = 0

    if not args.no_up:
        print("bringing the lab up ...")
        r = runner.up()
        if r.returncode != 0:
            print(r.stderr[-2000:])
            write_status(running=False, error="compose up failed")
            return 3
    print("lab is up:", ", ".join(runner.running_names()) or "(none)")

    runner.write_limits("", "")
    runner.reload_nginx()

    print(f"adding source-IP pools ({args.ip_count} attack, {args.benign_count} benign) ...")
    runner.add_ip_pool("slow-gen", "172.18.16", args.ip_count)
    runner.add_ip_pool("flood-gen", "172.18.17", args.ip_count)
    runner.add_ip_pool("legit-loadgen", "172.18.15", args.benign_count)

    cap_name = "live_capture.pcap"
    cap_path = Path(runner.repo) / "captures" / cap_name
    if cap_path.exists():
        cap_path.unlink()
    print("starting capture:", cap_path)
    runner.start_capture(cap_name)
    time.sleep(1.0)

    dur = args.duration + 5
    if args.mode in ("benign", "mixed") or args.also_benign:
        runner.launch("legit-loadgen", "benign", dur, label="livelab",
                      ip_base="172.18.15", ip_count=args.benign_count,
                      extra=["--benign", str(args.benign_count)] + side_log_arg)
    if args.mode in ("slow", "mixed"):
        runner.launch("slow-gen", "slow", dur,
                      label="livelab", ip_base="172.18.16", ip_count=args.ip_count,
                      extra=["--slow", str(args.ip_count)] + side_log_arg)
    if args.mode in ("flood", "mixed"):
        n_flood = args.ip_count * max(1, args.conns_per_ip)
        runner.launch("flood-gen", "flood", dur,
                      label="livelab", ip_base="172.18.17", ip_count=args.ip_count,
                      extra=["--flood", str(n_flood),
                             "--req-per-conn", str(args.req_per_conn)] + side_log_arg)
    print(f"traffic launched (mode={args.mode}, generators running {dur}s)")

    sensor = LiveSensor(cap_path)
    emitted: set = set()
    counted_flows: set = set()
    limits = {"rate": False, "conn": False}
    decisions = 0
    t0 = time.time()

    ON = ON_THRESHOLD
    OFF = OFF_THRESHOLD
    latest: dict = {}
    latest_mech: dict = {}
    latest_prof: dict = {}

    def confusion() -> dict:
        tp = fp = tn = fn = un = observe = 0
        for truth, score, final, age in latest.values():
            if not final and age < OBSERVE_MIN_S:
                observe += 1
                continue
            pred = score >= COUNT_THRESHOLD
            if truth == "attack":
                tp += int(pred); fn += int(not pred)
            elif truth == "benign":
                fp += int(pred); tn += int(not pred)
            else:
                un += 1
        return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
                "unknown": un, "observing": observe}

    try:
        while time.time() - t0 < args.duration:
            flows = sensor.poll()
            now = sensor.latest_ts or time.time()

            # Refresh side-log index from the mounted volume each iteration.
            try:
                side_rows = load_side_log(side_log_host)
                side_idx = _side_log_index(side_rows)
            except Exception:
                side_idx = {}

            win = WindowTracker(10.0)
            for fs in flows:
                if fs.t_first <= 0:
                    continue
                win.on_connect(fs.client_ip, fs.t_first)
                if fs.t_close is not None:
                    win.on_close(fs.client_ip, fs.t_close)

            for fs in flows:
                if fs.t_first <= 0 or fs.fwd_bytes <= 0:
                    continue
                age = ((fs.t_close - fs.t_first) if fs.t_close is not None
                       else max(0.0, now - fs.t_first))
                t_end = fs.t_close if fs.t_close is not None else fs.t_last
                flow_meta[str(fs.flow_id)] = (fs.client_ip, fs.client_port,
                                              fs.t_first, t_end)
                bucket = int(min(age, 600) // 15)
                key = (fs.flow_id, "final" if fs.t_close is not None else bucket)
                if key in emitted:
                    continue
                emitted.add(key)
                if len(emitted) > 200_000:
                    emitted.clear()

                rec = fs.to_record()
                http = parse_http(bytes.fromhex(rec["fwd_payload"]))
                feats = build_features(rec, http, win, fs.client_ip, now)
                res = engine.score(feats, fs.client_ip)

                # Join to side log on (client_ip, client_port, time overlap).
                # Unmatched = "unmatched", never guessed.
                truth = "unmatched"
                attack_type = "unmatched"
                cip, cport, t0, t1 = flow_meta[str(fs.flow_id)]
                row = _match_side_log(side_idx, cip, cport, t0, t1)
                if row is not None:
                    truth = row.get("role", "unmatched")
                    attack_type = row.get("attack_type", "unmatched")
                    matched_count += 1
                decision_count += 1

                model_score = float(res["calibrated"])
                score = model_score
                evidence = ""
                stall = stall_evidence(feats, fs.client_ip, fs.flow_id, now)
                if stall is not None:
                    ev, reasons = stall
                    evidence = ",".join(reasons)
                    if ev.severity > score:
                        score = float(ev.severity)
                        res["top_group"] = "stall"
                        res["mechanism"] = _stall_mechanism(reasons)
                        res["action"] = engine.policy.decide(fs.client_ip, score)

                rec_out = {
                    "i": decisions,
                    "ts": time.time(),
                    "flow": str(fs.flow_id),
                    "entity": fs.client_ip,
                    "client_port": fs.client_port,
                    "t_first": fs.t_first,
                    "t_end": t_end,
                    "age": round(age, 1),
                    "display_guess": flow_signature(feats),
                    "truth": truth,
                    "attack_type": attack_type,
                    "model_score": round(model_score, 4),
                    "score": round(score, 4),
                    "raw": round(res["raw"], 4),
                    "group": res["top_group"],
                    "evidence": evidence,
                    "mechanism": mechanism_kind(res["mechanism"]),
                    "reason": res["mechanism"].reason,
                    "action": res["action"],
                    "final": fs.t_close is not None,
                    "directive": nginx_directives(res["mechanism"]),
                }
                append_feed(rec_out)
                all_decisions.append(rec_out)
                if fs.flow_id not in counted_flows:
                    counted_flows.add(fs.flow_id)
                    decisions += 1
                latest[fs.flow_id] = (truth, score, fs.t_close is not None, age)
                latest_mech[fs.flow_id] = res["mechanism"]
                latest_prof[fs.flow_id] = {
                    "rate": float(feats.get("requests_per_s", 0.0)),
                    "concurrent_conns": int(feats.get("concurrent_conns", 0.0) or 0),
                    "stall": float(feats.get("stall_time_s", 0.0)),
                }

            max_cal = max((s for _t, s, _f, _a in latest.values()), default=0.0)
            if args.no_enforce:
                want_rate = want_conn = False
            elif max_cal >= ON:
                severe = [fid for fid, (_t, s, _f, _a) in latest.items() if s >= ON]
                mechs = []
                for fid in severe:
                    m = latest_mech.get(fid)
                    if m is None:
                        continue
                    if not args.no_backstop:
                        m = apply_profile_guard(m, latest_prof.get(fid, {}))
                    mechs.append(m)
                want_rate = any(m.rate_limit is not None for m in mechs)
                want_conn = any(m.conn_limit is not None for m in mechs)
            elif max_cal < OFF:
                want_rate = want_conn = False
            else:
                want_rate, want_conn = limits["rate"], limits["conn"]

            if (want_rate, want_conn) != (limits["rate"], limits["conn"]):
                runner.write_limits(RATE_CONF_ON if want_rate else "",
                                    CONN_CONF_ON if want_conn else "")
                rr = runner.reload_nginx()
                print(f"[enforce] rate={want_rate} conn={want_conn} reload_ok={rr.returncode == 0}")
                limits = {"rate": want_rate, "conn": want_conn}

            write_status(running=True, mode=args.mode, decisions=decisions,
                         flows_seen=len(flows), counters=confusion(),
                         limits=limits, updated=time.time())
            time.sleep(2.0)
    except KeyboardInterrupt:
        print("interrupted")
    finally:
        runner.stop_capture()
        if not args.keep_traffic:
            # Generators were started with dur = duration + 5s; let them finish
            # writing side-log rows before we kill them. Benign connections can
            # take up to the response-read timeout, so wait generously.
            time.sleep(15.0)
            runner.stop_traffic()
        try:
            if limits["rate"] or limits["conn"]:
                runner.write_limits("", "")
                runner.reload_nginx()
                limits = {"rate": False, "conn": False}
        except Exception:
            pass

        # --- Post-run: join every decision to the complete side log -------
        match_rate = 0.0
        try:
            # Give generator containers a moment to flush the side log.
            time.sleep(1.0)
            side_rows = load_side_log(side_log_host)
            side_idx_final = _side_log_index(side_rows)

            n_rows = len(side_rows)
            role_counts: dict[str, int] = {}
            atype_counts: dict[str, int] = {}
            for r in side_rows:
                role_counts[r.get("role", "?")] = role_counts.get(r.get("role", "?"), 0) + 1
                atype_counts[r.get("attack_type", "?")] = atype_counts.get(r.get("attack_type", "?"), 0) + 1

            print("\n=== Side log (off-the-wire labels) ===")
            print(f"path: {side_log_host}")
            print(f"rows: {n_rows}")
            print(f"role counts: {dict(sorted(role_counts.items()))}")
            print(f"attack_type counts: {dict(sorted(atype_counts.items()))}")
            print("first 5 rows:")
            for r in side_rows[:5]:
                print("  ", json.dumps(r, separators=(",", ":")))

            # Re-match ALL decisions against the complete side log.
            final_truth: dict[str, tuple[str, str]] = {}  # flow_id -> (truth, attack_type)
            for d in all_decisions:
                fid = d["flow"]
                cip = d["entity"]
                cport = d.get("client_port", 0)
                t0 = d.get("t_first", 0.0)
                t1 = d.get("t_end", 0.0)
                row = _match_side_log(side_idx_final, cip, cport, t0, t1)
                if row is None:
                    final_truth[fid] = ("unmatched", "unmatched")
                else:
                    final_truth[fid] = (row.get("role", "unmatched"),
                                        row.get("attack_type", "unmatched"))

            matched = sum(1 for t, _ in final_truth.values() if t != "unmatched")
            total = len(final_truth)
            match_rate = (100.0 * matched / total) if total else 0.0

            # Rewrite the feed with final joined truth.
            final_feed: list[dict] = []
            for d in all_decisions:
                fid = d["flow"]
                t, at = final_truth.get(fid, ("unmatched", "unmatched"))
                dd = dict(d)
                dd["truth"] = t
                dd["attack_type"] = at
                final_feed.append(dd)
            FEED_PATH.write_text("")
            for dd in final_feed:
                append_feed(dd)

            # Final confusion matrix from joined truth only (exclude unmatched).
            tp = fp = tn = fn = unmatched_n = 0
            per_type: dict[str, dict[str, int]] = {}
            for d in final_feed:
                t, at = final_truth.get(d["flow"], ("unmatched", "unmatched"))
                if t == "unmatched":
                    unmatched_n += 1
                    continue
                pred = d["score"] >= COUNT_THRESHOLD
                key = at
                b = per_type.setdefault(key, {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "total": 0})
                b["total"] += 1
                if t == "attack":
                    b["tp" if pred else "fn"] += 1
                    if pred:
                        tp += 1
                    else:
                        fn += 1
                else:
                    b["fp" if pred else "tn"] += 1
                    if pred:
                        fp += 1
                    else:
                        tn += 1

            print("\n=== Joined-truth evaluation (side log only) ===")
            print(f"match rate: {match_rate:.1f}%  ({matched}/{total} decisions matched)")
            print(f"TP={tp} FP={fp} TN={tn} FN={fn} unmatched={unmatched_n}")
            if tp + fn:
                print(f"attack recall: {tp / (tp + fn) * 100:.1f}%")
            if fp + tn:
                print(f"benign FPR: {fp / (fp + tn) * 100:.4f}%")
            print("per attack_type:")
            for at, b in sorted(per_type.items()):
                rec = (b["tp"] / (b["tp"] + b["fn"]) * 100) if (b["tp"] + b["fn"]) else 0.0
                fpr = (b["fp"] / (b["fp"] + b["tn"]) * 100) if (b["fp"] + b["tn"]) else 0.0
                print(f"  {at}: total={b['total']} TP={b['tp']} FP={b['fp']} "
                      f"TN={b['tn']} FN={b['fn']} recall={rec:.1f}% fpr={fpr:.4f}%")

            # Update latest with final truth so the dashboard shows joined truth.
            for fid, (t, at) in final_truth.items():
                if fid in latest:
                    _s, _f, _a = latest[fid][1], latest[fid][2], latest[fid][3]
                    latest[fid] = (t, _s, _f, _a)

        except Exception as e:
            print(f"[post-run side-log join failed: {e}]")

        write_status(running=False, mode=args.mode, decisions=decisions,
                     counters=confusion(), limits=limits, updated=time.time(),
                     side_log_path=str(side_log_host),
                     side_log_match_rate=round(match_rate, 2))

    print(f"done: {decisions} decisions scored  match_rate={match_rate:.1f}%")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())