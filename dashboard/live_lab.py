#!/usr/bin/env python3
"""live_lab.py — score REAL packets from the Docker lab, in real time.

This is the physical half of the live demo. It:

  1. brings up the lab (proxy + backend + benign/slow/flood generators),
  2. starts a packet capture on the proxy interface,
  3. launches the traffic generators (with one source IP per worker, exactly
     as the training captures did),
  4. tails the growing pcap, rebuilds flows, computes the 16 features at the
     current instant and scores each flow with the REAL model + calibrator +
     SHAP + mechanism switch,
  5. writes the resulting nginx directives into proxy/limits/ and reloads nginx,
  6. streams every decision into reports/live_feed.jsonl for the dashboard.

Run (from the repo root):

    .venv/bin/python dashboard/live_lab.py --duration 180 --mode mixed

The dashboard's "Live lab" tab reads reports/live_feed.jsonl and shows this
happen live. Nothing here is simulated: the packets are real, captured off the
wire, and the decisions come from the project's own modules.
"""
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

from live import (  # noqa: E402
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
    role_for_ip,
)
from mechanism import (  # noqa: E402
    CONN_LIMIT,
    DETECT_THRESHOLD,
    LADDER,
    Mechanism,
    apply_profile_guard,
)
from m1_capture.features import WindowTracker, build_features  # noqa: E402
from m1_capture.merge import GT_ROLE  # noqa: E402
from m1_capture.sensor import parse_http  # noqa: E402
from m2_triggers.stall import STALL_THRESHOLD_S, detect as detect_stall  # noqa: E402
from schemas import FlowRecord  # noqa: E402

ON_THRESHOLD = LADDER[1][0]      # enable a directive above this
OFF_THRESHOLD = LADDER[2][0]     # release it once everything is back below this

# What counts as "detected" in the confusion matrix. This is the project's own
# DETECT_THRESHOLD (0.30, the throttle rung), NOT the enforcement threshold
# above. Using 0.55 here under-counted true positives by one whole rung.
COUNT_THRESHOLD = DETECT_THRESHOLD

# A flow younger than Module 2's stall threshold cannot be judged yet. The
# model's slow-attack boundary is ~30 s of flow age, so scoring an open 3 s
# flow as a false negative is dishonest. Such flows are reported as
# "observing" and excluded from TP/FP/TN/FN.
OBSERVE_MIN_S = STALL_THRESHOLD_S

# Only the semantic stall reasons are used on live traffic. These are the ones
# measured on the labelled dataset (923/923 slowloris, 275/275 RUDY,
# 6/3820 benign). The age-only rules (long_idle_connection, zero_req_per_conn)
# are deliberately excluded because the dataset has no benign flow older than
# 33.7 s, so they were never validated against long-lived benign keep-alives.
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
    """Run Module 2's semantic stall rules on the current feature vector.

    Why this exists
    ---------------
    The shipped model learned *flow age* rather than *unfinished requests*:
    in the training data every benign flow is <= 33.7 s old while every
    slowloris flow is 55-80 s old, so `conn_age_s` alone separates the classes
    (feature importance: header_complete = 0.0000). Measured consequence: a
    slowloris flow scores the benign floor until it is ~30 s old, and a
    completely normal 45 s keep-alive scores 1.0000.

    Module 2's rules are semantic — an unterminated header or an unfinished
    declared body — so they fire from STALL_THRESHOLD_S (10 s). They are run
    in parallel with the model and OR'd with it.

    Returns (TriggerEvent, [reasons]) for the validated reasons, else None.
    """
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
    """The enforcement a stall-class verdict justifies: hold sockets + timeout."""
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

    # Make sure the capture is stopped and the status is written even when the
    # runner is asked to stop with SIGTERM.
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))

    if not LabRunner.docker_available():
        print("Docker is not available — cannot run the live lab.")
        write_status(running=False, error="docker unavailable")
        return 2

    runner = LabRunner()
    engine = LiveEngine()

    # Fresh feed for this run.
    FEED_PATH.write_text("")
    write_status(running=True, mode=args.mode, started=time.time(),
                 duration=args.duration, pid=os.getpid(),
                 no_enforce=args.no_enforce,
                 decisions=0, flows_seen=0, counters={}, limits={"rate": False,
                 "conn": False})

    if not args.no_up:
        print("bringing the lab up ...")
        r = runner.up()
        if r.returncode != 0:
            print(r.stderr[-2000:])
            write_status(running=False, error="compose up failed")
            return 3
    print("lab is up:", ", ".join(runner.running_names()) or "(none)")

    # Always start from a clean slate: clear any limits left by a previous run
    # so the baseline/defended phases cannot inherit each other's state.
    runner.write_limits("", "")
    runner.reload_nginx()

    # One source IP per worker, as the training captures used.
    print(f"adding source-IP pools ({args.ip_count} attack, {args.benign_count} benign) ...")
    runner.add_ip_pool("slow-gen", "172.18.16", args.ip_count)
    runner.add_ip_pool("flood-gen", "172.18.17", args.ip_count)
    runner.add_ip_pool("legit-loadgen", "172.18.15", args.benign_count)

    # Capture into the mounted volume so the host can read it.
    cap_name = "live_capture.pcap"
    cap_path = Path(runner.repo) / "captures" / cap_name
    if cap_path.exists():
        cap_path.unlink()
    print("starting capture:", cap_path)
    runner.start_capture(cap_name)
    time.sleep(1.0)

    # Launch traffic. Attacks only from the attack containers.
    dur = args.duration + 5
    if args.mode in ("benign", "mixed") or args.also_benign:
        runner.launch("legit-loadgen", "benign", dur, label="livelab",
                      ip_base="172.18.15", ip_count=args.benign_count,
                      extra=["--benign", str(args.benign_count)])
    if args.mode in ("slow", "mixed"):
        runner.launch("slow-gen", "slow", dur,
                      label="livelab", ip_base="172.18.16", ip_count=args.ip_count,
                      extra=["--slow", str(args.ip_count)])
    if args.mode in ("flood", "mixed"):
        n_flood = args.ip_count * max(1, args.conns_per_ip)
        runner.launch("flood-gen", "flood", dur,
                      label="livelab", ip_base="172.18.17", ip_count=args.ip_count,
                      extra=["--flood", str(n_flood),
                             "--req-per-conn", str(args.req_per_conn)])
    print(f"traffic launched (mode={args.mode}, generators running {dur}s)")

    sensor = LiveSensor(cap_path)
    emitted: set = set()
    limits = {"rate": False, "conn": False}
    decisions = 0
    t0 = time.time()

    ON = ON_THRESHOLD
    OFF = OFF_THRESHOLD
    latest: dict = {}       # flow_id -> (truth, score, is_final)
    latest_mech: dict = {}  # flow_id -> mechanism kind
    latest_prof: dict = {}  # flow_id -> {rate, concurrent_conns, stall} profile

    def confusion() -> dict:
        tp = fp = tn = fn = un = observe = 0
        for truth, score, final, age in latest.values():
            # A flow younger than the stall window has not had a fair chance to
            # show its behaviour yet. Counting it as a miss would measure the
            # clock, not the detector.
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
                truth = (GT_ROLE.get(http.get("ground_truth"))
                         or role_for_ip(fs.client_ip) or "unknown")

                # ---- OR the model with Module 2's semantic stall rules ----
                # The model alone needs ~30 s of flow age before it leaves the
                # benign floor (it learned age, not unfinished requests). The
                # stall rule fires at STALL_THRESHOLD_S (10 s) on the same
                # feature vector. Take whichever verdict is stronger; this
                # never lowers a model score, so the model's own detections
                # are unchanged.
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
                    "age": round(age, 1),
                    "profile": flow_signature(feats),
                    "truth": truth,
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
                decisions += 1
                latest[fs.flow_id] = (truth, score, fs.t_close is not None, age)
                latest_mech[fs.flow_id] = res["mechanism"]
                latest_prof[fs.flow_id] = {
                    "rate": float(feats.get("requests_per_s", 0.0)),
                    "concurrent_conns": int(feats.get("concurrent_conns", 0.0) or 0),
                    "stall": float(feats.get("stall_time_s", 0.0)),
                }

            # ---- enforcement: drive nginx from the CURRENT state of all flows ---
            max_cal = max((s for _t, s, _f, _a in latest.values()), default=0.0)
            if args.no_enforce:
                # Shadow mode: we still score and explain, but we never write a
                # limit. This is the honest "without defence" control arm.
                want_rate = want_conn = False
            elif max_cal >= ON:
                severe = [fid for fid, (_t, s, _f, _a) in latest.items() if s >= ON]
                mechs = []
                for fid in severe:
                    m = latest_mech.get(fid)
                    if m is None:
                        continue
                    # The profile guard lives in mechanism.py: it takes the
                    # mechanism the SHAP explanation chose and, if `contains()`
                    # says it cannot contain this flow's own measured profile,
                    # adds the missing limit. This is what stops a keep-alive
                    # request flood (attributed to the concurrency group ->
                    # limit_conn) from slipping through undefended.
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
            runner.stop_traffic()
        # Never leave the proxy throttling anyone: clear limits on exit.
        try:
            if limits["rate"] or limits["conn"]:
                runner.write_limits("", "")
                runner.reload_nginx()
                limits = {"rate": False, "conn": False}
        except Exception:
            pass
        write_status(running=False, mode=args.mode, decisions=decisions,
                     counters=confusion(), limits=limits, updated=time.time())
    print(f"done: {decisions} decisions scored")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
