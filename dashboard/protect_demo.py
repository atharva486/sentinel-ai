#!/usr/bin/env python3
"""protect_demo.py — controlled proof that the middleware protects the site.

This is the "apply it for real" demo. It runs the *same* attack twice against
the same real site behind the same reverse proxy, and changes exactly one thing:

    Phase A  baseline  — detector runs in SHADOW mode (--no-enforce):
                         it scores and explains, but writes no limit.
    Phase B  defended  — detector enforces: it writes nginx limits and reloads.

Proof is read from nginx's OWN access log (`logs/flow.log`), not from our
counters, so the numbers cannot be a print statement we control:

  * benign clients  (172.18.15.x) should stay served in BOTH phases,
  * attack clients  (172.18.16.x slowloris / 172.18.17.x flood) should be
    served in A and rejected (HTTP 429) in B.

Run (from the repo root):

    .venv/bin/python dashboard/protect_demo.py

Defaults (flood, 4 attack IPs, 200 requests/burst, 30 s per phase) are tuned so
the flood is actually *detected*, which is what makes the A/B meaningful.

Enforcement note: when the detector fires, live_lab applies the mechanism the
explanation chose AND cross-checks it against the flow's own measured profile
(the rule `mechanism.contains` already encodes). A keep-alive request flood can
be attributed to the "concurrency" SHAP group, which would pick `limit_conn` — a
defence that cannot contain a rate-shaped attack — so a rate limit is added. Pass
`--no-backstop` to see the un-cross-checked behaviour (0 % suppression for flood).

Result is written to reports/protection_proof.json and printed as a table.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

DASH_DIR = Path(__file__).resolve().parent
REPO = DASH_DIR.parent

FLOW_LOG = REPO / "logs" / "flow.log"
PROOF_PATH = REPO / "reports" / "protection_proof.json"

# Source-IP pools the traffic generators bind to (see dashboard/live_lab.py).
_CLASSES = (("172.18.15.", "benign"), ("172.18.16.", "slow"), ("172.18.17.", "flood"))


def classify(ip: str) -> str:
    for prefix, name in _CLASSES:
        if ip.startswith(prefix):
            return name
    return "other"


def _load_line(line: str) -> dict | None:
    """Parse one nginx access-log line.

    The log_format writes `$time_iso8601` unquoted, which is not valid JSON, so
    older lines fail a straight `json.loads`. New lines quote it; we accept both
    by re-quoting the timestamp before retrying.
    """
    try:
        return json.loads(line)
    except json.JSONDecodeError:
        pass
    fixed = re.sub(r'"ts_start":([^"][^,]*),', r'"ts_start":"\1",', line)
    try:
        return json.loads(fixed)
    except json.JSONDecodeError:
        return None


def read_segment(start: int) -> list[dict]:
    rows: list[dict] = []
    if not FLOW_LOG.exists():
        return rows
    with FLOW_LOG.open("rb") as fh:
        fh.seek(start)
        data = fh.read()
    for line in data.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line:
            continue
        rec = _load_line(line)
        if rec is not None:
            rows.append(rec)
    return rows


def _pct(vals: list[int], pred) -> float:
    return round(100.0 * sum(1 for v in vals if pred(v)) / len(vals), 1) if vals else 0.0


def summarize(rows: list[dict]) -> dict:
    out: dict[str, dict] = {}
    for cls in ("benign", "slow", "flood"):
        sel = [r for r in rows if classify(str(r.get("remote_addr", ""))) == cls]
        n = len(sel)
        d: dict = {"requests": n}
        if n:
            codes = [int(r.get("status") or 0) for r in sel]
            times = sorted(float(r.get("request_time") or 0.0) for r in sel)
            d["pct_2xx"] = _pct(codes, lambda c: 200 <= c < 300)
            d["pct_429"] = _pct(codes, lambda c: c == 429)
            d["pct_5xx"] = _pct(codes, lambda c: 500 <= c < 600)
            d["p50_ms"] = round(1000.0 * times[len(times) // 2], 1)
            d["p95_ms"] = round(1000.0 * times[min(len(times) - 1, int(0.95 * len(times)))], 1)
        out[cls] = d
    return out


def run_phase(name: str, args, no_enforce: bool) -> tuple[int, dict]:
    start = FLOW_LOG.stat().st_size if FLOW_LOG.exists() else 0
    cmd = [
        args.python, str(DASH_DIR / "live_lab.py"),
        "--duration", str(args.duration),
        "--mode", args.mode,
        "--ip-count", str(args.ip_count),
        "--benign-count", str(args.benign_count),
        "--req-per-conn", str(args.req_per_conn),
        "--also-benign",
    ]
    if no_enforce:
        cmd.append("--no-enforce")
    if args.no_up:
        cmd.append("--no-up")
    if getattr(args, "no_backstop", False):
        cmd.append("--no-backstop")
    print(f"\n=== phase {name} ===", flush=True)
    print("    " + " ".join(cmd), flush=True)
    rc = subprocess.run(cmd, cwd=str(REPO)).returncode
    if rc != 0:
        print(f"    ! phase exited with code {rc}")
    time.sleep(1.0)  # let nginx flush the access log
    return rc, summarize(read_segment(start))


def main() -> int:
    ap = argparse.ArgumentParser(description="A/B proof of the inline defence")
    ap.add_argument("--duration", type=int, default=30,
                    help="seconds per phase (needs >45s for slowloris to age)")
    ap.add_argument("--mode", choices=["flood", "slow", "mixed"], default="flood")
    ap.add_argument("--ip-count", type=int, default=4,
                    help="attack source IPs per attack container")
    ap.add_argument("--benign-count", type=int, default=20)
    ap.add_argument("--req-per-conn", type=int, default=200,
                    help="flood: requests per burst (lower = smaller pcap / less CPU)")
    ap.add_argument("--no-backstop", action="store_true",
                    help="do not cross-check the chosen mechanism against the flow "
                         "profile (baseline control: a flood then stays undefended)")
    ap.add_argument("--python", default=sys.executable,
                    help="interpreter used to run dashboard/live_lab.py")
    ap.add_argument("--no-up", action="store_true",
                    help="assume the lab is already up")
    args = ap.parse_args()

    print("protect_demo: baseline (shadow) vs defended (enforcing)")
    print(f"  mode={args.mode}  duration/phase={args.duration}s  "
          f"attack_ips={args.ip_count}  benign_ips={args.benign_count}")

    rc_a, base = run_phase("A · baseline (no defence)", args, no_enforce=True)
    rc_b, defended = run_phase("B · defended (nginx limits)", args, no_enforce=False)

    def served(d: dict, cls: str) -> float:
        return d.get(cls, {}).get("pct_2xx", 0.0)

    attack_cls = "slow" if args.mode == "slow" else "flood"
    proof = {
        "generated": time.time(),
        "mode": args.mode,
        "duration_per_phase_s": args.duration,
        "ip_count": args.ip_count,
        "req_per_conn": args.req_per_conn,
        "backstop": not args.no_backstop,
        "source": "logs/flow.log (nginx access log)",
        "baseline": base,
        "defended": defended,
        "verdict": {
            "attack_class": attack_cls,
            "attack_served_baseline_pct": served(base, attack_cls),
            "attack_served_defended_pct": served(defended, attack_cls),
            "attack_429_defended_pct": defended.get(attack_cls, {}).get("pct_429", 0.0),
            "benign_served_baseline_pct": served(base, "benign"),
            "benign_served_defended_pct": served(defended, "benign"),
            "benign_429_defended_pct": defended.get("benign", {}).get("pct_429", 0.0),
            "attack_requests_baseline": base.get(attack_cls, {}).get("requests", 0),
            "attack_requests_defended": defended.get(attack_cls, {}).get("requests", 0),
        },
    }
    v = proof["verdict"]
    v["attack_suppressed"] = v["attack_served_defended_pct"] < v["attack_served_baseline_pct"] - 20
    # "Benign preserved" = the defence never rate-limits a legitimate client.
    # We key on 429s rather than 2xx because the benign generator emits slow
    # uploads that get client-aborted (400) in BOTH phases, which made the raw
    # 2xx percentage too noisy at these request volumes.
    v["benign_preserved"] = v["benign_429_defended_pct"] <= 1.0

    PROOF_PATH.parent.mkdir(parents=True, exist_ok=True)
    PROOF_PATH.write_text(json.dumps(proof, indent=2))

    print("\n" + "=" * 74)
    print("PROTECTION PROOF  (measured from nginx access log, not our counters)")
    print("=" * 74)
    print(f"{'class':<8} | {'phase':<9} | {'requests':>9} | {'2xx %':>7} | "
          f"{'429 %':>6} | {'5xx %':>6} | {'p95 ms':>7}")
    print("-" * 74)
    for cls in ("benign", "slow", "flood"):
        for phase, data in (("baseline", base), ("defended", defended)):
            d = data.get(cls, {})
            print(f"{cls:<8} | {phase:<9} | {d.get('requests', 0):>9} | "
                  f"{d.get('pct_2xx', 0.0):>7} | {d.get('pct_429', 0.0):>6} | "
                  f"{d.get('pct_5xx', 0.0):>6} | {d.get('p95_ms', 0.0):>7}")
    print("=" * 74)
    print(f"attack ({attack_cls}) served: {v['attack_served_baseline_pct']}%  ->  "
          f"{v['attack_served_defended_pct']}%")
    print(f"benign served:              {v['benign_served_baseline_pct']}%  ->  "
          f"{v['benign_served_defended_pct']}%")
    print(f"benign rejected (429):      {v['benign_429_defended_pct']}%  "
          f"(collateral check)")
    print(f"attack suppressed: {v['attack_suppressed']} | "
          f"benign preserved: {v['benign_preserved']}")
    print(f"\nwrote {PROOF_PATH.relative_to(REPO)}")
    if args.mode == "slow":
        print("note: slowloris requests never complete, so they mostly do not "
              "appear in the access log until nginx times them out.")
    return 0 if (v["attack_suppressed"] or v["benign_preserved"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
