#!/usr/bin/env python3
"""bench.py — live benchmark harness. Measurements only.

HONESTY NOTE (why this file was rewritten)
------------------------------------------
An earlier version filled in "modelled specification" numbers whenever Docker
was not running: a fixed 1.35 s "detection latency", 99.8 % "legit success",
12.4 ms "p99". Those were targets, not measurements, but they were printed in a
results table that looked empirical. A benchmark that invents values is worse
than no benchmark, so that behaviour is gone.

What this module does now:

  * With `--live` and the Docker lab running, it measures real HTTP success and
    latency against the proxy, and (if present) reports detection timing from the
    detector's own live feed.
  * In any other mode it refuses to print numbers and says so plainly.

The A/B protection proof (no-defence vs defence, read from nginx's access log)
now lives in `dashboard/protect_demo.py`. Prefer that for the demo.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional

try:
    import httpx
except ImportError:  # pragma: no cover - depends on the environment
    httpx = None

REPO = Path(__file__).resolve().parents[1]
PROXY_URL = "http://localhost:8080"
FEED = REPO / "reports" / "live_feed.jsonl"


def docker_running() -> bool:
    try:
        res = subprocess.run(
            ["docker", "compose", "ps", "--services", "--filter", "status=running"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5,
        )
        running = [s.strip() for s in res.stdout.splitlines() if s.strip()]
        return "proxy" in running or "backend" in running
    except Exception:
        return False


def measure_success_rate(proxy_url: str, n: int = 30) -> Optional[float]:
    """Percentage of 2xx responses, or None if it could not be measured."""
    if httpx is None:
        return None
    ok = 0
    for _ in range(n):
        try:
            r = httpx.get(f"{proxy_url.rstrip('/')}/health", timeout=2.0)
            if r.status_code == 200:
                ok += 1
        except Exception:
            pass
    return round(100.0 * ok / n, 2)


def measure_p99_ms(proxy_url: str, n: int = 30) -> Optional[float]:
    """99th-percentile round-trip latency in ms, or None if not measured."""
    if httpx is None:
        return None
    times = []
    for _ in range(n):
        try:
            t0 = time.perf_counter()
            r = httpx.get(f"{proxy_url.rstrip('/')}/health", timeout=2.0)
            if r.status_code == 200:
                times.append(1000.0 * (time.perf_counter() - t0))
        except Exception:
            pass
    if not times:
        return None
    times.sort()
    return round(times[min(len(times) - 1, int(0.99 * len(times)))], 2)


def first_detection_s() -> Optional[float]:
    """Seconds from the live-lab run start to the first flagged (>=0.55) flow."""
    status = REPO / "reports" / "live_lab_status.json"
    if not status.exists() or not FEED.exists():
        return None
    try:
        started = float(json.loads(status.read_text()).get("started", 0.0))
    except Exception:
        return None
    if started <= 0:
        return None
    for line in FEED.read_text().splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if float(rec.get("score", 0.0)) >= 0.55:
            return round(float(rec.get("ts", 0.0)) - started, 2)
    return None


def run(attack: str, proxy_url: str) -> dict:
    success = measure_success_rate(proxy_url)
    p99 = measure_p99_ms(proxy_url)
    detected = first_detection_s()
    measured = success is not None or p99 is not None
    return {
        "attack": attack,
        "measured": measured,
        "httpx_available": httpx is not None,
        "legit_success_pct": success,
        "legit_p99_ms": p99,
        "first_detection_s": detected,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Sentinel-AI live benchmark (measurements only)")
    ap.add_argument("--attack", choices=["slowloris", "flood", "all"], default="all")
    ap.add_argument("--proxy-url", default=PROXY_URL)
    ap.add_argument("--live", action="store_true",
                    help="measure against running Docker containers")
    args = ap.parse_args()

    if not args.live or not docker_running():
        print("=" * 78)
        print("BENCHMARK: NOT MEASURED")
        print("=" * 78)
        reason = "no --live flag" if not args.live else "Docker lab is not running"
        print(f"Reason: {reason}.")
        print("This harness no longer prints modelled/target numbers — only real ones.")
        print("For the protection proof, run:")
        print("  .venv/bin/python dashboard/protect_demo.py --duration 60 --mode flood")
        return 2

    if httpx is None:
        print("Note: httpx is not installed, so HTTP success/latency cannot be "
              "measured here. Install it or use dashboard/protect_demo.py.")
        return 2

    attacks = ["slowloris", "flood"] if args.attack == "all" else [args.attack]
    rows = [run(a, args.proxy_url) for a in attacks]

    print("=" * 78)
    print("SENTINEL-AI BENCHMARK — LIVE MEASURED (nginx /health probes)")
    print("=" * 78)
    print(f"{'attack':<10} | {'legit 2xx %':>11} | {'legit p99 ms':>12} | "
          f"{'first detect s':>14}")
    print("-" * 78)
    for r in rows:
        ok = "n/a" if r["legit_success_pct"] is None else f"{r['legit_success_pct']}"
        p99 = "n/a" if r["legit_p99_ms"] is None else f"{r['legit_p99_ms']}"
        det = "n/a" if r["first_detection_s"] is None else f"{r['first_detection_s']}"
        print(f"{r['attack']:<10} | {ok:>11} | {p99:>12} | {det:>14}")
    print("=" * 78)
    print("Note: detection time is read from the detector's live feed; it is only")
    print("      useful when a live-lab run is in progress.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
