#!/usr/bin/env python3
"""Generate Phase 3 traffic from the host, one worker at a time.

Each generate.py subprocess runs a single worker (or small batch), avoiding
asyncio concurrency issues. Captures traffic with tcpdump on loopback.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CAPTURES = REPO / "captures"
RUNS = REPO / "reports" / "runs"


def parse_mix(s: str | None) -> list[tuple[str, int]]:
    if not s:
        return []
    out = []
    for item in s.split(","):
        item = item.strip()
        if not item:
            continue
        t, c = item.rsplit(":", 1)
        out.append((t.strip(), int(c.strip())))
    return out


def run_generator(benign_mix: list[tuple[str, int]],
              attack_mix: list[tuple[str, int]],
              side_log: Path,
              duration: int = 15,
              label: str = "gen") -> None:
    """Run generate.py as a subprocess for one batch of workers."""
    benign_arg = ",".join(f"{t}:{c}" for t, c in benign_mix) if benign_mix else ""
    attack_arg = ",".join(f"{t}:{c}" for t, c in attack_mix) if attack_mix else ""

    cmd = ["python3", "gen/generate.py", "--mode", "mix",
           "--duration", str(duration),
           "--label", label,
           "--side-log", str(side_log),
           "--dur-min", "5", "--dur-max", "12"]
    if benign_arg:
        cmd += ["--benign-mix", benign_arg]
    if attack_arg:
        cmd += ["--attack-mix", attack_arg]

    env = dict(os.environ)
    env["LAB_HOST"] = "localhost"
    env["LAB_PORT"] = "8080"

    result = subprocess.run(
        cmd, env=env, cwd=REPO,
        capture_output=True, text=True,
        timeout=duration + 30,
    )
    if result.returncode != 0:
        print(f"  WARNING: exit {result.returncode}", flush=True)
        if result.stderr:
            print(f"  {result.stderr[-200:]}", flush=True)
    else:
        for line in result.stdout.strip().splitlines():
            if line.startswith("["):
                print(f"  {line}", flush=True)


def main() -> None:
    if len(sys.argv) < 5:
        print(f"Usage: {sys.argv[0]} <session> <benign_mix> <attack_mix> <duration_s>")
        sys.exit(1)

    session = sys.argv[1]
    benign_mix = parse_mix(sys.argv[2])
    attack_mix = parse_mix(sys.argv[3])
    duration = int(sys.argv[4])

    run_dir = RUNS / session
    run_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = CAPTURES / f"{session}.pcap"
    side_log = run_dir / "side_log.jsonl"

    for p in (pcap_path, side_log):
        if p.exists():
            p.unlink()

    print(f"=== Session {session} ===")
    print(f"  Benign: {benign_mix}, Attack: {attack_mix}, Duration: {duration}s")
    print(f"  Pcap: {pcap_path}")
    print(f"  Side log: {side_log}")

    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-s", "0", "-w", str(pcap_path),
         "tcp port 8080"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    total_benign = sum(c for _, c in benign_mix)
    total_attack = sum(c for _, c in attack_mix)
    print(f"  Benign: {total_benign}, Attack: {total_attack}")

    start = time.time()

    # Run benign in batches of 3
    if total_benign > 0:
        print(f"  Running {total_benign} benign...", flush=True)
        remaining = dict(benign_mix)
        while any(c > 0 for c in remaining.values()):
            batch = []
            for st in list(remaining.keys()):
                if remaining[st] > 0:
                    take = min(3, remaining[st])
                    batch.append((st, take))
                    remaining[st] -= take
            run_generator(batch, [], side_log, duration=duration,
                          label=session)

    # Run attacks in batches of 3
    if total_attack > 0:
        print(f"  Running {total_attack} attack...", flush=True)
        remaining = dict(attack_mix)
        while any(c > 0 for c in remaining.values()):
            batch = []
            for at in list(remaining.keys()):
                if remaining[at] > 0:
                    take = min(3, remaining[at])
                    batch.append((at, take))
                    remaining[at] -= take
            run_generator([], batch, side_log, duration=duration,
                          label=session)

    elapsed = time.time() - start
    print(f"  Done in {elapsed:.1f}s", flush=True)

    tcpdump.send_signal(signal.SIGTERM)
    tcpdump.wait(timeout=10)

    if pcap_path.exists():
        print(f"  Pcap: {pcap_path.stat().st_size:,} bytes", flush=True)
    if side_log.exists():
        rows = sum(1 for _ in side_log.open())
        print(f"  Side log: {rows} rows", flush=True)

    print(f"=== Session {session} complete ===")


if __name__ == "__main__":
    main()
