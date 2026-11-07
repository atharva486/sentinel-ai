#!/usr/bin/env python3
"""Generate one Phase 3 session's traffic from the host.

Runs generate.py directly (LAB_HOST=localhost LAB_PORT=8080) with each worker
batch as a separate subprocess to avoid asyncio concurrency issues.
Captures traffic with tcpdump on loopback.

Usage:
    gen_phase3_host.py <session> <benign_mix> <attack_mix> <duration_s>
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
                  duration: int = 30,
                  dur_min: int = 8,
                  dur_max: int = 15,
                  label: str = "gen") -> None:
    """Run generate.py as a subprocess with the given mixes."""
    benign_arg = ",".join(f"{t}:{c}" for t, c in benign_mix) if benign_mix else ""
    attack_arg = ",".join(f"{t}:{c}" for t, c in attack_mix) if attack_mix else ""

    cmd = ["python3", "gen/generate.py", "--mode", "mix",
           "--duration", str(duration),
           "--label", label,
           "--side-log", str(side_log),
           "--dur-min", str(dur_min),
           "--dur-max", str(dur_max)]
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
        timeout=duration + 60,
    )
    if result.returncode != 0:
        print(f"  WARNING: generate.py exited with {result.returncode}")
        if result.stderr:
            print(f"  stderr: {result.stderr[-300:]}")
    else:
        for line in result.stdout.strip().splitlines():
            if line.startswith("["):
                print(f"  {line}")


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

    print(f"=== Generating session {session} ===")
    print(f"  Benign mix: {benign_mix}")
    print(f"  Attack mix: {attack_mix}")
    print(f"  Duration: {duration}s per batch")
    print(f"  Pcap: {pcap_path}")
    print(f"  Side log: {side_log}")

    # Start tcpdump on loopback (host -> proxy:8080 goes via lo)
    tcpdump = subprocess.Popen(
        ["tcpdump", "-i", "lo", "-s", "0", "-w", str(pcap_path),
         "tcp port 8080"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1.0)

    total_benign = sum(c for _, c in benign_mix)
    total_attack = sum(c for _, c in attack_mix)
    print(f"  Total benign: {total_benign}, Total attack: {total_attack}")

    start = time.time()

    # Run benign workers in batches of 5
    batch_size = 5
    if total_benign > 0:
        print(f"  Running {total_benign} benign connections...")
        remaining = dict(benign_mix)
        while any(c > 0 for c in remaining.values()):
            batch = []
            for sub_type in list(remaining.keys()):
                if remaining[sub_type] > 0:
                    take = min(batch_size, remaining[sub_type])
                    batch.append((sub_type, take))
                    remaining[sub_type] -= take
            run_generator(batch, [], side_log, duration=duration,
                          label=session, dur_min=8, dur_max=15)

    # Run attack workers in batches of 5
    if total_attack > 0:
        print(f"  Running {total_attack} attack connections...")
        remaining = dict(attack_mix)
        while any(c > 0 for c in remaining.values()):
            batch = []
            for at in list(remaining.keys()):
                if remaining[at] > 0:
                    take = min(batch_size, remaining[at])
                    batch.append((at, take))
                    remaining[at] -= take
            run_generator([], batch, side_log, duration=duration,
                          label=session, dur_min=8, dur_max=15)

    elapsed = time.time() - start
    print(f"  Traffic generation complete in {elapsed:.1f}s")

    # Stop tcpdump
    print("  Stopping tcpdump...")
    tcpdump.send_signal(signal.SIGTERM)
    tcpdump.wait(timeout=10)

    # Verify
    if pcap_path.exists():
        size = pcap_path.stat().st_size
        print(f"  Pcap saved: {pcap_path} ({size:,} bytes)")
    else:
        print("  WARNING: Pcap not found!")

    if side_log.exists():
        rows = sum(1 for _ in side_log.open())
        print(f"  Side log saved: {side_log} ({rows} rows)")
    else:
        print("  WARNING: Side log not found!")

    print(f"=== Session {session} complete ===")


if __name__ == "__main__":
    main()
