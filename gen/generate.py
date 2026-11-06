#!/usr/bin/env python3
from __future__ import annotations
import argparse
import asyncio
import json
import random
import time

LAB_HOST = "proxy"
LAB_PORT = 80
SRC_IPS: list[str] = []

# Opens a TCP connection, optionally pinned to a specific source IP.
async def _connect(src_ip: str | None = None):
    if src_ip:
        return await asyncio.open_connection(
            LAB_HOST, LAB_PORT, local_addr=(src_ip, 0))
    return await asyncio.open_connection(LAB_HOST, LAB_PORT)

# Side-log row written once per connection so labels can be joined off the wire.
# Columns: src_ip, src_port, start_ts, end_ts, role, attack_type, tool, parameters.
def _side_log(path: str | None, row: dict) -> None:
    if not path:
        return
    line = json.dumps(row, separators=(",", ":")) + "\n"
    # asyncio is single-threaded; open+write has no await inside, so concurrent
    # worker coroutines cannot interleave within this block.
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)


# Simulates a realistic browser session with reconnects and slow but finite
# uploads.  ``sub_type`` tags the connection in the side log so each benign
# flavour can be evaluated separately:
#   "normal"        - standard short POST (existing behaviour)
#   "slow_mobile"   - simulated netem delay between body chunks (slow header
#                     and slow upload completion)
#   "large_upload"  - POST body that takes multiple seconds to send
#   "api_crawler"   - high request rate on a keep-alive connection
#   "keepalive_polling" - long-lived connection with periodic small requests
#   "browser_parallel" - several parallel connections from one client
#                     (orchestrated at run_mix level; sub_type tags each conn)
async def benign_worker(agent: int, duration: int, think_lo: float,
                        think_hi: float, slow_fraction: float = 0.15,
                        stagger: float = 0.0, src_ip: str | None = None,
                        stats: dict | None = None,
                        side_log: str | None = None,
                        sub_type: str = "normal",
                        netem_delay_ms: float = 0.0,
                        netem_rate_kbps: float = 0.0):
    if stats is None:
        stats = {"connections_attempted": 0, "connections_succeeded": 0,
                 "connections_failed": 0, "requests_attempted": 0,
                 "requests_completed": 0, "requests_failed": 0,
                 "exceptions": []}
        
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    end = time.time() + duration
    uid = f"u{agent}"
    start_ts = time.time()

    while time.time() < end:
        stats["connections_attempted"] = stats.get("connections_attempted", 0) + 1
        try:
            reader, writer = await _connect(src_ip)
            stats["connections_succeeded"] = stats.get("connections_succeeded", 0) + 1
        except Exception as e:
            stats["connections_failed"] = stats.get("connections_failed", 0) + 1
            stats["exceptions"].append(f"agent={agent} connect: {type(e).__name__}: {e}")
            await asyncio.sleep(1.0)
            continue
        sock = writer.get_extra_info("sockname")
        src_port = sock[1] if sock else None
        for _ in range(random.randint(1, 3)):
            if time.time() >= end:
                break
            slow = random.random() < slow_fraction
            # Large upload sub-type always uses a big body.
            if sub_type == "large_upload":
                body_len = random.randint(500_000, 5_000_000)
            elif slow:
                body_len = random.randint(200_000, 2_000_000)
            else:
                body_len = random.randint(0, 4000)
            head = (f"POST /api/txn HTTP/1.1\r\n"
                    f"Host: api\r\n"
                    f"User-Agent: Mozilla/5.0\r\n"
                    f"Content-Length: {body_len}\r\n"
                    f"Content-Type: multipart/form-data\r\n\r\n").encode()
            stats["requests_attempted"] = stats.get("requests_attempted", 0) + 1
            try:
                if sub_type == "slow_mobile" or slow:
                    # Simulated netem: delay between body chunks.
                    writer.write(head)
                    await writer.drain()
                    chunk = b"x" * 8192
                    sent = 0
                    while sent < body_len and time.time() < end:
                        to_send = min(len(chunk), body_len - sent)
                        writer.write(chunk[:to_send])
                        try:
                            await writer.drain()
                        except ConnectionResetError as e:
                            stats["requests_failed"] = stats.get("requests_failed", 0) + 1
                            stats["exceptions"].append(f"agent={agent} send_body: ConnectionResetError: {e}")
                            raise
                        sent += to_send
                        # netem delay between chunks
                        if netem_delay_ms > 0:
                            await asyncio.sleep(netem_delay_ms / 1000.0)
                        elif sub_type == "slow_mobile":
                            await asyncio.sleep(random.uniform(0.3, 0.9))
                        else:
                            await asyncio.sleep(random.uniform(0.05, 0.2))
                else:
                    body = b"x" * body_len if body_len else b""
                    writer.write(head + body)
                    await writer.drain()
                try:
                    await asyncio.wait_for(reader.read(4096), timeout=30)
                except asyncio.TimeoutError:
                    stats["exceptions"].append(f"agent={agent} response_read_timeout")
                    pass
                stats["requests_completed"] = stats.get("requests_completed", 0) + 1
            except ConnectionResetError as e:
                stats["requests_failed"] = stats.get("requests_failed", 0) + 1
                if "send_body" not in stats["exceptions"][-1] if stats["exceptions"] else True:
                    stats["exceptions"].append(f"agent={agent} request: ConnectionResetError: {e}")
                break
            except Exception as e:
                stats["requests_failed"] = stats.get("requests_failed", 0) + 1
                stats["exceptions"].append(f"agent={agent} request: {type(e).__name__}: {e}")
                break
            await asyncio.sleep(random.uniform(think_lo, think_hi))
        _side_log(side_log, {
            "src_ip": src_ip,
            "src_port": src_port,
            "start_ts": start_ts,
            "end_ts": time.time(),
            "role": "benign",
            "attack_type": f"benign_{sub_type}",
            "tool": "generate.py",
            "parameters": {"duration": duration, "think_lo": think_lo,
                           "think_hi": think_hi, "slow_fraction": slow_fraction,
                           "stagger": stagger, "sub_type": sub_type,
                           "netem_delay_ms": netem_delay_ms,
                           "netem_rate_kbps": netem_rate_kbps},
        })
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        await asyncio.sleep(random.uniform(0.05, 0.4))


# Simulates a Slowloris attack that never terminates its HTTP header.
async def slowloris_worker(conn_id: int, duration: int,
                           keepalive_interval: float = 1.0,
                           stagger: float = 0.0, src_ip: str | None = None,
                           side_log: str | None = None):
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    end = time.time() + duration
    if time.time() >= end:
        return
    reader, writer = await _connect(src_ip)
    sock = writer.get_extra_info("sockname")
    src_port = sock[1] if sock else None
    start_ts = time.time()
    writer.write(f"GET /api/txn?q={'y' * 70}&u={conn_id} HTTP/1.1\r\n"
                 f"Host: api\r\nUser-Agent: Mozilla/5.0\r\n".encode())
    await writer.drain()

    while time.time() < end:
        writer.write(f"X-keepalive: {random.randint(1, 99999)}\r\n".encode())
        await writer.drain()
        await asyncio.sleep(random.uniform(keepalive_interval * 0.5,
                                           keepalive_interval * 1.5))
    _side_log(side_log, {
        "src_ip": src_ip,
        "src_port": src_port,
        "start_ts": start_ts,
        "end_ts": time.time(),
        "role": "attack",
        "attack_type": "slowloris",
        "tool": "generate.py",
        "parameters": {"duration": duration, "keepalive_interval": keepalive_interval,
                       "stagger": stagger},
    })
    writer.close()


# Simulates a high-rate HTTP flood using keep-alive connections.
async def flood_worker(conn_id: int, duration: int, req_per_conn: int = 200,
                       stagger: float = 0.0, src_ip: str | None = None,
                       side_log: str | None = None):
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    end = time.time() + duration
    if time.time() >= end:
        return
    reader, writer = await _connect(src_ip)
    sock = writer.get_extra_info("sockname")
    src_port = sock[1] if sock else None
    start_ts = time.time()

    while time.time() < end:
        for _ in range(req_per_conn):
            req = (b"GET /api/txn HTTP/1.1\r\nHost: api\r\n"
                   b"Connection: keep-alive\r\n"
                   b"User-Agent: Mozilla/5.0\r\n\r\n")
            writer.write(req)
        await writer.drain()
        try:
            await asyncio.wait_for(reader.read(65536), timeout=2)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(random.uniform(0.03, 0.06))
    _side_log(side_log, {
        "src_ip": src_ip,
        "src_port": src_port,
        "start_ts": start_ts,
        "end_ts": time.time(),
        "role": "attack",
        "attack_type": "flood",
        "tool": "generate.py",
        "parameters": {"duration": duration, "req_per_conn": req_per_conn,
                       "stagger": stagger},
    })
    writer.close()


# Simulates a R.U.D.Y. (R-U-Dead-Yet) slow POST attack.
# Completes the HTTP header (including Content-Length) then drips the body
# byte-by-byte at a random interval, keeping the connection open long after
# the header is done.  Looks like a legitimate slow upload from the header
# side, but never finishes the body.
async def ruddy_worker(conn_id: int, duration: int,
                       drip_interval: float = 0.5,
                       body_len: int = 500_000,
                       drip_chunk: int = 64,
                       stagger: float = 0.0,
                       src_ip: str | None = None,
                       side_log: str | None = None):
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    end = time.time() + duration
    if time.time() >= end:
        return
    reader, writer = await _connect(src_ip)
    sock = writer.get_extra_info("sockname")
    src_port = sock[1] if sock else None
    start_ts = time.time()
    # Complete header with a large Content-Length but no \\r\\n\\r\\n body
    # terminator problem -- header IS complete, body is the slow part.
    head = (f"POST /api/upload HTTP/1.1\r\n"
            f"Host: api\r\nUser-Agent: Mozilla/5.0\r\n"
            f"Content-Length: {body_len}\r\n"
            f"Content-Type: application/octet-stream\r\n\r\n").encode()
    writer.write(head)
    await writer.drain()
    sent = 0
    while sent < body_len and time.time() < end:
        chunk = min(drip_chunk, body_len - sent)
        writer.write(b"x" * chunk)
        try:
            await writer.drain()
        except ConnectionResetError:
            break
        sent += chunk
        await asyncio.sleep(random.uniform(drip_interval * 0.5,
                                           drip_interval * 1.5))
    _side_log(side_log, {
        "src_ip": src_ip,
        "src_port": src_port,
        "start_ts": start_ts,
        "end_ts": time.time(),
        "role": "attack",
        "attack_type": "ruddy",
        "tool": "generate.py",
        "parameters": {"duration": duration, "drip_interval": drip_interval,
                       "body_len": body_len, "drip_chunk": drip_chunk,
                       "stagger": stagger},
    })
    writer.close()


# Simulates a low-and-slow attacker that mimics benign pacing.
# Uses complete headers, modest request rates, and short-lived connections --
# the same shape as benign traffic but with attack intent.  The goal is to
# test whether the detector can distinguish low-rate attack from benign when
# both look alike at the flow level.
async def low_and_slow_worker(conn_id: int, duration: int,
                              req_per_conn: int = 5,
                              inter_req_gap: float = 2.0,
                              body_len: int = 200,
                              stagger: float = 0.0,
                              src_ip: str | None = None,
                              side_log: str | None = None):
    if stagger > 0:
        await asyncio.sleep(random.uniform(0.0, stagger))
    end = time.time() + duration
    if time.time() >= end:
        return
    reader, writer = await _connect(src_ip)
    sock = writer.get_extra_info("sockname")
    src_port = sock[1] if sock else None
    start_ts = time.time()
    while time.time() < end:
        for _ in range(req_per_conn):
            if time.time() >= end:
                break
            req = (f"GET /api/poll?id={conn_id} HTTP/1.1\r\n"
                   f"Host: api\r\nUser-Agent: Mozilla/5.0\r\n"
                   f"Content-Length: {body_len}\r\n\r\n").encode()
            writer.write(req)
            try:
                await writer.drain()
            except ConnectionResetError:
                break
            await asyncio.sleep(random.uniform(inter_req_gap * 0.5,
                                               inter_req_gap * 1.5))
        # Close and reopen occasionally to mimic benign churn
        await asyncio.sleep(random.uniform(0.5, 2.0))
    _side_log(side_log, {
        "src_ip": src_ip,
        "src_port": src_port,
        "start_ts": start_ts,
        "end_ts": time.time(),
        "role": "attack",
        "attack_type": "low_and_slow",
        "tool": "generate.py",
        "parameters": {"duration": duration, "req_per_conn": req_per_conn,
                       "inter_req_gap": inter_req_gap,
                       "body_len": body_len, "stagger": stagger},
    })
    writer.close()

# Picks this worker's source IP from the container's pool.
def _ip_for(i: int) -> str | None:
    if not SRC_IPS:
        return None
    return SRC_IPS[i % len(SRC_IPS)]

# Runs a mixed benign/attack traffic generation with randomized parameters.
# Each benign sub-type and attack type is tagged in the side log so it can
# be evaluated separately.  Parameters (connection count, drip interval,
# header size, request rate, lifetime) are randomized per run so the model
# cannot win by memorizing the lab.
#
# ``benign_mix``: list of (sub_type, count) tuples, e.g.
#   [("normal", 20), ("slow_mobile", 10), ("large_upload", 5),
#    ("api_crawler", 8), ("keepalive_polling", 5), ("browser_parallel", 7)]
# ``attack_mix``: list of (attack_type, count) tuples, e.g.
#   [("slowloris", 10), ("ruddy", 5), ("flood", 3), ("low_and_slow", 5)]
# ``dur_min``/``dur_max``: per-connection duration range in seconds --
#   randomized so lifetimes overlap between benign and attack.
async def run_mix(duration: int,
                  benign_mix: list[tuple[str, int]],
                  attack_mix: list[tuple[str, int]],
                  label: str,
                  stagger: float | None = None,
                  side_log: str | None = None,
                  dur_min: int = 30,
                  dur_max: int = 180):
    if stagger is None:
        stagger = duration * 0.6
    tasks = []
    conn_id = 0

    # ---- Benign workers (randomized sub-types and durations) ----
    for sub_type, count in benign_mix:
        for i in range(count):
            conn_dur = random.randint(dur_min, dur_max)
            tasks.append(benign_worker(
                i, conn_dur, 0.2, 2.0,
                stagger=stagger,
                src_ip=_ip_for(conn_id), side_log=side_log,
                sub_type=sub_type,
                netem_delay_ms=random.uniform(0, 200)
                if sub_type == "slow_mobile" else 0.0,
                netem_rate_kbps=random.uniform(10, 500)
                if sub_type == "slow_mobile" else 0.0,
            ))
            conn_id += 1

    # ---- Attack workers (randomized types and parameters) ----
    for attack_type, count in attack_mix:
        for i in range(count):
            conn_dur = random.randint(dur_min, dur_max)
            if attack_type == "slowloris":
                tasks.append(slowloris_worker(
                    i, conn_dur,
                    keepalive_interval=random.uniform(0.5, 3.0),
                    stagger=stagger,
                    src_ip=_ip_for(conn_id), side_log=side_log))
            elif attack_type == "ruddy":
                tasks.append(ruddy_worker(
                    i, conn_dur,
                    drip_interval=random.uniform(0.2, 2.0),
                    body_len=random.randint(100_000, 2_000_000),
                    drip_chunk=random.randint(16, 256),
                    stagger=stagger,
                    src_ip=_ip_for(conn_id), side_log=side_log))
            elif attack_type == "flood":
                tasks.append(flood_worker(
                    i, conn_dur,
                    req_per_conn=random.randint(50, 1000),
                    stagger=stagger,
                    src_ip=_ip_for(conn_id), side_log=side_log))
            elif attack_type == "low_and_slow":
                tasks.append(low_and_slow_worker(
                    i, conn_dur,
                    req_per_conn=random.randint(3, 10),
                    inter_req_gap=random.uniform(1.0, 5.0),
                    body_len=random.randint(50, 500),
                    stagger=stagger,
                    src_ip=_ip_for(conn_id), side_log=side_log))
            else:
                raise ValueError(f"unknown attack type: {attack_type}")
            conn_id += 1

    n_benign = sum(c for _, c in benign_mix)
    n_attack = sum(c for _, c in attack_mix)
    print(f"[{label}] {n_benign} benign ({[s for s,_ in benign_mix]}) + "
          f"{n_attack} attack ({[a for a,_ in attack_mix]}), "
          f"durations {dur_min}-{dur_max}s, for {duration}s")
    await asyncio.gather(*tasks, return_exceptions=True)

# Runs a benign-only traffic generation to measure false-positive rate.
async def run_benign_only(duration: int, n_benign: int, label: str,
                          stagger: float | None = None,
                          side_log: str | None = None):
    if stagger is None:
        stagger = duration * 0.6
    stats_list = [{"connections_attempted": 0, "connections_succeeded": 0,
                   "connections_failed": 0, "requests_attempted": 0,
                   "requests_completed": 0, "requests_failed": 0,
                   "exceptions": []} for _ in range(n_benign)]
    tasks = [benign_worker(i, duration, 0.2, 2.0, stagger=stagger,
                           src_ip=_ip_for(i), stats=stats_list[i],
                           side_log=side_log)
             for i in range(n_benign)]
    print(f"[{label}] benign only: {n_benign} agents, {duration}s "
          f"(this run gives the FPR)")
    await asyncio.gather(*tasks, return_exceptions=True)

    total = {"connections_attempted": 0, "connections_succeeded": 0,
             "connections_failed": 0, "requests_attempted": 0,
             "requests_completed": 0, "requests_failed": 0,
             "exceptions": []}
    for s in stats_list:
        for k in ["connections_attempted", "connections_succeeded", "connections_failed",
                  "requests_attempted", "requests_completed", "requests_failed"]:
            total[k] += s.get(k, 0)
        total["exceptions"].extend(s.get("exceptions", []))

    print(f"[{label}] STATS: connections={total['connections_succeeded']}/{total['connections_attempted']} "
          f"failed={total['connections_failed']}, requests={total['requests_completed']}/{total['requests_attempted']} "
          f"failed={total['requests_failed']}")
    if total["exceptions"]:
        print(f"[{label}] EXCEPTIONS ({len(total['exceptions'])}):")
        for exc in total["exceptions"][:10]:
            print(f"  {exc}")
        if len(total["exceptions"]) > 10:
            print(f"  ... and {len(total['exceptions']) - 10} more")

MIXED_PROFILES = [
    "benign_only",
    "slow_only",
    "flood_only",
    "benign_then_slow",
    "benign_then_flood",
    "slow_then_benign",
    "flood_then_benign",
    "benign_concurrent_slow",
    "slow_and_flood",
]

# Runs one worker phase with a timeout so it cannot hang the whole IP.
async def _bounded(coro, timeout: float):
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except Exception:
        return None

# Sleeps for a delay then runs a coroutine.
async def _after(delay: float, coro):
    if delay > 0:
        await asyncio.sleep(delay)
    return await coro

# Runs one source IP through a real-world attack profile.
async def mixed_ip_worker(i: int, profile: str, duration: int,
                          req_per_conn: int = 50, src_ip: str | None = None,
                          side_log: str | None = None):
    half = max(1, duration // 2)
    span = duration + 15
    hspan = half + 15

    def ben(dur, stagger):
        return _bounded(benign_worker(i, dur, 0.2, 2.0, stagger=stagger,
                                      src_ip=src_ip, side_log=side_log), dur + 15)

    if profile == "benign_only":
        await ben(duration, duration * 0.6)
    elif profile == "slow_only":
        await _bounded(slowloris_worker(i, duration, stagger=duration * 0.6,
                                        src_ip=src_ip, side_log=side_log), span)
    elif profile == "flood_only":
        await _bounded(flood_worker(i, duration, req_per_conn=req_per_conn,
                                    stagger=duration * 0.6, src_ip=src_ip,
                                    side_log=side_log), span)
    elif profile == "benign_then_slow":
        await asyncio.gather(ben(half, 0.0),
                             _after(half, _bounded(slowloris_worker(i, half,
                                                             src_ip=src_ip,
                                                             side_log=side_log),
                                                 hspan)))
    elif profile == "benign_then_flood":
        await asyncio.gather(ben(half, 0.0),
                             _after(half, _bounded(flood_worker(i, half,
                                                                req_per_conn=req_per_conn,
                                                                src_ip=src_ip,
                                                                side_log=side_log),
                                                     hspan)))
    elif profile == "slow_then_benign":
        await asyncio.gather(_bounded(slowloris_worker(i, half, src_ip=src_ip,
                                                       side_log=side_log), hspan),
                             _after(half, ben(half, 0.0)))
    elif profile == "flood_then_benign":
        await asyncio.gather(_bounded(flood_worker(i, half, req_per_conn=req_per_conn,
                                                   src_ip=src_ip, side_log=side_log),
                                      hspan),
                             _after(half, ben(half, 0.0)))
    elif profile == "benign_concurrent_slow":
        await asyncio.gather(ben(duration, duration * 0.6),
                             _bounded(slowloris_worker(i, duration,
                                                       stagger=duration * 0.6,
                                                       src_ip=src_ip,
                                                       side_log=side_log), span))
    elif profile == "slow_and_flood":
        await asyncio.gather(_bounded(slowloris_worker(i, duration,
                                                       stagger=duration * 0.6,
                                                       src_ip=src_ip,
                                                       side_log=side_log), span),
                             _bounded(flood_worker(i, duration,
                                                   req_per_conn=req_per_conn,
                                                   stagger=duration * 0.6,
                                                   src_ip=src_ip,
                                                   side_log=side_log), span))
    else:
        raise ValueError(f"unknown mixed profile: {profile}")


# Runs N source IPs through mixed profiles in round-robin order.
async def run_mixed(duration: int, n_ips: int, label: str, req_per_conn: int = 50,
                    side_log: str | None = None):
    tasks = [mixed_ip_worker(i, MIXED_PROFILES[i % len(MIXED_PROFILES)],
                             duration, req_per_conn=req_per_conn,
                             src_ip=_ip_for(i), side_log=side_log)
             for i in range(n_ips)]
    print(f"[{label}] mixed: {n_ips} IPs over {len(MIXED_PROFILES)} profiles, "
          f"{duration}s (per-flow labels via side log)")
    await asyncio.gather(*tasks, return_exceptions=True)

# Parses CLI args and dispatches to the selected traffic generation mode.
def _parse_mix(s: str | None) -> list[tuple[str, int]]:
    """Parse a comma-separated list of ``type:count`` pairs."""
    if not s:
        return []
    out = []
    for item in s.split(","):
        item = item.strip()
        if not item:
            continue
        if ":" not in item:
            raise ValueError(f"mix entry must be type:count, got {item!r}")
        t, c = item.rsplit(":", 1)
        out.append((t.strip(), int(c.strip())))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Generate labelled L7 attack traffic against the lab proxy")
    ap.add_argument("--mode", required=True,
                    choices=["benign", "mix", "slow", "flood", "mixed"])
    ap.add_argument("--duration", type=int, default=120,
                    help="total seconds to run")
    ap.add_argument("--benign", type=int, default=50,
                    help="benign connections (mix mode: total benign count)")
    ap.add_argument("--slow", type=int, default=200,
                    help="slowloris connections (mix mode: kept for compat)")
    ap.add_argument("--flood", type=int, default=20,
                    help="flood connections (mix mode: kept for compat)")
    ap.add_argument("--req-per-conn", type=int, default=200,
                    help="flood: requests written per write() burst "
                         "(lower = smaller pcaps, same high-rate signature)")
    ap.add_argument("--mixed", type=int, default=0,
                    help="mixed mode: N source IPs, each playing a real-world "
                         "benign/attack/switch profile (per-flow labels)")
    ap.add_argument("--label", default="run")
    ap.add_argument("--side-log", default=None,
                    help="path to per-connection side-log JSONL (labels off "
                         "the wire)")
    ap.add_argument("--benign-mix", default=None,
                    help="comma-separated sub_type:count pairs for benign, "
                         "e.g. normal:40,slow_mobile:10,large_upload:5")
    ap.add_argument("--attack-mix", default=None,
                    help="comma-separated attack_type:count pairs, e.g. "
                         "slowloris:10,ruddy:5,flood:3,low_and_slow:5")
    ap.add_argument("--dur-min", type=int, default=30,
                    help="minimum per-connection duration seconds")
    ap.add_argument("--dur-max", type=int, default=180,
                    help="maximum per-connection duration seconds")
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

    benign_mix = _parse_mix(args.benign_mix)
    attack_mix = _parse_mix(args.attack_mix)

    # Backward-compatible: if --benign-mix/--attack-mix not given, use the
    # legacy --benign/--slow/--flood counts.
    if not benign_mix and not attack_mix:
        benign_mix = [("normal", args.benign)]
        if args.slow > 0:
            attack_mix.append(("slowloris", args.slow))
        if args.flood > 0:
            attack_mix.append(("flood", args.flood))

    if args.mode == "benign":
        asyncio.run(run_benign_only(args.duration, args.benign, args.label,
                                    side_log=args.side_log))
    elif args.mode in ("slow", "flood", "mix"):
        # Legacy single-attack modes map to attack_mix.
        if not attack_mix:
            if args.mode == "slow":
                attack_mix = [("slowloris", args.slow)]
            elif args.mode == "flood":
                attack_mix = [("flood", args.flood)]
        asyncio.run(run_mix(args.duration, benign_mix or [("normal", 1)],
                            attack_mix, args.label,
                            side_log=args.side_log,
                            dur_min=args.dur_min, dur_max=args.dur_max))
    elif args.mode == "mixed":
        asyncio.run(run_mixed(args.duration, args.mixed, args.label,
                              req_per_conn=args.req_per_conn,
                              side_log=args.side_log))
    else:
        asyncio.run(run_mix(args.duration, benign_mix or [("normal", 1)],
                            attack_mix, args.label,
                            side_log=args.side_log,
                            dur_min=args.dur_min, dur_max=args.dur_max))


if __name__ == "__main__":
    main()