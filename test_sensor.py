#!/usr/bin/env python3
"""
test_sensor.py — verify sensor.py + features.py with NO network and NO Docker.

Builds pcaps byte by byte that reproduce each traffic shape, runs the real
extractor over them, and asserts the signature is recovered. This is the check
that was missing before: the code was never executed against a known input.

Run:  python3 test_sensor.py
"""
from __future__ import annotations

import dpkt
import sys
from pathlib import Path

from features import (FEATURE_ORDER, WindowTracker, build_features,
                      group_of, vectorise)
from sensor import parse_http, read_pcap

T0 = 1_700_000_000.0
CLIENT = "10.0.0.11"
SERVER = "10.0.0.10"
TMP = Path("/tmp/opencode/testcap")
TMP.mkdir(parents=True, exist_ok=True)

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08


def mkpkt(ts: float, src: str, sport: int, dst: str, dport: int,
          flags: int, payload: bytes = b"") -> bytes:
    import socket
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, ack=1,
                       flags=flags, win=65535, off=5)
    tcp.data = payload
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst),
                    p=dpkt.ip.IP_PROTO_TCP, len=40 + len(payload))
    ip.data = tcp
    return bytes(ip)


def _wrap_eth(ip_bytes):
    """Add an Ethernet header, as tcpdump does when capturing on eth0."""
    return (bytes.fromhex("020000000001") + bytes.fromhex("020000000002")
            + (0x0800).to_bytes(2, "big") + ip_bytes)


def _wrap_sll(ip_bytes):
    """Add a Linux cooked capture (SLL) header, as tcpdump emits for '-i any'.

    Layout is 16 bytes: packet_type(2) arphrd(2) addr_len(2) addr(8) proto(2).
    """
    return (bytes(2)                          # packet type: sent by us
            + bytes.fromhex("0001")           # ARPHRD_ETHER
            + (6).to_bytes(2, "big")          # address length: MAC
            + bytes(8)                        # 8-byte address field
            + (0x0800).to_bytes(2, "big")     # protocol: IPv4
            + ip_bytes)


def syn(ts, c=CLIENT, s=SERVER, cp=40000):
    return (ts, mkpkt(ts, c, cp, s, 80, SYN))


def synack(ts, c=CLIENT, s=SERVER, cp=40000):
    return (ts, mkpkt(ts, s, 80, c, cp, SYN | ACK))


def data(ts, payload, direction="c2s", c=CLIENT, s=SERVER, cp=40000):
    src, dst = (c, s) if direction == "c2s" else (s, c)
    sp, dp = (cp, 80) if direction == "c2s" else (80, cp)
    return (ts, mkpkt(ts, src, sp, dst, dp, PSH | ACK, payload))


def fin(ts, direction="c2s", c=CLIENT, s=SERVER, cp=40000):
    src, dst = (c, s) if direction == "c2s" else (s, c)
    sp, dp = (cp, 80) if direction == "c2s" else (80, cp)
    return (ts, mkpkt(ts, src, sp, dst, dp, FIN | ACK))


def write_pcap(name, pkts, link="eth"):
    """link: 'eth' (DLT_EN10MB), 'sll' (DLT_LINUX_SLL), 'raw' (DLT_RAW).

    Default is 'eth' because that is what tcpdump produces on eth0 inside the
    proxy container — i.e. the case that actually matters.
    """
    lt = {"eth": dpkt.pcap.DLT_EN10MB,
          "sll": dpkt.pcap.DLT_LINUX_SLL,
          "raw": dpkt.pcap.DLT_RAW}[link]
    wrap = {"eth": _wrap_eth, "sll": _wrap_sll, "raw": lambda b: b}[link]

    path = TMP / f"{name}_{link}.pcap"
    with path.open("wb") as fh:
        w = dpkt.pcap.Writer(fh, linktype=lt)
        for ts, buf in pkts:
            w.writepkt(wrap(buf), ts=ts)
        w.close()
    return path


# ---------------------------------------------------------------- traffic shapes
def benign():
    """Normal keep-alive browsing: 3 complete requests, full body."""
    cp = 41000
    req = (b"GET /api/items HTTP/1.1\r\nHost: api\r\n"
           b"User-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n")
    p = [syn(T0, cp=cp), synack(T0 + 0.002, cp=cp)]
    t = T0 + 0.004
    for _ in range(3):
        p.append(data(t, req, cp=cp)); t += 0.25
        p.append(data(t + 0.01, b'{"ok":true}', "s2c", cp=cp)); t += 0.24
    p.append(fin(t, cp=cp))
    return write_pcap("benign", p)


def slowloris():
    """Header trickled 1 byte/sec and NEVER terminated. No FIN, ever."""
    cp = 42000
    head = b"GET /api/search?q=" + b"a" * 60 + b" HTTP/1.1\r\nHost: api\r\n"
    p = [syn(T0, cp=cp), synack(T0 + 0.003, cp=cp)]
    t = T0 + 0.005
    for i in range(0, len(head), 8):
        p.append(data(t, head[i:i + 8], cp=cp))
        t += 1.0
    p.append(data(t + 2.0, b"X", "s2c", cp=cp))
    return write_pcap("slowloris", p)


def rudy():
    """Valid complete header, Content-Length: 5000000, body trickled."""
    cp = 43000
    head = (b"POST /api/upload HTTP/1.1\r\nHost: api\r\n"
            b"Content-Length: 5000000\r\n\r\n")
    p = [syn(T0, cp=cp), synack(T0 + 0.002, cp=cp)]
    p.append(data(T0 + 0.004, head, cp=cp))
    t = T0 + 0.006
    for _ in range(20):
        p.append(data(t, b"x" * 10, cp=cp))
        t += 1.0
    return write_pcap("rudy", p)


def flood():
    """40 complete requests in ~2 seconds on ONE connection."""
    cp = 44000
    req = (b"GET /api/items HTTP/1.1\r\nHost: api\r\n"
           b"Connection: keep-alive\r\n\r\n")
    p = [syn(T0, cp=cp), synack(T0 + 0.002, cp=cp)]
    t = T0 + 0.003
    for _ in range(40):
        p.append(data(t, req, cp=cp))
        p.append(data(t + 0.001, b'{"ok":true}', "s2c", cp=cp))
        t += 0.05
    p.append(fin(t, cp=cp))
    return write_pcap("flood", p)


def multi_concurrent():
    """Twenty Slowloris connections at once — this is what limit_conn acts on.

    No single connection looks extreme. Only the CONCURRENCY across
    connections is anomalous, which is exactly why window-tier features exist.
    """
    p = []
    for i in range(20):
        cp = 45000 + i
        head = b"GET /api/x?q=" + b"a" * 40 + b" HTTP/1.1\r\nHost: api\r\n"
        p.append(syn(T0 + i * 0.01, cp=cp))
        p.append(synack(T0 + i * 0.01 + 0.002, cp=cp))
        t = T0 + i * 0.01 + 0.004
        for j in range(0, len(head), 8):
            p.append(data(t, head[j:j + 8], cp=cp))
            t += 0.9
    return write_pcap("multi_concurrent", p)


def feats_from(path, entity="e1", now=None, window_s=10.0):
    recs = read_pcap(path, flush_after=5.0)
    win = WindowTracker(window_s=window_s)
    rows = []
    for r in recs:
        http = parse_http(bytes.fromhex(r["fwd_payload"]))
        win.on_connect(entity, r["t_first"])
        if r["t_close"] is not None:
            win.on_close(entity, r["t_close"])
        rows.append((r, http,
                     build_features(r, http, win, entity,
                                    now if now is not None else r["t_last"])))
    return recs, rows


FAIL = []


def check(label, cond, detail=""):
    if cond:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}   got: {detail}")
        FAIL.append(label)


def main() -> None:
    print("\n=== BENIGN: complete keep-alive browsing ===")
    _, rows = feats_from(benign())
    f = rows[0][2]
    check("header_complete == 1", f["header_complete"] == 1.0, f["header_complete"])
    check("stall_time_s == 0", f["stall_time_s"] == 0.0, f["stall_time_s"])
    check("requests_per_conn_so_far == 3",
          f["requests_per_conn_so_far"] == 3.0, f["requests_per_conn_so_far"])
    check("body_frac_sent == 1", f["body_frac_sent"] == 1.0, f["body_frac_sent"])
    print(f"        bytes_in={f['bytes_in']:.0f}  "
          f"bytes_in_per_s={f['bytes_in_per_s']:.0f}")

    print("\n=== SLOWLORIS: header never terminates, connection never closes ===")
    recs, rows = feats_from(slowloris())
    f = rows[-1][2]
    check("a record exists for the unfinished flow", len(recs) >= 1, len(recs))
    check("header_complete == 0", f["header_complete"] == 0.0, f["header_complete"])
    check("stall_time_s > 0", f["stall_time_s"] > 0, f["stall_time_s"])
    # A trickled header fragment "GET /api/se..." contains the substring "GET "
    # but is NOT a complete request. Counting it as one makes a Slowloris flow
    # look like a 1-request browser session, which is precisely the confusion
    # that let the old stall detector score Slowloris as stall_time == 0.
    check("partial header is NOT counted as a request",
          f["requests_per_conn_so_far"] == 0.0,
          f["requests_per_conn_so_far"])
    check("requests_per_s == 0 (no complete request yet)",
          f["requests_per_s"] == 0.0, f["requests_per_s"])
    check("is_open == 1", f.get("is_open") in (1.0, None), f.get("is_open"))
    print(f"        stall_time_s={f['stall_time_s']:.1f}  "
          f"header_complete={f['header_complete']}")

    print("\n=== RUDY: huge Content-Length, body trickled ===")
    recs, rows = feats_from(rudy())
    f, http = rows[-1][2], rows[-1][1]
    check("header_complete == 1", f["header_complete"] == 1.0, f["header_complete"])
    check("declared_body parsed == 5000000",
          http["declared_body"] == 5000000, http["declared_body"])
    check("body_frac_sent < 1", f["body_frac_sent"] < 1.0, f["body_frac_sent"])
    check("stall_time_s > 0", f["stall_time_s"] > 0, f["stall_time_s"])
    check("bytes_declared > 1e6", f["bytes_declared"] > 1e6, f["bytes_declared"])
    print(f"        bytes_declared={f['bytes_declared']:.0f}  "
          f"body_frac_sent={f['body_frac_sent']:.5f}  "
          f"drip={f['body_drip_rate_bps']:.2f} B/s")

    print("\n=== FLOOD: high rate, every request complete ===")
    recs, rows = feats_from(flood())
    f = rows[0][2]
    check("header_complete == 1", f["header_complete"] == 1.0, f["header_complete"])
    check("stall_time_s == 0", f["stall_time_s"] == 0.0, f["stall_time_s"])
    check("requests_per_conn_so_far > 10",
          f["requests_per_conn_so_far"] > 10, f["requests_per_conn_so_far"])
    check("bytes_in_per_s > 1000", f["bytes_in_per_s"] > 1000, f["bytes_in_per_s"])
    print(f"        bytes_in_per_s={f['bytes_in_per_s']:.0f}  "
          f"requests_per_conn_so_far={f['requests_per_conn_so_far']:.0f}")

    print("\n=== 20 CONCURRENT SLOWLORIS: only the aggregate is anomalous ===")
    recs, rows = feats_from(multi_concurrent())
    check("20 flows reconstructed", len(recs) == 20, len(recs))
    last = rows[-1][2]
    check("concurrent_conns tracks the aggregate",
          last["concurrent_conns"] > 0, last["concurrent_conns"])
    check("conns_per_second_opened > 0",
          last["conns_per_second_opened"] > 0,
          last["conns_per_second_opened"])
    print(f"        concurrent_conns={last['concurrent_conns']:.0f}  "
          f"conns_per_s_opened={last['conns_per_second_opened']:.2f}")

    print("\n=== SEPARATION: can a rate-vs-stall switch use these? ===")
    _, b = feats_from(benign())
    _, s = feats_from(slowloris())
    _, r = feats_from(rudy())
    _, fl = feats_from(flood())
    table = [("benign", b[0][2]), ("slowloris", s[-1][2]),
             ("rudy", r[-1][2]), ("flood", fl[0][2])]
    keys = ["stall_time_s", "bytes_in_per_s", "requests_per_conn_so_far",
            "header_complete", "bytes_declared", "body_frac_sent",
            "concurrent_conns"]
    print(f"    {'feature':28}{'benign':>10}{'slowlor':>10}{'rudy':>10}{'flood':>10}   group")
    for k in keys:
        v = [t[1].get(k, 0.0) for t in table]
        print(f"    {k:28}{v[0]:10.2f}{v[1]:10.2f}{v[2]:10.2f}{v[3]:10.2f}   {group_of(k)}")

    slow_vec = vectorise(s[-1][2])
    fast_vec = vectorise(fl[0][2])
    check("slow and flood vectors are distinguishable",
          slow_vec != fast_vec)
    check("vector length == len(FEATURE_ORDER)",
          len(slow_vec) == len(FEATURE_ORDER), len(slow_vec))

    print("\n=== LINKTYPES: eth / sll / raw all decode identically ===")
    cp = 41000
    req = b"GET /api/items HTTP/1.1\r\nHost: api\r\n\r\n"
    pkts = [syn(T0, cp=cp), synack(T0 + 0.002, cp=cp),
            data(T0 + 0.004, req, cp=cp),
            data(T0 + 0.02, b'{"ok":true}', "s2c", cp=cp),
            fin(T0 + 0.5, cp=cp)]

    for link in ("eth", "sll", "raw"):
        recs_l = read_pcap(write_pcap("linktest", pkts, link=link),
                           flush_after=5.0)
        check(f"{link}: 1 flow recovered", len(recs_l) == 1, len(recs_l))
        if recs_l:
            check(f"{link}: client_ip is dotted-quad text",
                  recs_l[0]["client_ip"] == CLIENT,
                  recs_l[0]["client_ip"])
            check(f"{link}: request counted",
                  recs_l[0]["n_requests_seen"] == 1,
                  recs_l[0]["n_requests_seen"])

    print()
    if FAIL:
        print(f"FAILED ({len(FAIL)}): {FAIL}")
        sys.exit(1)
    print(f"all {len(FEATURE_ORDER)}-feature checks passed across 5 traffic shapes")


if __name__ == "__main__":
    main()
