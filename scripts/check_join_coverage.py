#!/usr/bin/env python3
"""
Does the side log join to the pcap?  Decisive, offline, deterministic.

Usage:
  python check_join_coverage.py CAPTURE.pcap SIDE_LOG.jsonl [PROXY_IP] [BACKEND_IP]
  e.g. python scripts/check_join_coverage.py captures/live_capture.pcap \
         reports/runs/run_1794079794/side_log.jsonl 172.18.0.2 172.18.0.3

It reads only the pcap (dpkt) and the side log; no model, no dashboard.
Client-facing connection = SYN (no ACK) with dst == PROXY_IP:80.
Upstream connection     = SYN (no ACK) with dst == BACKEND_IP:80.
A client SYN is "matched" if the side log has the same (src_ip, src_port) and
the SYN time lies inside [start_ts - tol, end_ts + tol].
"""
import json
import socket
import sys
from collections import Counter

import dpkt

TOL = 2.0  # seconds of tolerance around the side-log window


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    pcap_path, log_path = sys.argv[1], sys.argv[2]
    proxy = sys.argv[3] if len(sys.argv) > 3 else "172.18.0.2"
    backend = sys.argv[4] if len(sys.argv) > 4 else "172.18.0.3"

    log = [json.loads(l) for l in open(log_path) if l.strip()]
    by_key = {}
    for r in log:
        by_key.setdefault((r["src_ip"], int(r["src_port"])), []).append(r)

    n_pkts = 0
    client, upstream, other = [], 0, 0
    pkts_per_conn = Counter()   # client->proxy packets per (src_ip, src_port)
    with open(pcap_path, "rb") as f:
        for ts, buf in dpkt.pcap.Reader(f):
            n_pkts += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, dpkt.tcp.TCP):
                    continue
                tcp = ip.data
                src, dst = socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst)
                if dst == proxy and tcp.dport == 80:
                    pkts_per_conn[(src, tcp.sport)] += 1
                if not (tcp.flags & dpkt.tcp.TH_SYN) or (tcp.flags & dpkt.tcp.TH_ACK):
                    continue
                if dst == proxy and tcp.dport == 80:
                    client.append((src, tcp.sport, ts))
                elif dst == backend and tcp.dport == 80:
                    upstream += 1
                else:
                    other += 1
            except Exception:
                continue

    # a retransmitted SYN has the same (src, sport) within a few seconds: count once
    seen, uniq = set(), []
    for src, sport, ts in sorted(client, key=lambda x: x[2]):
        if (src, sport) in seen:
            continue
        seen.add((src, sport))
        uniq.append((src, sport, ts))

    matched, unmatched, reason = 0, [], Counter()
    for src, sport, ts in uniq:
        rows = by_key.get((src, sport))
        if not rows:
            unmatched.append((src, sport, ts))
            reason["no side-log row for this (ip, port)"] += 1
            continue
        if any(
            r["start_ts"] - TOL
            <= ts
            <= ((r["end_ts"] if r["end_ts"] is not None else float("inf")) + TOL)
            for r in rows
        ):
            matched += 1
        else:
            unmatched.append((src, sport, ts))
            reason["(ip, port) found but outside the time window"] += 1

    print(f"packets read:                 {n_pkts}")
    print(f"client SYNs (to {proxy}:80):   {len(client)}  unique (ip,port): {len(uniq)}")
    print(f"upstream SYNs (to {backend}:80): {upstream}")
    print(f"side-log rows:                {len(log)}  (distinct (ip,port): {len(by_key)})")
    pct = 100 * matched / max(1, len(uniq))
    print(f"\nclient connections matched to side log: {matched}/{len(uniq)} = {pct:.1f}%")
    for k, v in reason.items():
        print(f"  unmatched because {k}: {v}")
    # side-log rows that never appear in the pcap
    pcap_keys = {(s, p) for s, p, _ in uniq}
    missing = [k for k in by_key if k not in pcap_keys]
    print(f"side-log (ip,port) pairs with no SYN in the pcap: {len(missing)} of {len(by_key)}")
    if unmatched:
        print("\nfirst 10 unmatched client SYNs (ip, port, seconds after first SYN):")
        t0 = uniq[0][2]
        for s, p, t in unmatched[:10]:
            print(f"  {s}:{p}  +{t - t0:.1f}s")
        ips = Counter(s for s, _, _ in unmatched)
        log_ips = {r["src_ip"] for r in log}
        print("\nunmatched source IPs that never appear in the side log:",
              sorted(i for i in ips if i not in log_ips)[:10])
    total_pk = sum(pkts_per_conn.values())
    if total_pk:
        um_keys = {(s_, p_) for s_, p_, _ in unmatched}
        um_pk = sum(v for k, v in pkts_per_conn.items() if k in um_keys)
        print(f"\nclient->proxy packets: {total_pk}; carried by the {len(um_keys)} UNMATCHED connections: "
              f"{um_pk} ({100 * um_pk / total_pk:.1f}%)")
        print("top 8 connections by packets (M = has side-log row, U = no side-log row):")
        for (s_, p_), v in pkts_per_conn.most_common(8):
            print(f"  {'U' if (s_, p_) in um_keys else 'M'}  {s_}:{p_}  {v} packets")
    print("\nVERDICT:", "join is fine; the problem is scoring throughput, not IPs/NAT"
          if pct >= 90 else "join coverage is low; inspect the unmatched list above")


if __name__ == "__main__":
    main()
