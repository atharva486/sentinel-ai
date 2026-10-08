#!/usr/bin/env python3
"""
sensor.py — pcap -> raw flow records.

WHY THIS FILE EXISTS
--------------------
nginx access logs CANNOT see slow attacks. nginx logs a request when it
COMPLETES. A Slowloris header never completes, so no log line is ever
written. The signature of a slow attack (connection open, data trickling,
nothing finished) is invisible to any completion-based logger.

So we do not use nginx logs as the source of truth. We read the packet
stream and reconstruct connections ourselves, including ones that never end.

Two properties this file guarantees:

  1. UNFINISHED FLOWS ARE EMITTED. Flows are flushed while still open
     (flush_after_s) so a Slowloris flow that never closes still produces a
     record. This is the single most important property in the file.

  2. DIRECTION IS KNOWN. The side that sent the SYN is the client. We never
     guess from payload.

Capture with tcpdump on the proxy container's interface:

    docker compose exec proxy tcpdump -i eth0 -w /captures/w.pcap \\
        -s 0 'tcp port 80'

Rotate per attack window (5s) so replay/processing stays bounded.
"""
from __future__ import annotations

import argparse
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path

import dpkt

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08

PAYLOAD_CAP = 65536        # bytes of payload kept per direction; totals are exact
DEFAULT_FLUSH_AFTER_S = 5.0
DEFAULT_TAIL = 30.0


@dataclass
class FlowState:
    """Accumulated state of one TCP connection, updated packet by packet."""
    flow_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int

    t_syn: float | None = None
    t_synack: float | None = None
    t_first: float = 0.0          # first byte seen in either direction
    t_last: float = 0.0
    t_close: float | None = None

    fwd_bytes: int = 0
    fwd_pkts: int = 0
    bwd_bytes: int = 0
    bwd_pkts: int = 0

    fwd_times: list[float] = field(default_factory=list)
    fwd_payload: bytearray = field(default_factory=bytearray)
    bwd_payload: bytearray = field(default_factory=bytearray)

    syn_retries: int = 0
    closed_by: str = ""           # "client" | "server" | ""
    finalized: bool = False

    # ---- convenience counters, filled during ingest ----
    n_requests_seen: int = 0

    def add(self, ts: float, direction: str, payload: bytes, flags: int) -> None:
        """Fold one packet into this flow."""
        if self.t_first == 0.0:
            self.t_first = ts
        self.t_last = max(self.t_last, ts)

        if direction == "fwd":
            self.fwd_pkts += 1
            self.fwd_bytes += len(payload)
            self.fwd_times.append(ts)
            if len(self.fwd_payload) < PAYLOAD_CAP:
                self.fwd_payload.extend(payload[: PAYLOAD_CAP - len(self.fwd_payload)])
        else:
            self.bwd_pkts += 1
            self.bwd_bytes += len(payload)
            if len(self.bwd_payload) < PAYLOAD_CAP:
                self.bwd_payload.extend(payload[: PAYLOAD_CAP - len(self.bwd_payload)])

        # request-line detection on the forward direction only
        if direction == "fwd" and payload:
            self.n_requests_seen += count_request_lines(payload)

        if flags & FIN:
            self.t_close = ts
            self.closed_by = "client" if direction == "fwd" else "server"
        elif flags & RST:
            self.t_close = ts
            self.closed_by = "client" if direction == "fwd" else "server"

    def to_record(self) -> dict:
        """Serialise to the raw form that features.py consumes."""
        return {
            "flow_id": self.flow_id,
            "client_ip": self.client_ip,
            "client_port": self.client_port,
            "server_ip": self.server_ip,
            "server_port": self.server_port,
            "t_syn": self.t_syn,
            "t_synack": self.t_synack,
            "t_first": self.t_first,
            "t_last": self.t_last,
            "t_close": self.t_close,
            "fwd_bytes": self.fwd_bytes,
            "fwd_pkts": self.fwd_pkts,
            "bwd_bytes": self.bwd_bytes,
            "bwd_pkts": self.bwd_pkts,
            "fwd_times": self.fwd_times,
            "fwd_payload": bytes(self.fwd_payload).hex(),
            "bwd_payload": bytes(self.bwd_payload).hex(),
            "syn_retries": self.syn_retries,
            "closed_by": self.closed_by,
            "finalized": self.finalized,
            "n_requests_seen": self.n_requests_seen,
        }


METHODS = (b"GET", b"POST", b"PUT", b"HEAD", b"DELETE", b"PATCH",
           b"OPTIONS", b"TRACE", b"CONNECT")


def count_request_lines(buf: bytes) -> int:
    """Count COMPLETE HTTP request lines in a payload chunk.

    A request line only counts if it is terminated by CRLF, i.e. the pattern
    "<METHOD> <path> HTTP/1.x\\r\\n".

    The naive version counted any occurrence of b"GET ", so a Slowloris flow
    trickling "GET /api/se..." one fragment at a time scored
    requests_per_conn == 1 -- indistinguishable from a normal single-request
    browser visit. Requiring the CRLF terminator is what makes an incomplete
    request visible as incomplete.
    """
    n = 0
    for method in METHODS:
        start = 0
        needle = method + b" "
        while True:
            i = buf.find(needle, start)
            if i < 0:
                break
            # the line must contain " HTTP/1." and terminate with CRLF
            eol = buf.find(b"\r\n", i)
            if eol > 0 and b" HTTP/1." in buf[i:eol]:
                n += 1
            start = i + len(needle)
    return n


def parse_http(payload: bytes) -> dict:
    """Minimal HTTP request parse. Deliberately tolerant.

    Returns:
      method, path, header_complete, header_bytes, declared_body,
      req_count

    header_complete is False when we never saw CRLFCRLF — which is exactly
    the Slowloris case, and the single most discriminative field we have.
    """
    end = payload.find(b"\r\n\r\n")
    header_complete = end >= 0
    head = payload[: end + 4] if header_complete else payload

    lines = head.split(b"\r\n")
    method, path = "", ""
    if lines and any(lines[0].startswith(m) for m in METHODS):
        parts = lines[0].split()
        if len(parts) >= 2:
            method = parts[0].decode("latin-1")
            path = parts[1].decode("latin-1")

    declared = 0
    for ln in lines[1:]:
        low = ln.lower()
        if low.startswith(b"content-length:"):
            try:
                declared = int(ln.split(b":", 1)[1].strip())
            except ValueError:
                declared = 0
            break

    return {
        "method": method,
        "path": path,
        "header_complete": header_complete,
        "header_bytes": (end + 4) if header_complete else len(payload),
        "declared_body": declared,
        "req_count": count_request_lines(payload),
    }


class FlowTracker:
    """Accumulates FlowState objects from a packet stream."""

    def __init__(self, flush_after_s: float = DEFAULT_FLUSH_AFTER_S):
        self.flush_after_s = flush_after_s
        self.flows: dict[tuple, FlowState] = {}
        self._seen_syn: dict[tuple, bool] = {}

    @staticmethod
    def _key(src, sport, dst, dport) -> tuple:
        # direction-independent key so both halves land in the same flow
        a, b = (src, sport), (dst, dport)
        return (a, b) if a <= b else (b, a)

    def ingest(self, ts: float, src, sport, dst, dport, payload, flags) -> None:
        key = self._key(src, sport, dst, dport)
        fs = self.flows.get(key)

        if fs is None:
            # First packet we see for this connection defines client->server,
            # unless it is a SYN-ACK, in which case the SYN we missed set it.
            is_syn = bool(flags & SYN) and not (flags & ACK)
            is_synack = bool(flags & SYN) and bool(flags & ACK)
            if is_synack:
                # SYN was missed; infer client from the SYN-ACK's destination
                c_ip, c_port, s_ip, s_port = dst, dport, src, sport
                direction = "fwd"
            else:
                c_ip, c_port, s_ip, s_port = src, sport, dst, dport
                direction = "fwd"
                if is_syn:
                    fs_t_syn = ts
                else:
                    fs_t_syn = None
            fs = FlowState(
                flow_id=f"{c_ip}:{c_port}-{s_ip}:{s_port}",
                client_ip=c_ip, client_port=c_port,
                server_ip=s_ip, server_port=s_port,
            )
            if direction == "fwd":
                fs.t_syn = ts if is_syn else None
            self.flows[key] = fs

        if src == fs.client_ip and sport == fs.client_port:
            direction = "fwd"
        else:
            direction = "bwd"

        is_syn = bool(flags & SYN) and not (flags & ACK)
        is_synack = bool(flags & SYN) and bool(flags & ACK)

        if is_syn and direction == "fwd":
            fs.t_syn = ts
        elif is_synack and direction == "bwd":
            fs.t_synack = ts

        fs.add(ts, direction, payload, flags)

        if fs.t_close is not None:
            fs.finalized = True

    def flush(self, now: float) -> list[FlowState]:
        """Emit flows that are closed, or open and older than flush_after_s.

        The second case is the important one: it is how a Slowloris flow that
        never closes still becomes a usable record.
        """
        out = []
        for key, fs in list(self.flows.items()):
            age = now - fs.t_last
            if fs.t_close is not None:
                out.append(fs)
                del self.flows[key]
            elif age >= self.flush_after_s:
                snapshot = FlowState(**{**fs.__dict__,
                                        "fwd_payload": fs.fwd_payload.copy(),
                                        "bwd_payload": fs.bwd_payload.copy(),
                                        "fwd_times": list(fs.fwd_times)})
                snapshot.finalized = False
                out.append(snapshot)
        return out


def _unwrap(buf: bytes, linktype: int):
    """Return an IPv4 packet from a frame, or None.

    tcpdump reports three different link types depending on where you capture,
    and getting this wrong silently yields zero flows — which reads as "no
    attacks detected" rather than as an error. So all three are handled.

      DLT_EN10MB    (1)   Ethernet — capturing on eth0
      DLT_LINUX_SLL (113) "any" device, and Docker's veth interfaces
      DLT_RAW       (101) loopback, and synthetic pcaps from tests
    """
    if linktype == dpkt.pcap.DLT_EN10MB:
        ip = dpkt.ethernet.Ethernet(buf).data
    elif linktype == dpkt.pcap.DLT_LINUX_SLL:
        # SLL header is 16 bytes. dpkt's parser exists but is picky about the
        # header length field, so slice off the fixed prefix and parse the IP
        # directly — fewer ways to fail silently.
        if len(buf) < 16:
            return None
        ip = dpkt.ip.IP(buf[16:])
    elif linktype == dpkt.pcap.DLT_RAW:
        ip = dpkt.ip.IP(buf)
    else:
        raise SystemExit(
            f"unsupported pcap link type {linktype}; capture with "
            "'tcpdump -i eth0' (Ethernet), '-i any' (SLL) or build DLT_RAW")

    return ip if isinstance(ip, dpkt.ip.IP) else None


def read_pcap(path: Path, flush_after: float) -> list[dict]:
    """Read a pcap file, return raw flow records.

    Flows that never closed are still emitted (finalized=False). That is the
    property that makes slow attacks visible at all.
    """
    tracker = FlowTracker(flush_after_s=flush_after)
    records: list[dict] = []
    last_ts = 0.0

    with path.open("rb") as fh:
        try:
            reader = dpkt.pcap.Reader(fh)
        except (ValueError, dpkt.dpkt.UnpackError) as exc:
            raise SystemExit(f"{path}: not a readable pcap ({exc})") from exc

        linktype = reader.datalink()

        for ts, buf in reader:
            last_ts = ts
            ip = _unwrap(buf, linktype)
            if ip is None:
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            # dpkt gives addresses as packed 4-byte strings; everything else
            # (comparisons, JSON, Redis keys) wants dotted-quad text.
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            tracker.ingest(ts, src, tcp.sport, dst, tcp.dport,
                           bytes(tcp.data), tcp.flags)

        # end of capture: flush everything still open, once
        for fs in tracker.flush(last_ts + flush_after + 1.0):
            fs.finalized = False
            records.append(fs.to_record())

    records.sort(key=lambda r: r["t_first"])
    return records


def main() -> None:
    ap = argparse.ArgumentParser(description="pcap -> raw flow records (JSONL)")
    ap.add_argument("pcap", type=Path)
    ap.add_argument("-o", "--out", type=Path, default=Path("flows.jsonl"))
    ap.add_argument("--flush-after", type=float, default=DEFAULT_FLUSH_AFTER_S)
    args = ap.parse_args()

    recs = read_pcap(args.pcap, args.flush_after)
    with args.out.open("w", encoding="utf-8") as fh:
        for r in recs:
            fh.write(json.dumps(r) + "\n")

    fin = sum(1 for r in recs if r["finalized"])
    print(f"{len(recs)} flow records ({fin} finalized, {len(recs)-fin} mid-flight)")
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
