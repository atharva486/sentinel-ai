#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import socket
from dataclasses import dataclass, field
from pathlib import Path
import dpkt

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08

PAYLOAD_CAP = 65536
DEFAULT_FLUSH_AFTER_S = 5.0
DEFAULT_TAIL = 30.0

@dataclass
class FlowState:
    flow_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int

    t_syn: float | None = None
    t_synack: float | None = None
    t_first: float = 0.0
    t_last: float = 0.0
    t_close: float | None = None
    t_first_bwd: float = 0.0

    fwd_bytes: int = 0
    fwd_pkts: int = 0
    bwd_bytes: int = 0
    bwd_pkts: int = 0

    fwd_times: list[float] = field(default_factory=list)
    fwd_payload: bytearray = field(default_factory=bytearray)
    bwd_payload: bytearray = field(default_factory=bytearray)

    syn_retries: int = 0
    closed_by: str = ""
    finalized: bool = False

    n_requests_seen: int = 0

    def add(self, ts: float, direction: str, payload: bytes, flags: int) -> None:
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
            if payload and self.t_first_bwd == 0.0:
                self.t_first_bwd = ts
            if len(self.bwd_payload) < PAYLOAD_CAP:
                self.bwd_payload.extend(payload[: PAYLOAD_CAP - len(self.bwd_payload)])

        if direction == "fwd" and payload:
            self.n_requests_seen += count_request_lines(payload)

        if flags & FIN:
            self.t_close = ts
            self.closed_by = "client" if direction == "fwd" else "server"
        elif flags & RST:
            self.t_close = ts
            self.closed_by = "client" if direction == "fwd" else "server"

    def to_record(self) -> dict:
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
            "t_first_bwd": self.t_first_bwd,
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
    n = 0
    for method in METHODS:
        start = 0
        needle = method + b" "
        while True:
            i = buf.find(needle, start)
            if i < 0:
                break
            eol = buf.find(b"\r\n", i)
            if eol > 0 and b" HTTP/1." in buf[i:eol]:
                n += 1
            start = i + len(needle)
    return n

def parse_http(payload: bytes) -> dict:
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

    return {
        "method": method,
        "path": path,
        "header_complete": header_complete,
        "header_bytes": (end + 4) if header_complete else len(payload),
        "declared_body": declared,
        "req_count": count_request_lines(payload),
    }

class FlowTracker:
    def __init__(self, flush_after_s: float = DEFAULT_FLUSH_AFTER_S):
        self.flush_after_s = flush_after_s
        self.flows: dict[tuple, FlowState] = {}
        self._seen_syn: dict[tuple, bool] = {}

    @staticmethod
    def _key(src, sport, dst, dport) -> tuple:
        a, b = (src, sport), (dst, dport)
        return (a, b) if a <= b else (b, a)

    def ingest(self, ts: float, src, sport, dst, dport, payload, flags) -> None:
        key = self._key(src, sport, dst, dport)
        fs = self.flows.get(key)

        if fs is None:
            is_syn = bool(flags & SYN) and not (flags & ACK)
            is_synack = bool(flags & SYN) and bool(flags & ACK)
            if is_synack:
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
    if linktype == dpkt.pcap.DLT_EN10MB:
        ip = dpkt.ethernet.Ethernet(buf).data
    elif linktype == dpkt.pcap.DLT_LINUX_SLL:
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

def read_pcap(path: Path, flush_after: float,
              as_of_seconds: float | None = None) -> list[dict]:
    """Read a pcap and return flow records.

    If ``as_of_seconds`` is given, only packets with ts <= as_of_seconds are
    ingested, so the returned flows reflect connection state at that decision
    time (not the full flow lifetime).
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
            if as_of_seconds is not None and ts > as_of_seconds:
                break
            last_ts = ts
            ip = _unwrap(buf, linktype)
            if ip is None:
                continue
            tcp = ip.data
            if not isinstance(tcp, dpkt.tcp.TCP):
                continue

            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)

            tracker.ingest(ts, src, tcp.sport, dst, tcp.dport,
                           bytes(tcp.data), tcp.flags)

        now = as_of_seconds if as_of_seconds is not None else last_ts
        for fs in tracker.flush(now + flush_after + 1.0):
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