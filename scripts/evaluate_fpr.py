
"""Offline flow-alert evaluation on a benign PCAP.

This reports flow-level alert statistics, NOT the assignment's
time-based false-positive rate.
"""
import argparse
import json
import time
from collections import Counter
from pathlib import Path

from m1_capture.features import WindowTracker
from m1_capture.sensor import read_pcap, parse_http
from m2_triggers.pipeline import detect_flow_triggers


def evaluate(pcap_path: Path) -> dict:
    started = time.perf_counter()
    records = read_pcap(pcap_path, flush_after=5.0)

    if not records:
        raise ValueError("PCAP produced no TCP flow records; cannot evaluate.")

    records.sort(key=lambda r: (r["t_first"], r["flow_id"]))

    # The reader emits one record per flow for this capture. Fail loudly
    # rather than silently counting duplicate snapshots as separate flows.
    flow_ids = [str(r["flow_id"]) for r in records]
    if len(flow_ids) != len(set(flow_ids)):
        raise ValueError(
            "Duplicate flow IDs found. Resolve snapshots before evaluating."
        )

    capture_start = min(float(r["t_first"]) for r in records)
    capture_end = max(float(r["t_last"]) for r in records)
    capture_duration = max(0.0, capture_end - capture_start)

    # Build observed connection intervals independently of WindowTracker's
    # latest-open interval matching. None means still open at capture end.
    intervals = []
    for rec in records:
        opened = float(rec["t_first"])
        closed = rec.get("t_close")
        if closed is not None:
            closed = float(closed)
            if closed < opened:
                closed = None
        intervals.append(
            (str(rec["client_ip"]), opened, closed, str(rec["flow_id"]))
        )

    per_trigger = Counter()
    alerted_flows = set()
    observations = 0
    window = WindowTracker(window_s=10.0)

    # Evaluate each flow at its last observed packet. Compute concurrency
    # from intervals at that instant; don't mutate it with on_connect/close.
    for rec in records:
        now = float(rec["t_last"])
        entity = str(rec["client_ip"])

        live = sum(
            1
            for client, opened, closed, _flow_id in intervals
            if client == entity
            and opened <= now
            and (closed is None or closed > now)
        )
        opened_recently = sum(
            1
            for client, opened, _closed, _flow_id in intervals
            if client == entity
            and now - 10.0 <= opened <= now
        )

        # Supply an isolated tracker populated with synthetic intervals
        # whose concurrency matches the timestamp being evaluated.
        # The interval list is populated directly to avoid on_close's
        # latest-open pairing behavior.
        window.intervals[entity] = [
            [opened, closed]
            for client, opened, closed, _flow_id in intervals
            if client == entity
        ]

        http = parse_http(bytes.fromhex(rec["fwd_payload"]))
        flow, events = detect_flow_triggers(
            rec=rec,
            http=http,
            window=window,
            entity=entity,
            now=now,
        )

        # Sanity-check the concurrency used by the detector.
        if int(round(flow.concurrent_conns)) != live:
            raise AssertionError(
                f"Concurrency mismatch for {flow.flow_id}: "
                f"detector={flow.concurrent_conns}, reconstructed={live}"
            )

        observations += 1
        for event in events:
            per_trigger[event.trigger] += 1
            alerted_flows.add(flow.flow_id)

    elapsed = time.perf_counter() - started
    result = {
        "pcap": str(pcap_path),
        "capture_duration_seconds": round(capture_duration, 3),
        "processing_seconds": round(elapsed, 3),
        "packets": None,
        "unique_flow_records": len(records),
        "closed_flows_observed": sum(
            rec.get("t_close") is not None for rec in records
        ),
        "still_open_at_capture_end": sum(
            rec.get("t_close") is None for rec in records
        ),
        "observations": observations,
        "alerts_by_trigger": dict(per_trigger),
        "flows_with_any_alert": len(alerted_flows),
        "flow_alert_fraction_percent": round(
            100.0 * len(alerted_flows) / observations, 4
        ) if observations else None,
        "note": (
            "Offline flow-alert fraction only. Each reconstructed flow is "
            "evaluated once at its last observed packet. This is not a "
            "time-based false-positive rate or a combined-trigger FPR."
        ),
    }
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to a benign-only PCAP file")
    parser.add_argument("--output", default="fpr_results.json")
    args = parser.parse_args()

    result = evaluate(Path(args.pcap))
    print(json.dumps(result, indent=2))
    Path(args.output).write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )
    print(f"\nSaved results to {args.output}")
