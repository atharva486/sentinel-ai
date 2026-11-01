#!/usr/bin/env python3
"""
Time-based false positive rate evaluation for Module 2 triggers.

This evaluator computes FPR using time-based observation units as required
by the assignment, not flow-alert fractions.
"""

import argparse
import json
import time
from collections import defaultdict
from pathlib import Path

from m1_capture.features import WindowTracker
from m1_capture.sensor import read_pcap, parse_http
from m2_triggers.pipeline import detect_flow_triggers
from m2_triggers.connection_signal import connection_open_rate
from m2_triggers.cusum import CUSUM


def evaluate_fixed_and_stall(pcap_path: Path) -> dict:
    """Evaluate fixed rules and stall detector on benign PCAP.

    Returns per-trigger alert counts and time-based FPR metrics.
    """
    started = time.perf_counter()
    records = read_pcap(pcap_path, flush_after=5.0)

    if not records:
        raise ValueError("PCAP produced no TCP flow records; cannot evaluate.")

    records.sort(key=lambda r: (r["t_first"], r["flow_id"]))

    capture_start = min(float(r["t_first"]) for r in records)
    capture_end = max(float(r["t_last"]) for r in records)
    capture_duration = max(0.0, capture_end - capture_start)

    # Build observed connection intervals
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

    # Track alerts per trigger
    per_trigger_alerts = defaultdict(list)  # trigger -> list of (ts, entity, flow_id)
    alerted_flow_ids = set()

    window = WindowTracker(window_s=10.0)

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

        for event in events:
            per_trigger_alerts[event.trigger].append({
                "ts": event.ts,
                "entity": event.entity_key,
                "flow_id": flow.flow_id,
                "detail": event.detail,
            })
            alerted_flow_ids.add(flow.flow_id)

    elapsed = time.perf_counter() - started

    # Compute time-based FPR: alerts per hour of capture time
    hours = capture_duration / 3600.0
    fpr_per_hour = {trigger: len(alerts) / hours if hours > 0 else 0.0
                    for trigger, alerts in per_trigger_alerts.items()}

    return {
        "capture_duration_seconds": round(capture_duration, 3),
        "processing_seconds": round(elapsed, 3),
        "unique_flow_records": len(records),
        "closed_flows_observed": sum(1 for r in records if r.get("t_close") is not None),
        "still_open_at_capture_end": sum(1 for r in records if r.get("t_close") is None),
        "total_flow_evaluations": len(records),
        "alerts_by_trigger": {k: len(v) for k, v in per_trigger_alerts.items()},
        "alert_details_by_trigger": {k: v for k, v in per_trigger_alerts.items()},
        "flows_with_any_alert": len(alerted_flow_ids),
        "flow_alert_fraction_percent": round(100.0 * len(alerted_flow_ids) / len(records), 4) if records else 0.0,
        "capture_hours": round(hours, 4),
        "fpr_per_hour_by_trigger": {k: round(v, 4) for k, v in fpr_per_hour.items()},
        "note": "Time-based FPR: alerts per hour of capture duration. Flow-alert fraction also reported for reference."
    }


def evaluate_cusum_time_based(
    pcap_path: Path,
    mu: float,
    sigma: float,
    window_s: float = 10.0,
    interval_s: float = 1.0,
    k: float = 0.5,
    h: float = 5.0,
) -> dict:
    """Evaluate CUSUM on benign PCAP using fixed time-grid sampling.

    Returns alert count and time-based FPR (alerts per sampled interval).
    """
    from m1_capture.sensor import read_pcap

    records = read_pcap(pcap_path, flush_after=5.0)
    if not records:
        raise ValueError("PCAP produced no TCP flow records")

    connection_starts = sorted(float(rec["t_first"]) for rec in records)
    capture_start = connection_starts[0]
    capture_end = max(float(rec["t_last"]) for rec in records)
    capture_duration = capture_end - capture_start

    # Sample on fixed grid
    samples = []
    count = 0
    while True:
        ts = capture_start + count * interval_s
        if ts > capture_end + 1e-9:
            break
        signal = connection_open_rate(connection_starts, ts, window_s)
        samples.append((ts, signal))
        count += 1

    detector = CUSUM(mu=mu, sigma=sigma, k=k, h=h)
    alert_times = []

    for ts, signal in samples:
        if detector.update(signal):
            alert_times.append(ts)

    total_samples = len(samples)
    alert_rate = len(alert_times) / total_samples if total_samples > 0 else 0.0
    hours = capture_duration / 3600.0
    fpr_per_hour = len(alert_times) / hours if hours > 0 else 0.0

    return {
        "capture_duration_seconds": round(capture_duration, 3),
        "unique_connection_start_events": len(connection_starts),
        "sampling_interval_seconds": interval_s,
        "signal_window_seconds": window_s,
        "sample_count": total_samples,
        "baseline_mu": mu,
        "baseline_sigma": sigma,
        "k": k,
        "h": h,
        "cusum_alert_count": len(alert_times),
        "alert_timestamps": [round(ts, 3) for ts in alert_times],
        "alerts_per_sampled_interval": round(alert_rate, 6),
        "alerts_per_hour": round(fpr_per_hour, 4),
        "note": "CUSUM evaluated on fixed time grid. FPR reported as alerts per sampled interval and per hour."
    }


def evaluate_combined(pcap_path: Path, cusum_params: dict | None = None) -> dict:
    """Evaluate combined detector (all triggers) with deduplication.

    Combined alert = any trigger fires for an entity in a 1-second time bin.
    """
    started = time.perf_counter()
    records = read_pcap(pcap_path, flush_after=5.0)

    if not records:
        raise ValueError("PCAP produced no TCP flow records")

    records.sort(key=lambda r: (r["t_first"], r["flow_id"]))

    capture_start = min(float(r["t_first"]) for r in records)
    capture_end = max(float(r["t_last"]) for r in records)
    capture_duration = capture_end - capture_start

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

    # Fixed rules + stall alerts (per-flow)
    per_trigger_alerts = defaultdict(list)
    window = WindowTracker(window_s=10.0)

    for rec in records:
        now = float(rec["t_last"])
        entity = str(rec["client_ip"])

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
            cusum_detectors=None,  # CUSUM handled separately
        )

        for event in events:
            per_trigger_alerts[event.trigger].append({
                "ts": event.ts,
                "entity": event.entity_key,
                "flow_id": flow.flow_id,
            })

    # CUSUM alerts (time-grid) if parameters provided
    cusum_alerts = []
    if cusum_params:
        connection_starts = sorted(float(rec["t_first"]) for rec in records)
        detector = CUSUM(
            mu=cusum_params["mu"],
            sigma=cusum_params["sigma"],
            k=cusum_params["k"],
            h=cusum_params["h"],
        )
        window_s = cusum_params.get("window_s", 10.0)
        interval_s = cusum_params.get("interval_s", 1.0)

        count = 0
        while True:
            ts = capture_start + count * interval_s
            if ts > capture_end + 1e-9:
                break
            signal = connection_open_rate(connection_starts, ts, window_s)
            if detector.update(signal):
                cusum_alerts.append({"ts": ts, "entity": "global", "signal": signal})
            count += 1

    per_trigger_alerts["cusum"] = cusum_alerts

    # Combined deduplication: 1-second time bins per entity
    combined_bins = set()  # (entity, bin_ts)
    for trigger, alerts in per_trigger_alerts.items():
        for alert in alerts:
            entity = alert["entity"]
            ts = alert["ts"]
            bin_ts = int(ts)  # 1-second bin
            combined_bins.add((entity, bin_ts))

    elapsed = time.perf_counter() - started
    hours = capture_duration / 3600.0

    return {
        "capture_duration_seconds": round(capture_duration, 3),
        "processing_seconds": round(elapsed, 3),
        "unique_flow_records": len(records),
        "per_trigger_alert_counts": {k: len(v) for k, v in per_trigger_alerts.items()},
        "combined_alert_bins": len(combined_bins),
        "combined_fpr_per_hour": round(len(combined_bins) / hours, 4) if hours > 0 else 0.0,
        "cusum_params_used": cusum_params,
        "note": "Combined detector: unique (entity, 1-second bin) pairs where any trigger fired. FPR = combined alert bins per hour."
    }


def main():
    parser = argparse.ArgumentParser(description="Time-based FPR evaluation for Module 2")
    parser.add_argument("pcap", help="Path to benign PCAP")
    parser.add_argument("--output", default="fpr_time_based.json")
    parser.add_argument("--cusum-calibration", help="Separate benign PCAP for CUSUM calibration")
    parser.add_argument("--cusum-window", type=float, default=10.0)
    parser.add_argument("--cusum-interval", type=float, default=1.0)
    parser.add_argument("--cusum-k", type=float, default=0.5)
    parser.add_argument("--cusum-h", type=float, default=5.0)
    args = parser.parse_args()

    pcap_path = Path(args.pcap)

    # Evaluate fixed rules + stall
    print("Evaluating fixed rules + stall detector...")
    fixed_stall_result = evaluate_fixed_and_stall(pcap_path)

    # Calibrate CUSUM if calibration PCAP provided
    cusum_params = None
    if args.cusum_calibration:
        print("Calibrating CUSUM on separate benign capture...")
        from evaluate_cusum import connection_starts_from_pcap, sample_signal, calibrate
        cal_starts, cal_duration, cal_end = connection_starts_from_pcap(Path(args.cusum_calibration))
        cal_samples = sample_signal(cal_starts, args.cusum_window, args.cusum_interval, capture_end=cal_end)
        mu, sigma = calibrate(cal_samples)
        cusum_params = {
            "mu": mu,
            "sigma": sigma,
            "k": args.cusum_k,
            "h": args.cusum_h,
            "window_s": args.cusum_window,
            "interval_s": args.cusum_interval,
        }
        print(f"  Calibrated: mu={mu:.4f}, sigma={sigma:.4f}")

    # Evaluate CUSUM on evaluation PCAP
    cusum_result = {}
    if cusum_params:
        print("Evaluating CUSUM...")
        cusum_result = evaluate_cusum_time_based(pcap_path, **cusum_params)

    # Evaluate combined detector
    print("Evaluating combined detector...")
    combined_result = evaluate_combined(pcap_path, cusum_params)

    # Compile final result
    result = {
        "pcap": str(pcap_path),
        "fixed_and_stall": fixed_stall_result,
        "cusum": cusum_result,
        "combined": combined_result,
        "calibration_pcap": args.cusum_calibration,
    }

    print(json.dumps(result, indent=2))
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nSaved results to {args.output}")


if __name__ == "__main__":
    main()
