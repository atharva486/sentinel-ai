"""Offline, timestamp-based CUSUM evaluation on TCP connection starts.

Calibration and evaluation must use separate benign captures.
The reported alert frequency is not automatically an assignment-compliant FPR.
"""

import argparse
import json
import statistics
import time
from pathlib import Path

import dpkt

from m1_capture.sensor import read_pcap
from m2_triggers.connection_signal import connection_open_rate
from m2_triggers.cusum import CUSUM


def pcap_time_bounds(pcap_path: Path) -> tuple[float, float]:
    """Return first and last packet timestamps from a classic PCAP."""
    first = None
    last = None

    with pcap_path.open("rb") as handle:
        reader = dpkt.pcap.Reader(handle)
        for ts, _ in reader:
            ts = float(ts)
            if first is None:
                first = ts
            last = ts

    if first is None or last is None:
        raise ValueError(f"No packets found in {pcap_path}")

    if last <= first:
        raise ValueError(
            f"Capture must span more than zero seconds: {last - first:.3f}s"
        )

    return first, last


def connection_starts_from_pcap(
    pcap_path: Path,
) -> tuple[list[float], float, float]:
    records = read_pcap(pcap_path, flush_after=5.0)
    if not records:
        raise ValueError(f"No TCP flow records found in {pcap_path}")

    starts = sorted(float(rec["t_first"]) for rec in records)
    capture_start, capture_end = pcap_time_bounds(pcap_path)
    duration = capture_end - capture_start

    if duration < 1:
        raise ValueError(
            f"Capture too short to sample reliably: {duration:.3f}s"
        )

    return starts, duration, capture_end


def sample_signal(
    starts: list[float],
    window_s: float,
    interval_s: float,
    capture_end: float | None = None,
) -> list[tuple[float, float]]:
    """Sample on a fixed grid through the requested capture end."""
    if not starts:
        raise ValueError("No connection starts available")
    if window_s <= 0 or interval_s <= 0:
        raise ValueError("window_s and interval_s must be positive")

    first = starts[0]
    last = starts[-1] if capture_end is None else float(capture_end)
    if last < first:
        raise ValueError("capture_end cannot precede the first connection start")

    samples = []
    count = 0
    while True:
        ts = first + count * interval_s
        if ts > last + 1e-9:
            break
        samples.append((ts, connection_open_rate(starts, ts, window_s)))
        count += 1

    return samples


def calibrate(samples: list[tuple[float, float]]) -> tuple[float, float]:
    values = [value for _, value in samples]
    if len(values) < 2:
        raise ValueError("Need at least two calibration samples")

    mu = statistics.mean(values)
    sigma = statistics.pstdev(values)
    if sigma <= 0:
        raise ValueError(
            "Calibration signal has zero variance; collect a more varied "
            "benign capture before calibrating CUSUM."
        )

    return mu, sigma


def evaluate(
    pcap_path: Path,
    mu: float,
    sigma: float,
    window_s: float,
    interval_s: float,
    k: float,
    h: float,
) -> dict:
    started = time.perf_counter()
    connection_starts, capture_duration, capture_end = (
        connection_starts_from_pcap(pcap_path)
    )
    samples = sample_signal(
        connection_starts, window_s, interval_s, capture_end=capture_end
    )
    detector = CUSUM(mu=mu, sigma=sigma, k=k, h=h)

    alert_times = []
    for ts, signal in samples:
        if detector.update(signal):
            alert_times.append(ts)

    elapsed = time.perf_counter() - started
    return {
        "pcap": str(pcap_path),
        "capture_duration_seconds": round(capture_duration, 3),
        "processing_seconds": round(elapsed, 3),
        "unique_connection_start_events": len(connection_starts),
        "sampling_interval_seconds": interval_s,
        "signal_window_seconds": window_s,
        "sample_count": len(samples),
        "baseline_mu": mu,
        "baseline_sigma": sigma,
        "k": k,
        "h": h,
        "cusum_alert_count": len(alert_times),
        "alert_timestamps": [round(ts, 3) for ts in alert_times],
        "alerts_per_sampled_second": (
            round(len(alert_times) / len(samples), 6) if samples else None
        ),
        "note": (
            "Offline connection-start replay sampled through the last PCAP "
            "packet timestamp. Calibration and evaluation captures must be "
            "separate. Alert frequency is not automatically the assignment's "
            "false-positive rate."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--calibration", required=True, help="Benign calibration PCAP")
    parser.add_argument("--evaluation", required=True, help="Separate benign evaluation PCAP")
    parser.add_argument("--window", type=float, default=10.0)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--k", type=float, default=0.5)
    parser.add_argument("--h", type=float, default=5.0)
    parser.add_argument("--output", default="cusum_eval_results.json")
    args = parser.parse_args()

    calibration_starts, calibration_duration, calibration_end = (
        connection_starts_from_pcap(Path(args.calibration))
    )
    calibration_samples = sample_signal(
        calibration_starts,
        args.window,
        args.interval,
        capture_end=calibration_end,
    )
    mu, sigma = calibrate(calibration_samples)

    result = evaluate(
        Path(args.evaluation),
        mu,
        sigma,
        args.window,
        args.interval,
        args.k,
        args.h,
    )
    result["calibration_pcap"] = args.calibration
    result["calibration_duration_seconds"] = round(calibration_duration, 3)
    result["calibration_sample_count"] = len(calibration_samples)

    print(json.dumps(result, indent=2))
    Path(args.output).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"\nSaved results to {args.output}")


if __name__ == "__main__":
    main()
