"""Time-based CUSUM using observed connection-start timestamps."""

from __future__ import annotations

from m2_triggers.connection_signal import connection_open_rate
from m2_triggers.cusum import CUSUM


class TimedCusum:
    """Evaluate a rolling connection-open rate on a fixed time grid."""

    def __init__(
        self,
        detector: CUSUM,
        window_s: float = 10.0,
        interval_s: float = 1.0,
    ) -> None:
        if window_s <= 0:
            raise ValueError("window_s must be greater than zero")
        if interval_s <= 0:
            raise ValueError("interval_s must be greater than zero")

        self.detector = detector
        self.window_s = float(window_s)
        self.interval_s = float(interval_s)
        self.next_sample_ts: float | None = None
        self.connection_starts: list[float] = []

    def on_connect(self, ts: float) -> None:
        """Record an observed connection start."""
        self.connection_starts.append(float(ts))

    def advance(self, now: float) -> list[tuple[float, float]]:
        """Evaluate every due sample at its scheduled timestamp."""
        now = float(now)

        if self.next_sample_ts is None:
            self.next_sample_ts = now

        results: list[tuple[float, float]] = []

        while self.next_sample_ts <= now:
            sample_ts = self.next_sample_ts
            signal = connection_open_rate(
                self.connection_starts,
                sample_ts,
                self.window_s,
            )

            if self.detector.update(signal):
                results.append((sample_ts, signal))

            self.next_sample_ts += self.interval_s

        # Keep all starts that could affect the next scheduled sample.
        cutoff = self.next_sample_ts - self.window_s
        self.connection_starts = [
            ts for ts in self.connection_starts if ts > cutoff
        ]

        return results
