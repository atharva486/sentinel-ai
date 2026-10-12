"""Fixed-cadence sampler for CUSUM connection-open-rate detection."""

from __future__ import annotations

from m2_triggers.cusum import CUSUM


class CusumSampler:
    """Sample a connection-open signal at fixed time intervals."""

    def __init__(
        self,
        detector: CUSUM,
        interval_s: float = 1.0,
    ) -> None:
        if interval_s <= 0:
            raise ValueError("interval_s must be greater than zero")

        self.detector = detector
        self.interval_s = float(interval_s)
        self.next_sample_ts: float | None = None

    def update(self, ts: float, signal: float) -> list[float]:
        """Return timestamps at which CUSUM detected a shift.

        The caller must provide the signal sampled or reconstructed for
        each scheduled instant. Repeated calls within one interval do
        not feed repeated values into CUSUM.
        """
        ts = float(ts)
        signal = float(signal)

        if self.next_sample_ts is None:
            self.next_sample_ts = ts

        alerts = []

        while self.next_sample_ts <= ts:
            sample_ts = self.next_sample_ts
            if self.detector.update(signal):
                alerts.append(sample_ts)

            self.next_sample_ts += self.interval_s

        return alerts
