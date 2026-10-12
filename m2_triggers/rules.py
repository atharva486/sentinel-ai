"""Simple fixed-threshold rules for cheap L7 DoS detection."""

import math

from schemas import FlowRecord, TriggerEvent


DEFAULT_RATE_THRESHOLD = 100.0
DEFAULT_CONNECTION_THRESHOLD = 50.0


def detect_rules(
    flow: FlowRecord,
    rate_threshold: float = DEFAULT_RATE_THRESHOLD,
    connection_threshold: float = DEFAULT_CONNECTION_THRESHOLD,
) -> list[TriggerEvent]:
    """Return fixed-rule alerts for unusually high request rates or connections.

    Thresholds are provisional and must be evaluated on benign traffic.
    """
    for name, value in (
        ("rate_threshold", rate_threshold),
        ("connection_threshold", connection_threshold),
    ):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{name} must be a positive finite number")
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be a positive finite number")

    events = []

    if flow.requests_per_s > rate_threshold:
        events.append(
            TriggerEvent(
                ts=flow.ts_end,
                entity_key=flow.entity_key,
                trigger="rate",
                severity=0.7,
                detail={
                    "rule": "high_request_rate",
                    "observed": flow.requests_per_s,
                    "threshold": rate_threshold,
                },
            )
        )

    if flow.concurrent_conns > connection_threshold:
        events.append(
            TriggerEvent(
                ts=flow.ts_end,
                entity_key=flow.entity_key,
                trigger="connections",
                severity=0.8,
                detail={
                    "rule": "too_many_connections",
                    "observed": flow.concurrent_conns,
                    "threshold": connection_threshold,
                },
            )
        )

    return events
