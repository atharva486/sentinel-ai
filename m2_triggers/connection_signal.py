"""Time-based connection-open-rate signal helpers."""

from __future__ import annotations


def connection_open_rate(
    connection_start_times: list[float],
    now: float,
    window_s: float = 10.0,
) -> float:
    """Count observed connection starts in (now-window_s, now], per second."""
    if window_s <= 0:
        raise ValueError("window_s must be greater than zero")

    lower_bound = float(now) - float(window_s)
    opened = sum(
        1
        for start in connection_start_times
        if lower_bound < float(start) <= float(now)
    )
    return opened / float(window_s)
