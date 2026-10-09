"""Cheap detection rules for slow and stalled HTTP connections."""

from schemas import FlowRecord, TriggerEvent


STALL_THRESHOLD_S = 10.0
CONN_LIMIT_SOFT = 50
TTFB_THRESHOLD_S = 10.0


def detect(
    f: FlowRecord,
    trigger_names: list[str] | None = None,
) -> TriggerEvent | None:
    """Return a stall TriggerEvent when a flow matches a stall rule.

    The detector only uses features already present in FlowRecord.
    It does not block traffic or make the final defence decision.
    """
    reasons: list[str] = []
    severity = 0.0

    # An unfinished HTTP header on an old connection.
    if not f.header_complete and f.conn_age_s > STALL_THRESHOLD_S:
        reasons.append("header_incomplete")
        severity = max(severity, 0.85)

    # A declared request body is still less than half received.
    if (
        f.bytes_declared > 0
        and f.body_frac_sent < 0.5
        and f.conn_age_s > STALL_THRESHOLD_S
    ):
        reasons.append("body_incomplete")
        severity = max(
            severity,
            min(1.0, max(0.0, 1.0 - f.body_frac_sent)),
        )

    # A large body is arriving unusually slowly.
    if (
        0 < f.body_drip_rate_bps < 100
        and f.bytes_declared > 10_000
    ):
        reasons.append("slow_drip")
        severity = max(severity, 0.6)

    # An old connection has completed very few requests.
    if f.conn_age_s > 60 and f.requests_per_conn_so_far <= 2:
        reasons.append("long_idle_connection")
        severity = max(severity, 0.7)

    # Response latency exceeded the configured threshold.
    if f.time_to_first_byte > TTFB_THRESHOLD_S:
        reasons.append("slow_first_byte")
        severity = max(severity, 0.5)

    # A connection has remained open without any observed request.
    if f.requests_per_conn_so_far == 0 and f.conn_age_s > 20:
        reasons.append("zero_req_per_conn")
        severity = max(severity, 0.6)

    # Too many concurrent connections for this entity.
    if f.concurrent_conns > CONN_LIMIT_SOFT:
        reasons.append("too_many_conns")
        severity = max(severity, 0.8)

    if not reasons:
        return None

    return TriggerEvent(
        ts=f.ts_end,
        entity_key=f.entity_key,
        trigger="stall",
        severity=severity,
        detail={
            "reasons": reasons,
            "conn_age_s": f.conn_age_s,
        },
    )
