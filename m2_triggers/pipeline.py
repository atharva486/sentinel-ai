"""Adapter from reconstructed sensor flows to Module 2 triggers."""

from __future__ import annotations

from m1_capture.features import (
    WindowTracker,
    flow_features,
    open_flow_features,
)
from schemas import FlowRecord, TriggerEvent
from m2_triggers.rules import detect_rules
from m2_triggers.stall import detect as detect_stall
from m2_triggers.cusum import CUSUM


def flow_record_from_sensor(
    rec: dict,
    http: dict,
    window: WindowTracker,
    entity: str,
    now: float,
) -> FlowRecord:
    """Convert one sensor record to the shared FlowRecord contract."""
    flow = flow_features(rec, now)
    opened = open_flow_features(rec, http, now)
    window_data = window.window_features(entity, now)

    return FlowRecord(
        flow_id=str(rec["flow_id"]),
        entity_key=entity,
        ts_start=float(rec["t_first"]),
        ts_end=float(now),
        src_ip=str(rec["client_ip"]),
        src_port=int(rec["client_port"]),
        dst_ip=str(rec["server_ip"]),
        dst_port=int(rec["server_port"]),
        proto="tcp",
        method=str(http.get("method") or ""),
        path=str(http.get("path") or ""),
        status_code=None,
        bytes_in=float(flow["bytes_in"]),
        bytes_out=float(flow["bytes_out"]),
        req_count=int(rec["n_requests_seen"]),
        conn_id=str(rec["flow_id"]),
        bytes_in_per_s=float(flow["bytes_in_per_s"]),
        bytes_out_per_s=float(flow["bytes_out_per_s"]),
        requests_per_s=float(flow["requests_per_s"]),
        packets_per_s=float(flow["packets_per_s"]),
        interarrival_mean=float(flow["interarrival_mean"]),
        interarrival_std=float(flow["interarrival_std"]),
        interarrival_max=float(flow["interarrival_max"]),
        concurrent_conns=float(window_data["concurrent_conns"]),
        conns_per_second_opened=float(
            window_data["conns_per_second_opened"]
        ),
        requests_per_conn_so_far=float(
            opened["requests_per_conn_so_far"]
        ),
        conn_age_s=float(opened["conn_age_s"]),
        stall_time_s=float(opened["stall_time_s"]),
        body_frac_sent=float(opened["body_frac_sent"]),
        bytes_declared=float(opened["bytes_declared"]),
        body_drip_rate_bps=float(opened["body_drip_rate_bps"]),
        time_to_first_byte=float(opened["time_to_first_byte"]),
        header_complete=int(opened["header_complete"]),
        syn_retries=float(flow["syn_retries"]),
        bytes_in_ratio=float(flow["bytes_in_ratio"]),
        is_open=int(opened["is_open"]),
    )


def detect_flow_triggers(
    rec: dict,
    http: dict,
    window: WindowTracker,
    entity: str,
    now: float,
    cusum_detectors: dict[str, CUSUM] | None = None,
) -> tuple[FlowRecord, list[TriggerEvent]]:
    """Run fixed rules and stall checks, with optional calibrated CUSUM.

    Supply a persistent mapping of entity keys to already-calibrated CUSUM
    instances to enable CUSUM. With no mapping, existing behavior is retained.

    CUSUM monitors conns_per_second_opened. Its baseline must be calibrated
    on benign observations and frozen before evaluation.
    """
    flow_record = flow_record_from_sensor(
        rec=rec,
        http=http,
        window=window,
        entity=entity,
        now=now,
    )

    events = detect_rules(flow_record)

    stall_event = detect_stall(flow_record)
    if stall_event is not None:
        events.append(stall_event)

    if cusum_detectors is not None:
        detector = cusum_detectors.get(entity)
        if detector is not None:
            signal = flow_record.conns_per_second_opened
            if detector.update(signal):
                events.append(
                    TriggerEvent(
                        ts=flow_record.ts_end,
                        entity_key=flow_record.entity_key,
                        trigger="cusum",
                        severity=0.7,
                        detail={
                            "rule": "connection_open_rate_shift",
                            "signal": signal,
                            "baseline_mu": detector.mu,
                            "baseline_sigma": detector.sigma,
                        },
                    )
                )

    return flow_record, events