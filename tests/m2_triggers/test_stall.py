from dataclasses import replace
from schemas import FlowRecord
from m2_triggers.stall import detect

# Normal flow: should not trigger
normal = FlowRecord(
    flow_id="normal-1",
    entity_key="client-1",
    ts_start=100.0,
    ts_end=101.0,
    src_ip="192.168.1.10",
    src_port=50001,
    dst_ip="192.168.1.20",
    dst_port=80,
)

assert detect(normal) is None, "Normal flow unexpectedly triggered"

# Old connection with an incomplete header: should trigger
slow_header = replace(
    normal,
    flow_id="slow-1",
    conn_age_s=15.0,
    header_complete=0.0,
)

event = detect(slow_header)

assert event is not None, "Slow header was not detected"
assert event.trigger == "stall"
assert "header_incomplete" in event.detail["reasons"]
assert event.severity >= 0.85

# Old connection with no requests: should trigger
idle = replace(
    normal,
    flow_id="idle-1",
    conn_age_s=25.0,
    requests_per_conn_so_far=0.0,
)

event = detect(idle)

assert event is not None, "Idle connection was not detected"
assert "zero_req_per_conn" in event.detail["reasons"]
# RUDY: large declared body with very slow progress
rudy = replace(
    normal,
    flow_id="rudy-1",
    conn_age_s=19.0,
    header_complete=1.0,
    bytes_declared=5_000_000.0,
    body_frac_sent=0.00004,
    body_drip_rate_bps=10.52,
    stall_time_s=19.0,
    requests_per_conn_so_far=1.0,
    is_open=1.0,
)

event = detect(rudy)

assert event is not None, "RUDY was not detected"
assert event.trigger == "stall"
assert (
    "slow_drip" in event.detail["reasons"]
    or "body_incomplete" in event.detail["reasons"]
), f"RUDY did not match an expected body-stall rule: {event.detail}"

print("PASS: RUDY slow body transfer is detected")
print("PASS: normal flow does not trigger")
print("PASS: incomplete header is detected")
print("PASS: idle connection is detected")
print("All stall detector checks passed")
