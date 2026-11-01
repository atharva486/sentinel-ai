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

print("PASS: normal flow does not trigger")
print("PASS: incomplete header is detected")
print("PASS: idle connection is detected")
print("All stall detector checks passed")
