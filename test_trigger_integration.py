import unittest

from schemas import FlowRecord, TriggerEvent
from m2_triggers.stall import detect as detect_stall
from m2_triggers.rules import detect_rules


def make_flow(**overrides):
    values = {
        "flow_id": "flow-test-1",
        "entity_key": "entity-test-1",
        "ts_start": 100.0,
        "ts_end": 115.0,
        "src_ip": "192.0.2.10",
        "src_port": 50000,
        "dst_ip": "192.0.2.20",
        "dst_port": 80,
    }
    values.update(overrides)
    return FlowRecord(**values)


class TestTriggerIntegration(unittest.TestCase):
    def test_normal_flow_produces_no_events(self):
        flow = make_flow()

        self.assertIsNone(detect_stall(flow))
        self.assertEqual(detect_rules(flow), [])

    def test_slow_flow_produces_stall_event(self):
        flow = make_flow(
            conn_age_s=15.0,
            header_complete=0.0,
            is_open=1.0,
        )

        event = detect_stall(flow)

        self.assertIsInstance(event, TriggerEvent)
        self.assertEqual(event.trigger, "stall")
        self.assertEqual(event.entity_key, flow.entity_key)
        self.assertIn("header_incomplete", event.detail["reasons"])

    def test_high_rate_and_connections_produce_rule_events(self):
        flow = make_flow(
            requests_per_s=150.0,
            concurrent_conns=75.0,
        )

        events = detect_rules(flow)

        self.assertEqual(
            {event.trigger for event in events},
            {"rate", "connections"},
        )
        for event in events:
            self.assertIsInstance(event, TriggerEvent)
            self.assertEqual(event.entity_key, flow.entity_key)

    def test_normal_flow_and_stall_flow_share_event_contract(self):
        flow = make_flow(
            conn_age_s=25.0,
            requests_per_conn_so_far=0.0,
            header_complete=0.0,
        )

        event = detect_stall(flow)

        self.assertIsNotNone(event)
        self.assertEqual(event.ts, flow.ts_end)
        self.assertGreaterEqual(event.severity, 0.0)
        self.assertLessEqual(event.severity, 1.0)

    def test_progressing_upload_does_not_trigger_body_incomplete(self):
        flow = make_flow(
            conn_age_s=20.0,
            header_complete=1.0,
            bytes_declared=1_000_000.0,
            body_frac_sent=0.30,
            body_drip_rate_bps=12_000.0,
            stall_time_s=20.0,
            is_open=1.0,
        )

        event = detect_stall(flow)

        self.assertTrue(
            event is None or "body_incomplete" not in event.detail["reasons"],
            f"Progressing upload incorrectly flagged: {event.detail if event else None}",
        )
if __name__ == "__main__":
    unittest.main()
