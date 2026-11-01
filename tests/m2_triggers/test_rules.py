import unittest

from m2_triggers.rules import detect_rules
from schemas import FlowRecord


def make_flow(requests_per_s=10.0, concurrent_conns=5.0):
    return FlowRecord(
        flow_id="test-flow",
        entity_key="test-entity",
        ts_start=100.0,
        ts_end=101.0,
        src_ip="192.0.2.10",
        src_port=12345,
        dst_ip="192.0.2.20",
        dst_port=80,
        requests_per_s=requests_per_s,
        concurrent_conns=concurrent_conns,
    )


class TestFixedRules(unittest.TestCase):
    def test_normal_flow_does_not_trigger(self):
        self.assertEqual(detect_rules(make_flow()), [])

    def test_high_request_rate_triggers_rate_rule(self):
        events = detect_rules(make_flow(requests_per_s=120.0))
        self.assertEqual([event.trigger for event in events], ["rate"])
        self.assertEqual(events[0].detail["rule"], "high_request_rate")

    def test_high_connections_trigger_connection_rule(self):
        events = detect_rules(make_flow(concurrent_conns=60.0))
        self.assertEqual([event.trigger for event in events], ["connections"])
        self.assertEqual(events[0].detail["rule"], "too_many_connections")

    def test_both_rules_can_trigger(self):
        events = detect_rules(
            make_flow(requests_per_s=120.0, concurrent_conns=60.0)
        )
        self.assertEqual(
            {event.trigger for event in events},
            {"rate", "connections"},
        )

    def test_invalid_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_rules(make_flow(), rate_threshold=0)


if __name__ == "__main__":
    unittest.main()
