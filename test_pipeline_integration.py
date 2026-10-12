import unittest

from m1_capture.features import WindowTracker
from m1_capture.sensor import read_pcap, parse_http
from m2_triggers.pipeline import detect_flow_triggers
from m2_triggers.rules import detect_rules
from test_sensor import benign, slowloris, flood


def detect_from_pcap(path, entity="test-entity"):
    records = read_pcap(path, flush_after=5.0)
    records = sorted(
        records,
        key=lambda rec: (rec["t_first"], rec["flow_id"]),
    )

    window = WindowTracker(window_s=10.0)
    prepared = []

    for rec in records:
        http = parse_http(bytes.fromhex(rec["fwd_payload"]))
        prepared.append((rec, http))

    # Offline replay: preserve each flow's own observed interval.
    # Avoid pairing closures by connection insertion order.
    window.intervals[entity] = [
        [
            float(rec["t_first"]),
            (
                float(rec["t_close"])
                if rec.get("t_close") is not None
                else None
            ),
        ]
        for rec, _http in prepared
    ]

    events = []
    flows = []

    for rec, http in prepared:
        now = float(rec["t_last"])

        flow, flow_events = detect_flow_triggers(
            rec=rec,
            http=http,
            window=window,
            entity=entity,
            now=now,
        )

        flows.append(flow)
        events.extend(flow_events)

    return flows, events


class PipelineIntegrationTests(unittest.TestCase):
    def test_slowloris_produces_stall_event(self):
        flows, events = detect_from_pcap(slowloris())
        self.assertTrue(flows)
        self.assertTrue(any(e.trigger == "stall" for e in events))

    def test_benign_does_not_produce_stall_event(self):
        _, events = detect_from_pcap(benign())
        self.assertFalse(any(e.trigger == "stall" for e in events))

    def test_flood_has_higher_rate_than_benign(self):
        benign_flows, _ = detect_from_pcap(benign())
        flood_flows, _ = detect_from_pcap(flood())

        self.assertTrue(benign_flows)
        self.assertTrue(flood_flows)

        benign_peak = max(f.requests_per_s for f in benign_flows)
        flood_peak = max(f.requests_per_s for f in flood_flows)

        self.assertGreater(flood_peak, benign_peak)

    def test_rate_rule_fires_above_threshold(self):
        flows, _ = detect_from_pcap(flood())
        self.assertTrue(flows)

        flow = max(flows, key=lambda f: f.requests_per_s)
        events = detect_rules(flow, rate_threshold=10.0)

        self.assertTrue(
            any(e.trigger == "rate" for e in events),
            f"Expected rate event at {flow.requests_per_s:.2f} requests/s",
        )


if __name__ == "__main__":
    unittest.main()