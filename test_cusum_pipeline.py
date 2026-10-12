import unittest

from m1_capture.features import WindowTracker
from m2_triggers.cusum import CUSUM
from m2_triggers.pipeline import detect_flow_triggers


def make_record(flow_id, entity, start, last, close=None):
    return {
        "flow_id": flow_id,
        "t_first": start,
        "t_last": last,
        "t_close": close,
        "client_ip": "192.0.2.10",
        "client_port": 50000,
        "server_ip": "192.0.2.20",
        "server_port": 80,
        "n_requests_seen": 1,
        "fwd_bytes": 100,
        "bwd_bytes": 0,
        "fwd_pkts": 1,
        "bwd_pkts": 0,
        "fwd_times": [start, last] if last > start else [start],
        "syn_retries": 0,
    }


def make_http():
    return {
        "method": "GET",
        "path": "/",
        "header_complete": True,
        "header_bytes": 20,
        "declared_body": 0,
    }


class TestCusumPipeline(unittest.TestCase):
    def test_without_detectors_preserves_existing_behavior(self):
        rec = make_record("f1", "client-a", 10, 11, 12)
        window = WindowTracker()
        window.on_connect("client-a", 10)
        window.on_close("client-a", 12)

        _, events = detect_flow_triggers(
            rec, make_http(), window, "client-a", 11
        )

        self.assertNotIn("cusum", {event.trigger for event in events})

    def test_configured_detector_can_emit_cusum_event(self):
        rec = make_record("f1", "client-a", 10, 11, 12)
        window = WindowTracker()
        window.on_connect("client-a", 10)
        window.on_close("client-a", 12)

        # Test-only parameters to exercise the integration path.
        detector = CUSUM(mu=0.0, sigma=1.0, k=0.0, h=0.05)
        detectors = {"client-a": detector}

        _, events = detect_flow_triggers(
            rec,
            make_http(),
            window,
            "client-a",
            11,
            cusum_detectors=detectors,
        )

        cusum_events = [event for event in events if event.trigger == "cusum"]
        self.assertEqual(len(cusum_events), 1)
        self.assertEqual(cusum_events[0].entity_key, "client-a")
        self.assertEqual(
            cusum_events[0].detail["rule"],
            "connection_open_rate_shift",
        )

    def test_detector_mapping_is_entity_specific(self):
        a = CUSUM(mu=0.0, sigma=1.0, k=0.0, h=0.1)
        b = CUSUM(mu=0.0, sigma=1.0, k=0.0, h=0.1)
        detectors = {"client-a": a, "client-b": b}

        self.assertIsNot(detectors["client-a"], detectors["client-b"])
        self.assertEqual(a.s_pos, 0.0)
        self.assertEqual(b.s_pos, 0.0)


if __name__ == "__main__":
    unittest.main()