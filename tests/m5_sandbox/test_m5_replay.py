#!/usr/bin/env python3
"""test_m5_replay.py — Tests for quarantine replay engine and label generation.

Verifies:
1. is_uncertain() correctly covers the 0.30–0.80 band.
2. label_from_replay() assigns y=1 on damage and y=0 otherwise.
3. Flow conversion and original speed replay handling.
"""
from __future__ import annotations

import unittest
from m5_sandbox.replay import (
    UNCERTAIN_HI,
    UNCERTAIN_LO,
    _flow_to_dict,
    is_uncertain,
    replay_sync,
)
from m5_sandbox.feedback import label_from_replay
from schemas import FlowRecord


class TestM5Replay(unittest.TestCase):
    def test_uncertain_band_boundaries(self):
        """is_uncertain() must strictly cover the 0.30–0.80 band."""
        self.assertEqual(UNCERTAIN_LO, 0.30)
        self.assertEqual(UNCERTAIN_HI, 0.80)

        # Values below 0.30: clearly benign -> False
        self.assertFalse(is_uncertain(0.0))
        self.assertFalse(is_uncertain(0.10))
        self.assertFalse(is_uncertain(0.29))
        self.assertFalse(is_uncertain(0.2999))

        # Boundary 0.30: uncertain -> True
        self.assertTrue(is_uncertain(0.30))
        self.assertTrue(is_uncertain(0.3001))

        # Interior uncertain points -> True
        self.assertTrue(is_uncertain(0.45))
        self.assertTrue(is_uncertain(0.50))
        self.assertTrue(is_uncertain(0.75))

        # Boundary 0.80: uncertain -> True
        self.assertTrue(is_uncertain(0.80))

        # Values above 0.80: clearly malicious -> False
        self.assertFalse(is_uncertain(0.8001))
        self.assertFalse(is_uncertain(0.85))
        self.assertFalse(is_uncertain(0.95))
        self.assertFalse(is_uncertain(1.0))

    def test_label_from_replay_assigns_damage_labels(self):
        """label_from_replay() assigns y=1 on damage and y=0 otherwise."""
        test_flows = [
            {"flow_id": "f_damage_1", "bytes_in": 500, "stall_time_s": 10.0},
            {"flow_id": "f_benign_1", "bytes_in": 1200, "stall_time_s": 0.0},
            {"flow_id": "f_damage_2", "bytes_in": 600, "stall_time_s": 8.0},
            {"flow_id": "f_benign_2", "bytes_in": 8000, "stall_time_s": 0.1},
        ]

        def mock_replay_fn(fl):
            # Simulate replay result: damage if flow_id starts with f_damage
            is_damaging = "damage" in fl.get("flow_id", "")
            return {
                "flow_id": fl.get("flow_id"),
                "caused_damage": is_damaging,
                "replay_duration_s": 6.5 if is_damaging else 0.05,
                "status_code": 504 if is_damaging else 200,
                "error": None,
            }

        labeled = label_from_replay(test_flows, replay_fn=mock_replay_fn)

        self.assertEqual(len(labeled), 4)

        # Flow 0: damage -> y=1
        self.assertEqual(labeled[0]["y"], 1)
        self.assertTrue(labeled[0]["_replay_damage"])
        self.assertEqual(labeled[0]["flow_id"], "f_damage_1")

        # Flow 1: no damage -> y=0
        self.assertEqual(labeled[1]["y"], 0)
        self.assertFalse(labeled[1]["_replay_damage"])
        self.assertEqual(labeled[1]["flow_id"], "f_benign_1")

        # Flow 2: damage -> y=1
        self.assertEqual(labeled[2]["y"], 1)
        self.assertTrue(labeled[2]["_replay_damage"])

        # Flow 3: no damage -> y=0
        self.assertEqual(labeled[3]["y"], 0)
        self.assertFalse(labeled[3]["_replay_damage"])

    def test_flow_to_dict_conversion(self):
        """FlowRecord and raw dicts must convert into valid replayable dictionaries."""
        rec = FlowRecord(
            flow_id="rec_123",
            entity_key="e1",
            ts_start=100.0,
            ts_end=110.0,
            src_ip="172.18.0.6",
            src_port=44120,
            dst_ip="172.18.0.2",
            dst_port=80,
            method="GET",
            path="/test",
            bytes_in=100,
            bytes_out=0,
        )
        d = _flow_to_dict(rec)
        self.assertEqual(d["flow_id"], "rec_123")
        self.assertEqual(d["client_ip"], "172.18.0.6")
        self.assertEqual(d["method"], "GET")
        self.assertEqual(d["path"], "/test")

    def test_replay_damage_condition(self):
        """Replay marks damage when server stalls or times out."""
        # A slow flow with stall_time_s > 5 and header_complete == 0.0
        slow_flow = {
            "flow_id": "slow_stall_flow",
            "method": "GET",
            "path": "/",
            "stall_time_s": 6.0,
            "header_complete": 0.0,
            "conn_age_s": 2.0,
        }
        res = replay_sync(slow_flow, sandbox_url="http://invalid-sandbox-address:9999")
        # In offline/standalone fallback mode, stall flow triggers damage
        self.assertTrue(res["caused_damage"])

        # A benign fast flow
        benign_flow = {
            "flow_id": "benign_fast_flow",
            "method": "GET",
            "path": "/",
            "stall_time_s": 0.0,
            "header_complete": 1.0,
            "conn_age_s": 0.05,
        }
        res_benign = replay_sync(benign_flow, sandbox_url="http://invalid-sandbox-address:9999")
        self.assertFalse(res_benign["caused_damage"])


if __name__ == "__main__":
    unittest.main()
