#!/usr/bin/env python3
"""test_m5_evade.py — Tests for black-box adversarial evasion and damage enforcement.

Verifies:
1. evade() reduces the suspicion score.
2. The "still causes damage" check is actually enforced.
3. Offline fallback operates cleanly without crashing.
"""
from __future__ import annotations

import asyncio
import unittest

from m5_sandbox.adversarial.evade import (
    _simulated_score,
    evade,
    evade_sync,
    measure_damage,
    send_slow,
)


class TestM5Evade(unittest.TestCase):
    def test_evade_reduces_score(self):
        """evade() must reduce the suspicion score below the baseline."""
        res = evade_sync(rounds=25, seed=42)

        self.assertIn("baseline_score", res)
        self.assertIn("evaded_score", res)
        self.assertIn("score_reduction", res)

        # Baseline score should be high for slow trickle attack (0.90)
        self.assertEqual(res["baseline_score"], 0.90)

        # Evaded score must be lower than baseline
        self.assertLess(res["evaded_score"], res["baseline_score"])
        self.assertGreater(res["score_reduction"], 0.0)

        # In unconstrained mode, score reduces below 0.30
        self.assertTrue(res["evaded"])

    def test_damage_check_enforced(self):
        """The 'still causes damage' check is physically enforced."""
        # Case A: Unconstrained evasion speeds up trickle so much that damage is lost
        res_unconstrained = evade_sync(rounds=30, enforce_damage=False, seed=42)
        self.assertFalse(
            res_unconstrained["still_causes_damage"],
            "Unconstrained evasion must lose damage when trickle is accelerated too much",
        )

        # Case B: Damage-enforced evasion guarantees still_causes_damage is True
        res_enforced = evade_sync(rounds=30, enforce_damage=True, seed=42)
        self.assertTrue(
            res_enforced["still_causes_damage"],
            "When enforce_damage=True, still_causes_damage must remain True",
        )
        # Score is reduced from baseline but cannot cross below 0.30 without losing damage
        self.assertLess(res_enforced["evaded_score"], res_enforced["baseline_score"])
        self.assertFalse(
            res_enforced["evaded"],
            "Attack cannot drop below 0.30 while physically maintaining connection exhaustion damage",
        )

    def test_measure_damage_logic(self):
        """measure_damage() correctly distinguishes damaging vs non-damaging parameters."""
        # Damaging attack: high interval and sufficient connections
        damaging_params = {"byte_interval": 0.10, "conns": 50}
        self.assertTrue(asyncio.run(measure_damage(damaging_params)))

        # Non-damaging: trickle too fast (<2.0s effective stall)
        fast_params = {"byte_interval": 0.01, "conns": 50}
        self.assertFalse(asyncio.run(measure_damage(fast_params)))

        # Non-damaging: connection count too low (<15 conns)
        low_conn_params = {"byte_interval": 0.10, "conns": 5}
        self.assertFalse(asyncio.run(measure_damage(low_conn_params)))

        # Custom damage function override
        custom_fn = lambda p: p.get("special_flag", False)
        self.assertTrue(asyncio.run(measure_damage({"special_flag": True}, damage_fn=custom_fn)))
        self.assertFalse(asyncio.run(measure_damage({"special_flag": False}, damage_fn=custom_fn)))

    def test_offline_fallback_simulation(self):
        """send_slow() offline fallback computes expected scores without requiring live proxy."""
        base_params = {"byte_interval": 0.10, "conns": 50, "entity": "adv-1"}
        score = asyncio.run(send_slow(base_params, proxy_url="http://invalid-proxy:9999"))
        self.assertAlmostEqual(score, 0.90, places=2)

        # Custom score function hook
        score_hook = lambda p: 0.42
        score_custom = asyncio.run(send_slow(base_params, score_fn=score_hook))
        self.assertEqual(score_custom, 0.42)


if __name__ == "__main__":
    unittest.main()
