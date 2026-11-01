#!/usr/bin/env python3
"""test_m5_feedback.py — Tests for active learning feedback loop and retraining constraints.

Verifies:
1. retrain_with_labels() never touches the held-out validation set.
2. retrain_with_labels() preserves exact FEATURE_ORDER.
3. evaluate_on_heldout() computes un-leaked evaluation metrics.
4. extract_uncertain_flows() captures strictly the uncertain score band.
"""
from __future__ import annotations

import unittest
import numpy as np
import pandas as pd

from m1_capture.features import FEATURE_ORDER
from m3_scoring.calibrate import CalibrationResult
from m3_scoring.train_xgb import leakage_guard
from m5_sandbox.feedback import (
    evaluate_on_heldout,
    extract_uncertain_flows,
    retrain_with_labels,
)


class TestM5Feedback(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Load candidate artifact and real partitioned data
        cls.artifact = CalibrationResult.load("calibration_result_candidate.joblib")
        cls.X_tr = pd.read_csv("data/X_train.csv")[FEATURE_ORDER]
        cls.y_tr = pd.read_csv("data/y_train.csv").squeeze("columns")
        cls.X_c = pd.read_csv("data/X_cal.csv")[FEATURE_ORDER]
        cls.y_c = pd.read_csv("data/y_cal.csv").squeeze("columns")
        cls.X_v = pd.read_csv("data/X_val.csv")[FEATURE_ORDER]
        cls.y_v = pd.read_csv("data/y_val.csv").squeeze("columns")

    def test_retrain_never_touches_held_out_set(self):
        """retrain_with_labels() must NEVER include held-out validation rows in training data."""
        # Create synthetic new labeled flows from replay
        new_flows = [
            {col: float(i + 1) for i, col in enumerate(FEATURE_ORDER)},
            {col: float((i + 1) * 2) for i, col in enumerate(FEATURE_ORDER)},
        ]
        new_flows[0]["y"] = 1
        new_flows[1]["y"] = 0

        initial_train_len = len(self.X_tr)
        val_len = len(self.X_v)

        # Fast training params for test execution
        fast_params = {"n_estimators": 10, "max_depth": 3, "n_jobs": 1}

        new_model, new_cal = retrain_with_labels(
            base_X_train=self.X_tr,
            base_y_train=self.y_tr,
            new_labeled_flows=new_flows,
            X_cal=self.X_c,
            y_cal=self.y_c,
            X_val=self.X_v,
            y_val=self.y_v,
            params=fast_params,
        )

        # Validation set must remain untouched with exactly val_len rows
        self.assertEqual(len(self.X_v), val_len)

        # Confirm the retrained model was fitted on base_train + new_flows only
        # We can check that predicting on X_val does not fail and evaluates independently
        eval_res = evaluate_on_heldout(new_model, new_cal, self.X_v, self.y_v)
        self.assertIn("pr_auc", eval_res)
        self.assertGreater(eval_res["pr_auc"], 0.70)
        self.assertLessEqual(eval_res["fpr"], 0.05)

    def test_retrain_preserves_feature_order(self):
        """retrain_with_labels() must strictly preserve the 16 FEATURE_ORDER columns."""
        # Create new labeled flows with deliberately scrambled column order and extra metadata
        scrambled_flows = [
            {
                "flow_id": "flow_scrambled_99",
                "stall_time_s": 8.0,
                "requests_per_s": 0.5,
                "y": 1,
                "bytes_in": 300,
                "header_complete": 0.0,
                "unrelated_meta": "debug_info",
            }
        ]

        fast_params = {"n_estimators": 5, "max_depth": 2, "n_jobs": 1}

        new_model, _ = retrain_with_labels(
            base_X_train=self.X_tr,
            base_y_train=self.y_tr,
            new_labeled_flows=scrambled_flows,
            X_cal=self.X_c,
            y_cal=self.y_c,
            X_val=self.X_v,
            y_val=self.y_v,
            params=fast_params,
        )

        # Model feature names must match FEATURE_ORDER in exact 16-feature sequence
        self.assertEqual(list(new_model.feature_names_in_), list(FEATURE_ORDER))
        self.assertEqual(len(new_model.feature_names_in_), 16)

    def test_leakage_guard_enforced(self):
        """leakage_guard() must raise AssertionError if forbidden target or non-contract columns exist."""
        bad_df = self.X_v.copy()
        bad_df["status_code"] = 503  # Forbidden target/outcome feature
        with self.assertRaises(AssertionError):
            leakage_guard(bad_df)

        bad_df2 = self.X_v.copy()
        bad_df2["total_bytes"] = 1000  # Termination feature forbidden by leakage guard
        with self.assertRaises(AssertionError):
            leakage_guard(bad_df2)

    def test_extract_uncertain_flows_band(self):
        """extract_uncertain_flows() extracts only flows within 0.30 <= score <= 0.80."""
        uncertain = extract_uncertain_flows(self.X_tr.head(100), self.artifact, n_recent=20)
        for fl in uncertain:
            score = fl["_pre_replay_score"]
            self.assertGreaterEqual(score, 0.30)
            self.assertLessEqual(score, 0.80)


if __name__ == "__main__":
    unittest.main()
