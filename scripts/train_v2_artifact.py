#!/usr/bin/env python3
"""
Train the live model exactly as scripts/binary_study_verify.py:

  * data/binary_study_client_flows.parquet, client-facing flows only
    (role in {attack, benign})
  * train = runH
  * the same 13 per-connection features and the same XGBoost params
  * identity calibrator: IsotonicRegression fitted on [0,1] -> [0,1]

Saves models/sentinel_v2_13feat.joblib with its own feature_order (the 13
BASE features), loadable by CalibrationResult and dashboard/live_lab.py
(--model).
"""
import os
import sys

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("./m1_capture"))

import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.isotonic import IsotonicRegression

from m3_scoring.calibrate import CalibrationResult

BASE = ["bytes_in", "bytes_in_per_s", "requests_per_s", "packets_per_s",
        "interarrival_mean", "interarrival_std", "interarrival_max",
        "requests_per_conn_so_far", "stall_time_s", "body_frac_sent",
        "bytes_declared", "body_drip_rate_bps", "header_complete"]

PARAMS = dict(n_estimators=200, max_depth=4, learning_rate=0.1, subsample=0.8,
              colsample_bytree=0.8, random_state=0, eval_metric="aucpr")

OUT = "models/sentinel_v2_13feat.joblib"


def main() -> None:
    df = pd.read_parquet("data/binary_study_client_flows.parquet")
    df = df[df.role.isin(["attack", "benign"])].copy()
    train = df[df.session == "runH"]
    X = train[BASE]
    y = (train.role == "attack").astype(int)

    model = xgb.XGBClassifier(**PARAMS).fit(X, y)

    # Identity calibrator: IsotonicRegression fit on [0,1] -> [0,1].
    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(np.array([0.0, 1.0]), np.array([0.0, 1.0]))

    result = CalibrationResult(model, calibrator, feature_order=list(BASE))
    result.save(OUT)

    # Sanity: identity calibrator => calibrated score == predict_proba.
    raw = model.predict_proba(X)[:, 1]
    cal = np.array(
        [result.calibrated_score(dict(zip(BASE, row))) for row in X.values]
    )
    print(f"train rows (runH): {len(train)}  features: {len(BASE)}")
    print(f"max |calibrated - predict_proba| on train: "
          f"{float(np.max(np.abs(cal - raw))):.2e}")
    print(f"saved {OUT} with feature_order={BASE}")


if __name__ == "__main__":
    main()
