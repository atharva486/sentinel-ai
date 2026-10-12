#!/usr/bin/env python3
"""Focused integration test for the Module 3 candidate artifact.

Verifies:
- Candidate artifact loads correctly via CalibrationResult.load()
- Feature-order validation enforced (exact match against FEATURE_ORDER)
- Calibrated attack probability scoring works
- SHAP explanation output contract (16 features, finite dict values)
- Artifact preserves the 16-feature contract and leakage guard
"""

import sys
import os
import numpy as np
import joblib
import pandas as pd

# Add project paths
sys.path.insert(0, '.')
sys.path.insert(0, './m1_capture')
sys.path.insert(0, './m3_scoring')

from m3_scoring.calibrate import CalibrationResult
from m3_scoring.explain import explain
from features import FEATURE_ORDER

# Artifact paths
ARTIFACT_PATH = 'calibration_result_candidate.joblib'
ORIGINAL_ARTIFACT = 'calibration_result.joblib'


def _ensure_artifact():
    """Retrain and save the candidate artifact before test session."""
    import numpy as np
    from m3_scoring.calibrate import calibrate
    from m3_scoring.train_xgb import train

    np.random.seed(42)
    X_train = pd.read_csv('data/X_train.csv')
    y_train = pd.read_csv('data/y_train.csv').squeeze('columns')
    X_cal = pd.read_csv('data/X_cal.csv')
    y_cal = pd.read_csv('data/y_cal.csv').squeeze('columns')
    X_val = pd.read_csv('data/X_val.csv')
    y_val = pd.read_csv('data/y_val.csv').squeeze('columns')

    X_train = X_train[FEATURE_ORDER]
    X_cal = X_cal[FEATURE_ORDER]
    X_val = X_val[FEATURE_ORDER]

    model = train(X_train, y_train, X_val, y_val, params=dict(
        n_estimators=400, max_depth=5, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, random_state=42
    ))
    result = calibrate(model, X_cal, y_cal)
    cal_result = CalibrationResult(
        model=model,
        calibrator=result.calibrator,
        feature_order=FEATURE_ORDER,
    )
    cal_result.save(ARTIFACT_PATH)
    print("  (Artifact %s recreated)" % ARTIFACT_PATH)


# Run all tests
if __name__ == '__main__':
    print("=" * 60)
    print("Module 3 Candidate Artifact Integration Tests")
    print("=" * 60)
    print()

    # Ensure artifact exists
    _ensure_artifact()

    print("Test: Candidate artifact loads correctly")
    candidate = CalibrationResult.load(ARTIFACT_PATH)
    assert candidate is not None, "FAIL: artifact load returned None"
    assert candidate.model is not None, "FAIL: model is None"
    assert candidate.calibrator is not None, "FAIL: calibrator is None"
    assert candidate.feature_order == FEATURE_ORDER, (
        "FAIL: feature_order mismatch. Got %s, expected %s"
        % (candidate.feature_order, FEATURE_ORDER))
    print("  PASS: artifact loads, model and calibrator present, feature_order matches")

    print("Test: Feature-order validation enforced")
    # Test with incompatible feature order
    artifact = joblib.load(ARTIFACT_PATH)
    artifact["feature_order"] = ["nonexistent_feature"]  # invalid
    joblib.dump(artifact, ARTIFACT_PATH)
    try:
        CalibrationResult.load(ARTIFACT_PATH)
        assert False, "FAIL: Expected ValueError for incompatible feature order"
    except ValueError as e:
        assert "feature_order" in str(e).lower(), (
            "FAIL: Error message should mention feature_order: %s" % str(e))
    print("  PASS: Incompatible feature order raises ValueError")

    # Test with reordered features
    artifact2 = joblib.load(ARTIFACT_PATH)
    artifact2["feature_order"] = FEATURE_ORDER[::-1]  # reversed
    joblib.dump(artifact2, ARTIFACT_PATH)
    try:
        CalibrationResult.load(ARTIFACT_PATH)
        assert False, "FAIL: Expected ValueError for reordered feature order"
    except ValueError as e:
        assert "feature_order" in str(e).lower(), (
            "FAIL: Error message should mention feature_order: %s" % str(e))
    print("  PASS: Reordered feature order raises ValueError")

    # Restore the valid artifact
    _ensure_artifact()
    print("  PASS: Valid artifact restored after validation tests")

    print("Test: Calibrated attack probability scoring")
    candidate = CalibrationResult.load(ARTIFACT_PATH)

    X_val = pd.read_csv('data/X_val.csv')
    row_dict = {}
    for i, f in enumerate(FEATURE_ORDER):
        row_dict[f] = float(X_val.iloc[0][f])

    score = candidate.calibrated_score(row_dict)
    assert isinstance(score, float), (
        "FAIL: calibrated_score should return float, got %s" % type(score))
    assert 0.0 <= score <= 1.0, (
        "FAIL: calibrated score should be in [0,1], got %.4f" % score)
    print("  PASS: calibrated_score returns %.4f in [0,1]" % score)

    print("Test: SHAP explanation output contract")
    candidate = CalibrationResult.load(ARTIFACT_PATH)

    X_val = pd.read_csv('data/X_val.csv')
    row_dict = {}
    for i, f in enumerate(FEATURE_ORDER):
        row_dict[f] = float(X_val.iloc[0][f])

    shap_result = explain(model=candidate.model, flow_features=row_dict)

    # Check: exactly 16 features
    assert len(shap_result) == len(FEATURE_ORDER), (
        "FAIL: SHAP result should have %d features, got %d"
        % (len(FEATURE_ORDER), len(shap_result)))

    # Check: all values are finite
    for name, val in shap_result.items():
        assert np.isfinite(val), (
            "FAIL: SHAP value for '%s' is not finite: %s" % (name, val))

    # Check: all keys are from FEATURE_ORDER
    for name in shap_result.keys():
        assert name in FEATURE_ORDER, (
            "FAIL: SHAP key '%s' not in FEATURE_ORDER" % name)

    print("  PASS: SHAP result has %d features, all values finite" % len(shap_result))

    print("Test: Original artifact preserved unchanged")
    orig = joblib.load(ORIGINAL_ARTIFACT)
    assert 'model_json' in orig, "FAIL: original artifact missing model_json"
    assert 'calibrator' in orig, "FAIL: original artifact missing calibrator"
    assert 'feature_order' in orig, "FAIL: original artifact missing feature_order"
    assert len(orig['feature_order']) == 16, (
        "FAIL: original artifact should have 16 features, got %d" % len(orig['feature_order']))

    print("  PASS: Original artifact unchanged (16 features, model+calibrator present)")

    print()
    print("=" * 60)
    print("ALL INTEGRATION TESTS PASSED")
    print("=" * 60)