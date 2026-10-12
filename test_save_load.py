#!/usr/bin/env python3
"""Test save/load for CalibrationResult."""
import sys
import os

# Add project paths
sys.path.insert(0, '.')
sys.path.insert(0, './m1_capture')
sys.path.insert(0, './m3_scoring')

from calibrate import calibrate, CalibrationResult
import numpy as np
import xgboost as xgb
import joblib

np.random.seed(42)
n = 200
X = np.random.rand(n, 16)
y = np.random.randint(0, 2, n)
model = xgb.XGBClassifier(n_estimators=10, random_state=42)
model.fit(X[:150], y[:150])

result = calibrate(model, X[150:], y[150:])

# Test 1: save and load
print("Test 1: save and load")
tmp_path = '/tmp/test_calibrate_result.joblib'
result.save(tmp_path)
loaded = CalibrationResult.load(tmp_path)

flow = {k: float(np.random.rand()) for k in loaded.feature_order}
orig_score = result.calibrated_score(flow)
loaded_score = loaded.calibrated_score(flow)
print(f'Original score: {orig_score:.4f}')
print(f'Loaded score: {loaded_score:.4f}')
print(f'Diff: {abs(orig_score - loaded_score):.6f}')
print(f'Scores match: {abs(orig_score - loaded_score) < 1e-6}')
assert abs(orig_score - loaded_score) < 1e-6, "Scores differ after save/load"

# Clean up
os.unlink(tmp_path)
print("  PASSED")

# Test 2: missing file
print("Test 2: missing file")
try:
    CalibrationResult.load("/tmp/nonexistent_calibration_result.joblib")
    assert False, "Expected ValueError for missing file"
except ValueError as e:
    print(f"  Error message: {e}")
    assert "not found" in str(e).lower() or "not exist" in str(e).lower()
print("  PASSED")

# Test 3: incompatible feature order
print("Test 3: incompatible feature order")
tmp_path2 = '/tmp/test_incompatible.joblib'
result.save(tmp_path2)
artifact = joblib.load(tmp_path2)
artifact["feature_order"] = ["nonexistent_feature"]  # invalid
joblib.dump(artifact, tmp_path2)
try:
    CalibrationResult.load(tmp_path2)
    assert False, "Expected ValueError for incompatible feature order"
except ValueError as e:
    print(f"  Error message: {e}")
    assert "feature_order" in str(e).lower()
os.unlink(tmp_path2)
print("  PASSED")

print("\nAll save/load tests PASSED!")