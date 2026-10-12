import sys
sys.path.insert(0, 'm1_capture')
sys.path.insert(0, '.')
sys.path.insert(0, 'm3_scoring')

import joblib
import numpy as np
import xgboost as xgb
from calibrate import calibrate, CalibrationResult
from features import FEATURE_ORDER

np.random.seed(42)
n = 200
X = np.random.rand(n, len(FEATURE_ORDER))
y = np.random.randint(0, 2, n)
model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
model.fit(X[:150], y[:150])

result = calibrate(model, X[150:], y[150:])

# Test 1: Exact match (should pass)
tmp_path = '/tmp/test_exact_match.joblib'
result.save(tmp_path)
loaded = CalibrationResult.load(tmp_path)
print('Test 1 PASS: Exact feature order match loads OK')

# Test 2: Unknown feature (should fail)
artifact = joblib.load(tmp_path)
artifact['feature_order'] = ['nonexistent'] + FEATURE_ORDER[1:]
joblib.dump(artifact, tmp_path)
try:
    CalibrationResult.load(tmp_path)
    print('Test 2 FAIL: Unknown feature should have been rejected')
except ValueError as e:
    print('Test 2 PASS: Unknown feature rejected')

# Test 3: Reordered feature (should fail)
artifact = joblib.load(tmp_path) if False else joblib.load('/tmp/test_exact_match.joblib')
reordered = FEATURE_ORDER[1:] + [FEATURE_ORDER[0]]  # cycle first to end
artifact['feature_order'] = reordered
joblib.dump(artifact, tmp_path)
try:
    CalibrationResult.load(tmp_path)
    print('Test 3 FAIL: Reordered features should have been rejected')
except ValueError as e:
    print('Test 3 PASS: Reordered features rejected')

# Test 4: Missing feature (shorter list, should fail)
artifact = joblib.load(tmp_path) if False else joblib.load('/tmp/test_exact_match.joblib')
shortened = FEATURE_ORDER[:10]  # only 10 features
artifact['feature_order'] = shortened
joblib.dump(artifact, tmp_path)
try:
    CalibrationResult.load(tmp_path)
    print('Test 4 FAIL: Shortened feature order should have been rejected')
except ValueError as e:
    print('Test 4 PASS: Shortened feature order rejected')

import os
try:
    os.unlink(tmp_path)
except:
    pass
print('All validation tests done')
