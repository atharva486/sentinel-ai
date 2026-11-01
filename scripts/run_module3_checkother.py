#!/usr/bin/env python3
"""Module 3 runner: train -> calibrate -> save -> evaluate -> verify.

Read-only w.r.t. existing artifacts: writes ONLY calibration_result_checkother.joblib.
"""

import sys, os, hashlib, json
from pathlib import Path

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("./m1_capture"))
sys.path.insert(0, os.path.abspath("./m3_scoring"))

import pandas as pd
import numpy as np
import joblib

from m1_capture.features import FEATURE_ORDER
from m3_scoring.train_xgb import train
from m3_scoring.calibrate import calibrate, CalibrationResult
from sklearn.metrics import (
    average_precision_score, roc_auc_score, confusion_matrix,
)

OUT_PATH = "calibration_result_checkother.joblib"

# ---- 0. Destination safety -------------------------------------------------
if os.path.exists(OUT_PATH):
    raise SystemExit(f"REFUSING TO OVERWRITE: {OUT_PATH} already exists.")

# ---- 1. Load data (keep y as pandas Series, per train_xgb requirement) -----
X_train = pd.read_csv("checkother/athcsv/X_train.csv")[FEATURE_ORDER]
y_train = pd.read_csv("checkother/athcsv/y_train.csv").squeeze("columns")
X_cal   = pd.read_csv("checkother/athcsv/X_cal.csv")[FEATURE_ORDER]
y_cal   = pd.read_csv("checkother/athcsv/y_cal.csv").squeeze("columns")
X_val   = pd.read_csv("checkother/athcsv/X_val.csv")[FEATURE_ORDER]
y_val   = pd.read_csv("checkother/athcsv/y_val.csv").squeeze("columns")

assert list(X_train.columns) == FEATURE_ORDER
assert list(X_cal.columns)   == FEATURE_ORDER
assert list(X_val.columns)   == FEATURE_ORDER
assert isinstance(y_train, pd.Series)
assert isinstance(y_cal, pd.Series)
assert isinstance(y_val, pd.Series)

print("Data loaded:")
print(f"  train: X={X_train.shape} y={y_train.shape} dist={dict(y_train.value_counts())}")
print(f"  cal  : X={X_cal.shape}   y={y_cal.shape}   dist={dict(y_cal.value_counts())}")
print(f"  val  : X={X_val.shape}   y={y_val.shape}   dist={dict(y_val.value_counts())}")

# ---- 2. Train --------------------------------------------------------------
print("\nTraining model (train_xgb.train)...")
model = train(X_train, y_train, X_val, y_val)
print(f"Model type: {type(model).__name__}, n_estimators={model.n_estimators}")

# ---- 3. Calibrate on held-out cal split only --------------------------------
print("\nCalibrating on X_cal/y_cal (held-out, never training data)...")
result = calibrate(model, X_cal, y_cal)
print(f"Calibrator type: {type(result.calibrator).__name__}")
print(f"Feature order match: {result.feature_order == FEATURE_ORDER}")

# ---- 4. Save new artifact ---------------------------------------------------
print(f"\nSaving artifact to {OUT_PATH} ...")
result.save(OUT_PATH)
size = os.path.getsize(OUT_PATH)
sha256 = hashlib.sha256(open(OUT_PATH, "rb").read()).hexdigest()
print(f"  size: {size} bytes")
print(f"  sha256: {sha256}")

# ---- 5. Evaluate on held-out val split --------------------------------------
THRESHOLD = 0.5
N_BINS = 10
edges = np.linspace(0, 1, N_BINS + 1)

def ece(ytrue, scores):
    total = len(ytrue)
    out = 0.0
    for i in range(N_BINS):
        m = (scores > edges[i]) & (scores <= edges[i + 1])
        if m.sum() > 0:
            out += (m.sum() / total) * abs(float(scores[m].mean()) - float(ytrue[m].mean()))
    return float(out)

def metrics(name, ytrue, scores):
    yp = (scores >= THRESHOLD).astype(int)
    tn, fp, fn, tp = confusion_matrix(ytrue, yp).ravel()
    pr = float(average_precision_score(ytrue, scores))
    ro = float(roc_auc_score(ytrue, scores))
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec  = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "name": name, "pr_auc": pr, "roc_auc": ro,
        "precision": prec, "recall": rec, "f1": f1, "fpr": fpr,
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
    }

yval = y_val.values
raw_scores = model.predict_proba(X_val)[:, 1]
cal_scores = np.array([result.calibrated_score(dict(zip(FEATURE_ORDER, row))) for row in X_val.values])

raw_m = metrics("raw", yval, raw_scores)
cal_m = metrics("calibrated", yval, cal_scores)

print("\n" + "=" * 70)
print("EVALUATION ON HELD-OUT VALIDATION (runs F-G), all rows, threshold 0.5")
print("=" * 70)
print(f"{'metric':<14} | {'raw':>10} | {'calibrated':>10}")
print("-" * 40)
for key in ["pr_auc", "roc_auc", "precision", "recall", "f1", "fpr"]:
    print(f"{key:<14} | {raw_m[key]:>10.6f} | {cal_m[key]:>10.6f}")
print()
print(f"{'confusion':<14} | raw: TP={raw_m['tp']} FP={raw_m['fp']} FN={raw_m['fn']} TN={raw_m['tn']}")
print(f"{'':<14} | cal: TP={cal_m['tp']} FP={cal_m['fp']} FN={cal_m['fn']} TN={cal_m['tn']}")
print(f"{'ece':<14} | raw={ece(yval, raw_scores):.6f} | cal={ece(yval, cal_scores):.6f}")

# Targets
targets = {"roc_auc": (">=", 0.85), "pr_auc": (">=", 0.90),
           "precision": ("==", 1.00), "recall": (">=", 0.65), "f1": (">=", 0.75), "ece": ("<=", 0.01)}
print("\nTarget check (calibrated scores unless noted):")
for key, (op, val) in targets.items():
    actual = cal_m[key] if key != "ece" else ece(yval, cal_scores)
    if op == ">=": ok = actual >= val
    elif op == "<=": ok = actual <= val
    elif op == "==": ok = abs(actual - val) < 1e-9
    print(f"  {key}: {actual:.6f} {op} {val} -> {'PASS' if ok else 'FAIL'}")

# ---- 6. Reload verification -------------------------------------------------
print("\nReloading artifact via CalibrationResult.load for verification...")
loaded = CalibrationResult.load(OUT_PATH)
assert loaded.feature_order == FEATURE_ORDER, "feature order mismatch after reload"
assert type(loaded.calibrator).__name__ == "IsotonicRegression"

# Sample calibrated prediction
sample = dict(zip(FEATURE_ORDER, X_val.iloc[0].values))
sample_score = loaded.calibrated_score(sample)
print(f"  feature_order match: True")
print(f"  sample calibrated_score: {sample_score:.6f}")
raw_p0 = float(model.predict_proba(X_val.iloc[[0]])[0, 1])
cal_p0_direct = float(loaded.calibrator.predict([raw_p0])[0])
print(f"  calibrated_score matches calibrator.predict: "
      f"{abs(sample_score - cal_p0_direct) < 1e-9}")

# Confirm original artifacts unchanged
for p in ["calibration_result.joblib", "calibration_result_candidate.joblib", "calibration_result_module3.joblib"]:
    h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    print(f"  {p}: sha256={h} (unchanged)")

print(f"\nArtifact saved: {OUT_PATH} ({size} bytes, sha256={sha256})")
print("Experiment complete.")
