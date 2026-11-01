import sys
import os
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("m1_capture"))
sys.path.insert(0, os.path.abspath("m3_scoring"))

import pandas as pd
import numpy as np
from m3_scoring.calibrate import calibrate
from m3_scoring.train_xgb import train
from features import FEATURE_ORDER
from sklearn.metrics import average_precision_score, roc_auc_score, confusion_matrix

# Load partitions
X_train = pd.read_csv("data/X_train.csv")
y_train = pd.read_csv("data/y_train.csv").squeeze("columns")
X_cal = pd.read_csv("data/X_cal.csv")
y_cal = pd.read_csv("data/y_cal.csv").squeeze("columns")
X_val = pd.read_csv("data/X_val.csv")
y_val = pd.read_csv("data/y_val.csv").squeeze("columns")

# Align features
X_train = X_train[FEATURE_ORDER]
X_cal = X_cal[FEATURE_ORDER]
X_val = X_val[FEATURE_ORDER]

print("Partitions loaded:")
print("  Train: %d rows" % len(X_train))
print("  Cal: %d rows" % len(X_cal))
print("  Val: %d rows" % len(X_val))
print()

# Define the 4 candidate configs
configs = {
    "baseline": dict(n_estimators=400, max_depth=5, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8),
    "smaller": dict(n_estimators=200, max_depth=5, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8),
    "shallower": dict(n_estimators=400, max_depth=3, learning_rate=0.1, subsample=0.8, colsample_bytree=0.8),
    "lower_lr": dict(n_estimators=400, max_depth=5, learning_rate=0.05, subsample=0.8, colsample_bytree=0.8),
}

results = {}

for name, params in configs.items():
    print("Training %s config..." % name)
    model = train(X_train, y_train, X_val, y_val, params=params)

    # Calibrate on held-out calibration partition
    result = calibrate(model, X_cal, y_cal)

    # Evaluate on untouched validation partition
    val_scores = model.predict_proba(X_val)[:, 1]
    calibrated_val_probs = result.calibrator.predict(val_scores)

    val_pr_auc = average_precision_score(y_val, val_scores)
    val_roc_auc = roc_auc_score(y_val, val_scores)
    calibrated_pr_auc = average_precision_score(y_val, calibrated_val_probs)
    calibrated_roc_auc = roc_auc_score(y_val, calibrated_val_probs)

    # ECE calculation
    def expected_calibration_error(y_true, y_pred_proba, n_bins=10):
        bin_edges = np.linspace(0, 1, n_bins + 1)
        ece = 0.0
        total = len(y_true)
        for i in range(n_bins):
            in_bin = (y_pred_proba > bin_edges[i]) & (y_pred_proba <= bin_edges[i+1])
            if np.sum(in_bin) > 0:
                prop = np.sum(in_bin) / total
                avg_conf = np.mean(y_pred_proba[in_bin])
                avg_acc = np.mean(y_true[in_bin])
                ece += prop * np.abs(avg_conf - avg_acc)
        return ece

    ece_uncal = expected_calibration_error(y_val, val_scores)
    ece_cal = expected_calibration_error(y_val, calibrated_val_probs)

    # Confusion matrix at threshold 0.5
    y_pred = (val_scores >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, y_pred).ravel()

    results[name] = {
        "val_pr_auc": val_pr_auc,
        "val_roc_auc": val_roc_auc,
        "cal_pr_auc": calibrated_pr_auc,
        "cal_roc_auc": calibrated_roc_auc,
        "ece_uncal": ece_uncal,
        "ece_cal": ece_cal,
        "precision": tp / (tp + fp) if (tp + fp) > 0 else 0,
        "recall": tp / (tp + fn) if (tp + fn) > 0 else 0,
        "fpr": fp / (fp + tn) if (fp + tn) > 0 else 0,
    }

    print("%s results:" % name)
    print("  Val PR-AUC: %.4f" % val_pr_auc)
    print("  Val ROC-AUC: %.4f" % val_roc_auc)
    print("  ECE uncal: %.4f" % ece_uncal)
    print("  ECE cal: %.4f" % ece_cal)
    print("  Precision: %.4f" % results[name]["precision"])
    print("  Recall: %.4f" % results[name]["recall"])
    print("  FPR: %.4f" % results[name]["fpr"])
    print()

# Select best based on: attack recall > PR-AUC > ECE improvement
print("=== Summary ===")
for name, r in results.items():
    print("%s: precision=%.4f recall=%.4f fpr=%.4f val_pr_auc=%.4f cal_pr_auc=%.4f ece_uncal=%.4f ece_cal=%.4f" % (
        name, results[name]["precision"], results[name]["recall"], results[name]["fpr"],
        results[name]["val_pr_auc"], results[name]["cal_pr_auc"], results[name]["ece_uncal"], results[name]["ece_cal"]))

# Pick best based on recall (documented priority)
best_name = max(results.keys(), key=lambda k: results[k]["recall"])
print("Best recall config: %s with recall %.4f" % (best_name, results[best_name]["recall"]))