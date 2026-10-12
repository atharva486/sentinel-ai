# Sentinel-AI Module 3 Hyperparameter Comparison & Baseline Candidate Handoff

## Overview

This document describes the selected baseline model for Module 3, the comparison experiment that led to its selection, and instructions for integration teams.

### Selected Configuration

| Parameter | Value |
|---|---|
| n_estimators | 400 |
| max_depth | 5 |
| learning_rate (LR) | 0.1 |
| subsample | 0.8 |
| colsample_bytree | 0.8 |
| random_state | 42 |
| Feature contract | 16 features from `FEATURE_ORDER` (frozen) |

### Reported Metrics (on untouched validation set `mix1-mix3`)

| Metric | Value |
|---|---|
| PR-AUC (raw scores) | **0.8115** |
| ROC-AUC (raw scores) | **0.7546** |
| PR-AUC (calibrated) | 0.8131 |
| ROC-AUC (calibrated) | 0.8737 |
| ECE (uncalibrated) | 0.0656 |
| **ECE (calibrated)** | **0.0054** |
| Precision (threshold 0.5) | **1.0** |
| **Recall (threshold 0.5)** | **0.7475** |
| **FPR (threshold 0.5)** | **0.0** |
| Per-sample CPU inference latency | **~7.25 ms** |
| Batch latency (20 runs on 1142 samples) | ~8.28 ms per run |
| Confusion matrix (threshold 0.5) | TP: 222, FP: 0, FN: 75, TN: 845 |

### Artifact Paths

| Artifact | Path | Description |
|---|---|---|
| **Original** | `calibration_result.joblib` | Original artifact (XGBoost + IsotonicRegression). **Do not modify or overwrite.** |
| **Candidate (baseline)** | `calibration_result_candidate.joblib` | New artifact with the selected baseline config. Trained on sessions 2b-4c, calibrated on 6d-6h, evaluated once on mix1-mix3. |

### Feature Contract

- **16 features** from `FEATURE_ORDER` (imported from `m1_capture.features`)
- Feature order is **frozen and enforced** via `CalibrationResult.load()`
- Leakage guard: 16 forbidden column names (e.g., `status_code`, `is_attack`, `attack_type`, etc.)
- All features must match `FEATURE_ORDER` exactly on load; reordered or shortened orders raise `ValueError`

### Loading & Scoring Example (integration-ready)

```python
import joblib
from m3_scoring.calibrate import CalibrationResult

# Load the candidate artifact
artifact = CalibrationResult.load("calibration_result_candidate.joblib")

# Score a single flow's features (dict keyed by feature name)
flow_features = {
    "bytes_in": 225021.0,
    "bytes_in_per_s": 10807.93,
    "requests_per_s": 0.10,
    "packets_per_s": 3.0,
    "interarrival_mean": 0.34,
    "interarrival_std": 0.46,
    "interarrival_max": 2.22,
    "concurrent_conns": 0.0,
    "conns_per_second_opened": 0.0,
    "requests_per_conn_so_far": 2.0,
    "conn_age_s": 20.82,
    "stall_time_s": 0.0,
    "body_frac_sent": 1.0,
    "bytes_declared": 3531.0,
    "body_drip_rate_bps": 10800.63,
    "header_complete": 1.0,
}

# Calibrated attack probability
prob = artifact.calibrated_score(flow_features)
# prob is a float in [0, 1] representing the calibrated attack risk

# SHAP explanation (full per-feature mapping)
shap_explanation = artifact.model  # XGBoost model for shap.TreeExplainer
from m3_scoring.explain import explain
shap_values = explain(model=artifact.model, flow_features=flow_features)
# shap_values is a dict: {feature_name -> shap_value}, exactly 16 entries,
# all finite floats. Larger positive values push the prediction toward attack.
```

### Calibration Details

- **Calibrator**: `IsotonicRegression(out_of_bounds="clip")`
- **Calibration data**: sessions 6d–6h (held-out, never used for model selection or threshold tuning)
- **Validation data**: sessions mix1–mix3 (completely untouched, final held-out test)
- **Calibrator fitted once** on calibration partition after final model training
- **Never re-calibrate** on training or validation data; doing so would violate the separation guarantee
- **ECE (expected calibration error) after calibration**: 0.0054 (excellent calibration)

### Dependencies

- Python 3.10+
- `xgboost`, `scikit-learn`, `numpy`, `pandas`, `joblib`
- `m1_capture` (provides `session_time_split`, `FEATURE_ORDER`, session metadata)
- `m3_scoring` (provides `train()`, `calibrate()`, `CalibrationResult`, `explain()`)
- SHAP for explanations (optional, used by `m3_scoring.explain`)

### Test Commands

```bash
# Run existing test suites (must-pass prerequisites)
python test_save_load.py        # 3/3 PASSED
python test_persistence.py      # 3/3 PASSED
python test_feature_order.py    # 4/4 PASSED

# Run the candidate artifact integration test
python test_candidate_artifact.py  # all PASSED (feature-order validation,
                                    # calibrated scoring, SHAP contract)

# Verify original artifact is untouched
joblib.load("calibration_result.joblib")  # should load successfully
```

### Limitations

- **RUDY (Rapid UDP DoS) attacks have not been separately validated** on the mix1-mix3 hold-out. The validation set contains mix1/mix2/mix3 traffic patterns; RUDY-specific behavior cannot be guaranteed without dedicated evaluation.
- Calibration is isotonic regression, which can overfit if the calibration partition is too small (2867 rows in this case — adequate but not unlimited).
- Feature order is strict: any deviation from the exact `FEATURE_ORDER` list (even a single reordered feature) will cause `CalibrationResult.load()` to raise `ValueError`.
- Inference latency measured on CPU only; GPU acceleration would change per-sample timing.
- All metrics reported on the untouched validation set (mix1-mix3). Results on other data distributions may differ.

### Integration Team Instructions

1. **Do not modify `calibration_result.joblib`**. It is the shared artifact and must remain in its original state.
2. **Use `calibration_result_candidate.joblib`** for the selected baseline model and calibration.
3. When loading the candidate artifact, always verify `feature_order` matches `FEATURE_ORDER` (the `CalibrationResult.load()` method enforces this).
4. Scoring: call `artifact.calibrated_score(flow_features_dict)` for calibrated attack probability in [0, 1].
5. SHAP: use `m3_scoring.explain.explain(model=artifact.model, flow_features=dict)` for the full 16-feature SHAP mapping.
6. If retraining is needed in the future, respect the session splits:
   - Model-train: sessions 2b, 3b, 4c
   - Calibration: sessions 6d, 6e, 6f, 6g, 6h
   - Validation/test: mix1, mix2, mix3 (untouched)
7. Keep `random_state=42` for reproducibility of the training pipeline.
8. Do not use the validation set (mix1-mix3) for hyperparameter tuning or threshold selection; it must remain completely untouched.

### Files Created or Changed

| File | Action |
|---|---|
| `m3_scoring/train_xgb.py` | Fixed `train()` to accept and use `params` dict (bug fix). The `params` argument was previously silently overridden by hardcoded defaults, making hyperparameter comparison impossible. |
| `calibration_result_candidate.joblib` | New artifact (baseline model + isotonic calibrator, 16 features, trained/evaluated as described). |
| `compare_hparam.py` | Experiment script that compares 4 hyperparameter configurations. |
| `test_hparam_experiment.py` | Focused tests: params argument usage, distinguishable PR-AUC results, reproducibility with fixed seed. |
| `test_candidate_artifact.py` | Focused integration test: artifact loading, feature-order validation, calibrated scoring, SHAP output contract. |
| `M3_HANDOFF.md` | This handoff document. |

### Contact / Questions

If the training or calibration code cannot reproduce the reported baseline metrics, or if the `params` fix in `train_xgb.py` causes unexpected behavior, please file an issue with the exact error and current artifact state. Do not modify the shared `calibration_result.joblib` without approval.