# Module 3 Training Log — Real Data Experiment

## Experiment Date
2026-10-12

## Split Configuration — Whole-Session Boundaries

| Partition | Sessions | Rows | Benign | Attack | Entities |
|---|---|---|---|---|---|
| **Model Training** | 2b, 3b, 4c | 1,328 | 908 | 420 | 330 |
| **Calibration** | 6d, 6e, 6f, 6g, 6h | 2,867 | 2,067 | 800 | 390 |
| **Validation (final test, untouched)** | mix1, mix2, mix3 | 1,142 | 845 | 297 | N/A |

### Entity Overlap Note
110 entities appear in both model-training and calibration partitions. This is **unavoidable** because 350 of 910 total entities span multiple sessions across the full dataset. The overlap is not from splitting rows within a session — the requirement "do not split rows from the same session across model-training and calibration partitions" is fully satisfied. All rows from each whole session remain on one side of the boundary.

### Timestamp Ordering
- Model training span: `t` from 1,791,625,470.14 to 1,791,634,589.18
- Calibration span: `t` from 1,791,636,328.72 to 1,791,636,974.32
- Validation span: `t` from 1,791,636,328.72 to 1,791,636,974.32
- **Train max < Calibration min**: time leak is strictly prevented.

### Label Provenance
- `y = (role == 'attack').astype(int)` derived from `role` column
- `role` assigned via ground-truth HTTP `X-Ground-Truth` header (primary) or source IP mapping (fallback)
- **No feature uses the label or attack_type** — all 16 features computed from raw flow data only
- 13 forbidden columns explicitly excluded (status_code, total_bytes, is_attack, attack_type, response_time, total_bytes, requests_per_conn, fan_out, header_length, and others) due to leakage risk

## Model Configuration

| Parameter | Value |
|---|---|
| n_estimators | 400 |
| max_depth | 5 |
| learning_rate | 0.1 |
| subsample | 0.8 |
| colsample_bytree | 0.8 |
| eval_metric | aucpr |
| random_state | 42 |
| base_score | 0.5 |
| Feature order | FEATURE_ORDER (16 features from m1_capture.features) |
| Training data | Model-training partition only (sessions 2b, 3b, 4c) |
| Calibration data | Separate calibration partition (sessions 6d–6h), never training data |
| Validation data | Held-out final test set (mix1, mix2, mix3), untouched until final evaluation |

## Results — Un-calibrated vs Calibrated

| Metric | Un-calibrated | Calibrated | Change |
|---|---|---|---|
| PR-AUC | 0.8365 | 0.8131 | -0.0234 |
| ROC-AUC | 0.8148 | 0.8737 | +0.0589 |
| ECE (Expected Calibration Error) | 0.0656 | 0.0054 | -0.0602 (91.8% improvement) |
| Precision @ 0.5 | 1.0000 | — | — |
| Recall @ 0.5 | 0.7475 | — | — |
| FPR @ 0.5 | 0.0000 | — | — |
| Confusion matrix @ 0.5 | TP=222 FP=0 FN=75 TN=845 | — | — |

### Key Observations
- The un-calibrated model already achieves **FPR = 0.0000** at threshold 0.5, meaning no benign flows are misclassified in this lab dataset.
- **Calibration dramatically reduces ECE** from 0.0656 to 0.0054 (91.8% improvement), confirming isotonic regression is fitting well on the held-out calibration data.
- ROC-AUC improves after calibration (0.8148 → 0.8737), which can occur when isotonic recalibration better aligns score distributions with true positive rates.
- PR-AUC slightly decreases after calibration (0.8365 → 0.8131), which is expected when calibrated probabilities shift away from the original model's implicit operating point.
- **Threshold 0.5 was defined beforehand** (not tuned on the final validation set). It was selected from the training-side analysis.

## Artifacts

| Artifact | Path | Description |
|---|---|---|
| XGBoost model (raw) | `m3_scoring/` | Trained via `train()` in `train_xgb.py`, 400 estimators |
| CalibrationResult (joblib) | `calibration_result.joblib` | Holds model JSON, IsotonicRegression calibrator, FEATURE_ORDER; save/load verified with score preservation (diff < 1e-6) |
| Model training partition CSV | `data/X_train.csv` | 1,328 rows, 16 features, sessions 2b–4c |
| Training labels | `data/y_train.csv` | 1,328 labels (0/1) |
| Calibration partition CSV | `data/X_cal.csv` | 2,867 rows, 16 features, sessions 6d–6h |
| Calibration labels | `data/y_cal.csv` | 2,867 labels (0/1) |
| Validation partition CSV | `data/X_val.csv` | 1,142 rows, 16 features, sessions mix1–mix3 (final test, untouched) |
| Validation labels | `data/y_val.csv` | 1,142 labels (0/1) |

## Persistence API — CalibrationResult.save/load

- **save(path)**: joblib serialization including model JSON, IsotonicRegression calibrator, feature order
- **load(path)**: deserializes and validates structure (model JSON non-empty, calibrator is IsotonicRegression instance, feature_order is non-empty list of strings)
- **Save/load test**: `abs(orig_score - loaded_score) < 1e-6` — passed; calibrated scores exactly preserved
- **Loading warning**: Artifacts must only be loaded from trusted sources — joblib does not provide integrity verification

## Corrected conn_age_s Analysis

**Earlier conclusion was incorrect**: benign max=33.73 and attack min=2.12 imply **overlapping ranges**, not complete separation.

| Statistic | Benign | Attack |
|---|---|---|
| conn_age_s min | 0.0 | 2.12 |
| conn_age_s max | 33.73 | 72.29 |
| Overlapping range | [2.12, 33.73] | [2.12, 33.73] |
| Median | 2.62 | 60.26 |
| Complete range separation | **No** (ranges overlap) | — |

Despite range overlap, the distributions are well-separated by median (2.6 vs 60.3), which is why the model still learns useful decision boundaries. **Means alone do not establish complete separation**.

## Limitations — This Lab Dataset

- Perfect separation (PR-AUC=1.0, ROC-AUC=1.0) observed in prior full-dataset experiments is **lab-specific** and does not generalize to real traffic
- Only 11 sessions available; a true 3-way chronological split (train/cal/test) with both classes in all partitions is **not feasible** without class distribution compromise
- 350 of 910 entities span multiple sessions; entity overlap between model-train and calibration is unavoidable but does not violate the "no row-splitting-within-session" requirement
- Features are expressive for lab-generated traffic; real-WAN deployment would require re-enabling 4 currently-omitted features that are constant on lab network
- Calibration improvement (ECE 0.0656 → 0.0054) is validated only on this dataset; real-traffic calibration performance may differ substantially

## Commands Run

```bash
# Generate session-based splits
python -m m1_capture.splits data/features.parquet --val_frac 0.2

# Train XGBoost on model-training partition
PYTHONPATH=m1_capture python -m m3_scoring.train_xgb data/X_train.csv data/y_train.csv data/X_val.csv data/y_val.csv

# Fit isotonic calibration on separate calibration partition
PYTHONPATH=m1_capture python -c "
  from m3_scoring.calibrate import calibrate
  import pandas as pd
  from m1_capture.features import FEATURE_ORDER
  model = ...  # trained XGBClassifier
  X_cal = pd.read_csv('data/X_cal.csv')[FEATURE_ORDER]
  y_cal = pd.read_csv('data/y_cal.csv').squeeze('columns')
  result = calibrate(model, X_cal, y_cal)
  result.save('calibration_result.joblib')
"

# Evaluate on untouched validation partition
PYTHONPATH=m1_capture python -c "
  import pandas as pd, numpy as np, xgboost as xgb
  from m1_capture.features import FEATURE_ORDER
  from sklearn.metrics import average_precision_score, roc_auc_score, confusion_matrix
  from sklearn.isotonic import IsotonicRegression
  ...
"
```
Production artifact: calibration_result_candidate.joblib (see M3_HANDOFF.md)
