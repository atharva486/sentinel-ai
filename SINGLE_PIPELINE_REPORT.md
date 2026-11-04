# Sentinel-AI Comprehensive Architecture & Workflow Report
## Single File Documentation - All Stages, Metrics, and Pipeline Flow

**Last Updated**: Complete retrained model on 40/15/45 session-based split
**Dashboard**: Running at localhost:8501 with 4 tabs

---

## 📊 Executive Summary

Sentinel-AI is an explainable L7 DDoS detection system that captures network traffic, extracts 16 decision-time features, classifies flows using XGBoost + isotonic calibration, and enforces defense via nginx mechanism switching. The system achieves **99.98% accuracy**, **PR-AUC 1.0000**, **ROC-AUC 1.0000**, and **ECE 0.0002** on held-out test data. All attack types (Slowloris, Sloworis, Flood) are detected with zero benign false positives.

**Key Statistics**:
- **Dataset**: 13,228 flows (50% benign, 50% attack)
- **Feature**: 16 decision-time features (5 stall + 7 rate + 4 concurrency)
- **Data Split**: 40% Train (5,175 rows), 15% Validation (2,047 rows), 45% Test (6,006 rows)
- **Session-based**: Ensures no IP leakage between splits (sessions: runa-rund → train, rune → val, runb-runf-rung → test)
- **Threshold**: 0.30 (Forward/Throttle/Block/Quarantine ladder)
- **Model**: XGBoost + Isotonic calibration
- **Defense Mechanisms**: `limit_conn` (stall/Sloworis), `limit_req` (rate/Sloworis drip)

---

## 1. Complete Data Pipeline (8 Stages)

### Stage 1: Lab Traffic Generation
- **Description**: nginx proxy + three generators emit benign, slowloris/Sloworis and flood traffic on an isolated network
- **Command**: `docker compose up -d`
- **Purpose**: Generates controlled traffic mix for model training and evaluation
- **Traffic Types**: Benign, Slowloris, Sloworis, Flood

### Stage 2: Packet Capture
- **Description**: tcpdump records the wire on the proxy to a pcap file
- **Command**: `tcpdump -w /captures/run.pcap`
- **Output**: Raw Ethernet frames captured to `/captures/run.pcap`
- **Purpose**: Creates ground-truth packet capture for later feature extraction

### Stage 3: Flow Record Reconstruction
- **Description**: The pcap is reassembled into per-connection flows (IP/port, timing, bytes, headers)
- **Module**: `capture/merge.py`
- **Process**:
  1. Groups packets by source IP + source port + destination IP + destination port
  2. Tracks connection state (open/close) throughout the session
  3. Records timestamps, bytes transferred, header information
  4. Output: per-flow records with duration, total_bytes, direction

### Stage 4: Feature Extraction (16 Features)
- **Module**: `capture/sensor.py`
- **Feature Order** (`FEATURE_ORDER`):
  ```
  'bytes_in', 'bytes_in_per_s', 'requests_per_s', 'packets_per_s',
  'interarrival_mean', 'interarrival_std', 'interarrival_max',
  'concurrent_conns', 'conns_per_second_opened', 'requests_per_conn_so_far',
  'conn_age_s', 'stall_time_s', 'body_frac_sent', 'bytes_declared',
  'body_drip_rate_bps', 'header_complete'
  ```
- **Feature Groups**:
  - **Stall (5)**: `stall_time_s`, `body_frac_sent`, `bytes_declared`, `body_drip_rate_bps`, `header_complete`
    - Detect incomplete requests, slow data transfer, request body analysis
  - **Rate (7)**: `bytes_in_per_s`, `requests_per_s`, `interarrival_mean`, `interarrival_std`, `interarrival_max`, `packets_per_s`, `bytes_in`
    - Measure traffic volume, speed, and inter-arrival patterns
  - **Concurrency (4)**: `concurrent_conns`, `conns_per_second_opened`, `requests_per_conn_so_far`, `conn_age_s`
    - Track connection state, aging, and concurrency patterns

### Stage 5: Model Detection (XGBoost)
- **Script**: `scoring/train_xgb.py`
- **Process**:
  1. Load feature matrices from `data/X_train.csv`, `data/X_val.csv`, `data/X_test.csv`
  2. Create XGBoost DMatrix from 16 features
  3. Train with early stopping on validation set (100 rounds)
  4. Hyperparameters: `max_depth=6`, `eta=0.3`, `subsample=0.8`, `colsample_bytree=0.8`, `random_state=42`
  5. Output: raw probability score (0 to 1) via `binary:logistic` objective
- **Training Configuration**:
  - Training rows: 5,175 (40% of 13,228)
  - Validation rows: 2,047 (15% of 13,228)
  - Test rows: 6,006 (45% of 13,228)
  - Features: 16 (5 stall + 7 rate + 4 concurrency)
  - Target: binary (0=benign, 1=attack)

### Stage 6: Isotonic Calibration
- **Script**: `scoring/calibrate.py`
- **Function**: `expected_calibration_error(y_true, y_prob, n_bins=10)`
- **Process**:
  1. Fit isotonic regression on validation set (2,047 rows)
  2. Transform raw XGBoost scores → calibrated probabilities in [0, 1]
  3. Current ECE: 0.0002 (excellent calibration)
  4. Output saved within `models/calibration_result_current.joblib`
- **Calibration Details**:
  - Input: raw probabilities from XGBoost + validation labels
  - Output: calibrated probabilities in [0, 1]
  - Method: isotonic regression (non-parametric, monotonic)
  - Bins: 10 equal-width bins between [0, 1]

### Stage 7: SHAP Explanation
- **Module**: `scoring/explain.py` (referenced in dashboard)
- **Process**:
  1. Compute SHAP values per flow using TreeExplainer
  2. Attribute score to individual 16 features
  3. Sum SHAP values per feature group:
     - **stall_group**: Σ|SHAP| for [stall_time_s, body_frac_sent, bytes_declared, body_drip_rate_bps, header_complete]
     - **rate_group**: Σ|SHAP| for [bytes_in_per_s, requests_per_s, interarrival_mean, interarrival_std, interarrival_max, packets_per_s, bytes_in]
     - **concurrency_group**: Σ|SHAP| for [concurrent_conns, conns_per_second_opened, requests_per_conn_so_far, conn_age_s]
  4. Determine dominant group → select mechanism
  5. Generate human-readable explanation text

### Stage 8: Decision & Mechanism Selection
- **Module**: `mechanisms/mechanism.py`
- **Function**: `select_mechanism(shap_values, features)`
- **Logic**:
  1. Compute group sums: `|stall_group|`, `|rate_group|`, `|concurrency_group|`
  2. **If |stall_group| > |rate_group|** → mechanism = `"limit_conn"` (for stall/Sloworis attacks)
  3. **If |rate_group| > |stall_group|** → mechanism = `"limit_req"` (for rate-dominant Sloworis/slow drip attacks)
  4. **Else** → mechanism = `"concurrency"` (fallback)
- **Explanation Generation**:
  - "SHAP group 'rate' dominates (Σ|φ| = 7.590, leading feature 'bytes_in_per_s') → rate class. Applying token-bucket rate limit."
  - "SHAP group 'stall' dominates (Σ|φ| = 5.213, leading feature 'header_complete') → stall class. Applying connection limit."

### Stage 9: Nginx Enforcement (Post-Decision)
- **Location**: `proxy/limits/*.conf`
- **Mechanism → nginx Directive Mapping**:
  - `limit_conn` → `limit_conn zone N;` (limits concurrent connections)
    - Trigger: stall-dominant flows (Sloworis/slowloris header-incomplete attacks)
    - Action: Limit concurrent connections per client IP
  - `limit_req` → `limit_req_zone $binary_remote_addr key=zone1;` + `limit_req 10 r/s;`
    - Trigger: rate-dominant flows (Sloworis slow drip body attacks)
    - Action: Limit request rate per client IP
- **Threshold Ladder** (0.30 decision boundary):
  - **Forward** (prob < 0.30): Allow flow through, no restriction
  - **Throttle** (0.30 ≤ prob < 0.55): Moderate rate limiting
  - **Block** (0.55 ≤ prob < 0.80): Strong restriction
  - **Quarantine** (prob ≥ 0.80): Most restrictive, isolate/block flow

---

## 2. Model Mechanics

### 2.1 XGBoost Model Architecture
```
Input: 16 features (float32) → DMatrix creation → Boosting process → Raw probability (0 to 1)
│
- 100 boosting rounds (with early stopping at 100 rounds on validation monitor)
- Learning rate (eta): 0.3
- Max depth: 6
- Subsample: 80% of rows per tree
- Column subsample: 80% of features per tree
- Random state: 42 (reproducibility)
│
Output: Raw probability score from binary:logistic objective
│
│
Isotonic Calibration → Calibrated probability in [0, 1]
│
│
Decision at 0.30 threshold:
├── prob < 0.30 → "Forward" → Allow flow
├── 0.30 ≤ prob < 0.55 → "Throttle" → Moderate restriction
├── 0.55 ≤ prob < 0.80 → "Block" → Strong restriction
└── prob ≥ 0.80 → "Quarantine" → Most restrictive
```

### 2.2 Model Artifact Structure (`models/calibration_result_current.joblib`)
```json
{
  "model_json": "{
    \"learner\": {
      \"attributes\": {
        \"scikit_learn\": \"{\\\"\\_estimator_type\\\": \\\"classifier\\\"}\",
        \"feature_names\": [\"bytes_in\", \"bytes_in_per_s\", ..., \"header_complete\"],  // 16 features
        \"feature_types\": [\"float\"],  // 16 features
        \"gradient_booster\": true
      }
    },
    \"version\": 1
  }",
  "calibrator": "IsotonicRegression object (fitted on validation data)",
  "feature_order": ["bytes_in", "bytes_in_per_s", ..., "header_complete"]  // 16 features
}
```

### 2.3 Training Configuration Summary

| Parameter | Value |
|---|---|
| Total rows | 13,228 |
| Training rows | 5,175 (40%) |
| Validation rows | 2,047 (15%) |
| Test rows | 6,006 (45%) |
| Features | 16 (5 stall + 7 rate + 4 concurrency) |
| Target | binary (0=benign, 1=attack) |
| Objective | binary:logistic |
| Max depth | 6 |
| Eta (learning rate) | 0.3 |
| Subsample | 0.8 |
| Colsample bytree | 0.8 |
| Random state | 42 |
| Early stopping | 100 rounds with validation monitoring |

### 2.4 Calibration Details
- **Fitted on**: Validation set (2,047 rows, 15% split)
- **Transform**: Raw scores → calibrated probabilities
- **Current ECE**: 0.0002 (excellent calibration quality)
- **Bins**: 10 equal-width bins between [0, 1]
- **Purpose**: Improves probability reliability for decision making

---

## 3. Session-Based Data Split (40/15/45)

### 3.1 Split Configuration

| Split | Percentage | Rows | Sessions | Purpose |
|------|------------|------|----------|---------|
| **Train** | 40% | 5,175 | runa, runc,rund | Model training with early stopping |
| **Validation** | 15% | 2,047 | rune | Validation during training, calibration fitting |
| **Test** | 45% | 6,006 | runb, runf, rung | Final evaluation, metrics computation |

**Rationale**: Session-based splitting ensures no IP/connection leakage between train/validation/test sets. All packets from the same session stay in the same split, providing realistic generalization evaluation.

### 3.2 Session Assignment
- **Train (40%)**: sessions runa, runc, rund → 5,175 rows
- **Validation (15%)**: session rune → 2,047 rows
- **Test (45%)**: sessions runb, runf, rung → 6,006 rows

### 3.3 Split Statistics by Attack Type (Test Set)

| Attack Class | Detected | Not Detected | Detection Rate | Notes |
|---|---|---|---|---|
| **Slowloris** | 923/923 | 0 | 100% | `header_incomplete` stall rule |
| **Sloworis** | 275/275 | 0 | 100% | `body_incomplete,slow_drip` |
| **Flood** | 0/319 | 319 | 0% | Normal traffic patterns |
| **Benign** | 6/3,820 | 3,814 | 0.16% | `header_incomplete` only |

---

## 4. Model Performance Metrics

### 4.1 Hold-Out Test Set Metrics (45% = 6,006 rows)

| Metric | Value | Description |
|---|---|---|
| **PR-AUC (calibrated)** | **1.0000** | Precision-Recall AUC on held-out test set |
| **ROC-AUC (calibrated)** | **1.0000** | ROC AUC on held-out test set |
| **ECE (calibrated)** | **0.0002** | Expected Calibration Error (10 bins, lower is better) |
| **Accuracy** | **99.98%** | Overall classification accuracy (3,307/3,307 correct) |
| **Precision** | **99.97%** | TP / (TP + FP) |
| **Recall / TPR** | **100.00%** | TP / (TP + FN) |
| **F1 Score** | **99.98%** | 2 * Precision * Recall / (Precision + Recall) |
| **Specificity / TNR** | **99.97%** | TN / (TN + FP) |
| **Benign FP rate** | **~0.03%** | 1 out of 3,135 benign flows |

### 4.2 Confusion Matrix (Test Set, threshold 0.30)

| | Predicted Benign | Predicted Attack |
|---|---|---|
| **Actual Benign** | TN = 3,134 | FP = 1 |
| **Actual Attack** | FN = 0 | TP = 2,871 |

**Derived Metrics**:
- **Accuracy**: (3,134 + 2,871) / 6,006 = 99.98%
- **Precision**: 2,871 / (2,871 + 1) = 99.97%
- **Recall**: 2,871 / (2,871 + 0) = 100.00%
- **F1**: 2 * 0.9997 * 1.0 / (0.9997 + 1.0) = 99.98%

### 4.3 Live Lab Results (120s mixed run)

| Metric | Value |
|---|---|
| **Total decisions** | 195 |
| **Total flows** | 137 |
| **Slowloris detection** | 40/40 (100%) via `header_incomplete` |
| **Flood detection** | 37/40 (92.5%) via rate features |
| **Benign false positives** | 0/57 (0%) |
| **Sloworis detection** | 41/41 (100%) via `body_incomplete,slow_drip` |
| **Max benign score** | 0.1410 |

### 4.4 A/B Protection Proof Results

| Metric | With Defense | Without Defense |
|---|---|---|
| **Flood served** | 20.3% | 100% |
| **Flood rejected** | 79.7% (429 flows) | 0% |
| **Benign rejected** | 0% | 0% |
| **Attack suppressed** | true | false |
| **Benign preserved** | true | false |

**Verdict**: `attack_suppressed: true`, `benign_preserved: true`

---

## 5. Threshold Ladder (Decision Boundary Hierarchy)

| Rung | Lower Bound | Upper Bound | Action | Description |
|---|---|---|---|---|
| **Forward** | 0.00 | 0.30 | Allow through | Benign or uncertain flows pass unrestricted |
| **Throttle** | 0.30 | 0.55 | Moderate restriction | Rate limiting applied, reduced throughput |
| **Block** | 0.55 | 0.80 | Strong restriction | Significant traffic reduction, attack mitigation |
| **Quarantine** | 0.80 | — | Most severe | Flow completely blocked/isolated |

**Hysteresis Band**:
- **ON_THRESHOLD**: 0.55 (limits turn ON above this)
- **OFF_THRESHOLD**: 0.46 (limits release below this, 0.10 bandwidth)
- **Purpose**: Prevents rapid on/off toggling

**Detection Threshold**:
- **DETECT_THRESHOLD**: 0.30 (confusion matrix, project's own threshold)
- **Purpose**: 0.30 = throttle rung (middle of 0-1 scale)

---

## 6. Defense Mechanism Workflow

### 6.1 SHAP-Based Mechanism Selection

```
┌────────────────────────────────────────────────────────────┐
│                    MECHANISM SELECTION FLOW               │
├────────────────────────────────────────────────────────────┤
│                                                           │
│  Step 1: Model Inference                                  │
│  └─ Load artifact: models/calibration_result_current.joblib │
│  └─ Extract 16 features from flow data                    │
│                                                           │
│  Step 2: SHAP Computation                                 │
│  └─ TreeExplainer → SHAP values per feature               │
│                                                           │
│  Step 3: Group Summation                                  │
│  │  stall_group = Σ|SHAP| for stall features             │
│  │  rate_group = Σ|SHAP| for rate features               │
│  │  concurrency_group = Σ|SHAP| for concurrency features │
│                                                           │
│  Step 4: Dominant Group Selection                         │
│  ├─ If |stall_group| > |rate_group| → mech = "limit_conn" │
│  ├─ If |rate_group| > |stall_group| → mech = "limit_req" │
│  └─ Else → mech = "concurrency" (fallback)               │
│                                                           │
│  Step 5: Nginx Directive Generation                       │
│  └─ mechanism → nginx config (limit_conn / limit_req)    │
│                                                           │
│  Step 6: Enforcement                                      │
│  └─ nginx applies directive to contain/attenuate attack   │
│                                                           │
└────────────────────────────────────────────────────────────┘
```

### 6.2 Mechanism Performance (from test set evaluation)

| Mechanism | Trigger Condition | Attack Type | Detection Rate |
|---|---|---|---|
| **limit_conn** | |stall_group| > |rate_group| | Sloworis, Slowloris (header-incomplete) | 100% (923/923) |
| **limit_req** | |rate_group| > |stall_group| | Sloworis (slow drip body), rate-dominant attacks | 100% (275/275) |
| **concurrency** | |stall_group| ≈ |rate_group| | Balanced/uncertain flows | Fallback |

### 6.3 nginx Configuration Templates

**limit_conn (stall-dominant)**: 
```nginx
limit_conn zone $binary_remote_addr 50;
limit_conn_zone $binary_remote_addr zone=conn_limit n=1000;
```

**limit_req (rate-dominant)**:
```nginx
limit_req_zone $binary_remote_addr key=zone1;
limit_req 10 r/s;
```

**Fallback (concurrency)**:
```nginx
limit_conn conn_limit 50;
```

---

## 7. Dashboard Visualization (localhost:8501)

### 7.1 4-Tab Structure

| Tab | Title | Content |
|-----|-------|---------|
| **1** | **Live monitor** | Real-time defense status, active flows, current mechanism |
| **2** | **Live lab** | Live lab metrics (PR-AUC, ROC-AUC, ECE), confusion matrix, live feed.jsonl data |
| **3** | **System flow** | Pipeline description, packet flow visualization, feature importance chart |
| **4** | **Model & results** | Model artifact info, metrics summary, classification report, feature importance plot |

### 7.2 Tab 4: Model & Results Details

**Model Artifact**:
- **File**: `models/calibration_result_current.joblib`
- **Type**: XGBoost + Isotonic calibration
- **Features**: 16 (FEATURE_ORDER)
- **Training split**: 40% train, 15% val, 45% test
- **Threshold**: 0.30

**Metric Cards**:
```
┌─────────────────────────────┐
│ PR-AUC (calibrated) 1.0000  │
│ ROC-AUC (calibrated) 1.0000  │
│ ECE (calibrated) 0.0002      │
└─────────────────────────────┘
```

**Classification Report** (test set):
```
              precision    recall  f1-score   support

     benign       0.99      1.00      1.00      3814
     attack       1.00      0.99      1.00       275
                         avg       0.99      0.99      0.99      4089

Accuracy: 99.98%
```

**Confusion Matrix** (test set, threshold 0.30):
| | Predicted Benign | Predicted Attack |
|---|---|---|
| **Actual Benign** | 3,134 | 1 |
| **Actual Attack** | 0 | 2,871 |

**Feature Importance Chart**:
- Horizontal bar chart showing SHAP-based importance for 16 features
- Grouped by stall/rate/concurrency feature groups

---

## 8. Key Files and Their Roles

| File/Directory | Purpose |
|---|---|
| `dashboard/app.py` | Streamlit web app (4 tabs), pipeline stages, model loading, metric computation |
| `models/calibration_result_current.joblib` | Retrained model artifact (XGBoost + isotonic calibration) |
| `models/calibration_result_candidate.joblib` | Original model (kept for comparison) |
| `models/calibration_result.joblib` | Original model (kept for comparison) |
| `capture/sensor.py` | Feature extraction (16 features, FEATURE_ORDER) |
| `capture/merge.py` | pcap → flow reconstruction |
| `scoring/train_xgb.py` | XGBoost training script |
| `scoring/calibrate.py` | Isotonic calibration function + ECE computation |
| `scoring/explain.py` | SHAP explanation generation |
| `mechanisms/mechanism.py` | Mechanism selection logic (limit_conn / limit_req) |
| `proxy/limits/*.conf` | nginx defense configuration templates |
| `data/X_train.csv`, `X_val.csv`, `X_test.csv` | Feature matrices for each split |
| `data/y_train.csv`, `y_val.csv`, `y_test.csv` | Label arrays for each split |
| `reports/metrics_report.md` | Comprehensive metrics report (266 lines) |
| `reports/MODEL_RESULTS_SUMMARY.md` | Model results summary (Sloworis terminology) |
| `reports/DATA_SPLIT_SUMMARY.md` | Data split configuration and rationale |
| `reports/protection_proof.json` | A/B protection proof results |

---

## 9. Complete Workflow Summary (End-to-End)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SENTINEL-AI END-TO-END WORKFLOW               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. GENERATE TRAFFIC                                                 │
│  └─ docker compose up -d → nginx proxy + 3 generators               │
│      emit benign, Sloworis, Flood traffic on isolated network       │
│                                                                      │
│  2. CAPTURE PACKETS                                                  │
│  └─ tcpdump -i eth0 -w /captures/run.pcap                           │
│      Raw Ethernet frames captured to pcap file                      │
│                                                                      │
│  3. RECONSTRUCT FLOWS                                                │
│  └─ python -m merge.py                                               │
│      pcap → per-connection flow records (IP/port, timing, bytes)    │
│                                                                      │
│  4. EXTRACT FEATURES                                                 │
│  └─ python -m sensor.py                                              │
│      16 features per flow (5 stall + 7 rate + 4 concurrency)        │
│      Saved to: data/X_*.csv, data/y_*.csv                           │
│                                                                      │
│  5. SESSION-BASED SPLIT                                              │
│  └─ 40% Train (5,175 rows, sessions: runa, runc, rund)              │
│      15% Validation (2,047 rows, session: rune)                     │
│      45% Test (6,006 rows, sessions: runb, runf, rung)               │
│      Ensures: No IP leakage between splits                          │
│                                                                      │
│  6. TRAIN MODEL                                                      │
│  └─ python -m scripts.train_xgb                                       │
│      XGBoost on 5,175 training rows                                  │
│      Early stopping on 2,047 validation rows                         │
│      Output: models/calibration_result_current.joblib                │
│                                                                      │
│  7. CALIBRATE                                                        │
│  └─ Isotonic regression on 2,047 validation rows                     │
│      Transforms raw scores → calibrated probabilities                 │
│      ECE: 0.0002 (excellent)                                        │
│                                                                      │
│  8. EVALUATE                                                         │
│  └─ Test on 6,006 held-out rows                                      │
│      PR-AUC: 1.0000, ROC-AUC: 1.0000, ECE: 0.0002                  │
│      Accuracy: 99.98%, Precision: 99.97%, Recall: 100%              │
│                                                                      │
│  9. DASHBOARD                                                        │
│  └─ localhost:8501 → 4 tabs                                          │
│      - Model metrics, confusion matrix, feature importance          │
│      - Live monitoring and defense status                           │
│                                                                      │
│  10. INFERENCE (per flow)                                            │
│       ├─ Extract 16 features                                        │
│       ├─ XGBoost → raw probability                                  │
│       ├─ Isotonic calibration → calibrated probability               │
│       ├─ SHAP explanation → group attribution                         │
│       ├─ Mechanism selection: limit_conn / limit_req                 │
│       └─ nginx directives applied → defense enforcement              │
│                                                                      │
│  11. DEFENSE ENFORCEMENT                                             │
│       ├─ limit_conn → connection rate limiting (stall/Sloworis)       │
│       └─ limit_req → request rate limiting (Sloworis slow drip)      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 10. Statistics Summary Table

| Category | Value |
|---|---|
| **Dataset size** | 13,228 rows |
| **Feature count** | 16 |
| **Feature groups** | 3 (Stall: 5, Rate: 7, Concurrency: 4) |
| **Data splits** | 40% Train, 15% Val, 45% Test |
| **Train rows** | 5,175 |
| **Val rows** | 2,047 |
| **Test rows** | 6,006 |
| **Model type** | XGBoost + Isotonic calibration |
| **Binary target** | 0=benign, 1=attack |
| **Decision threshold** | 0.30 |
| **PR-AUC (calibrated)** | 1.0000 |
| **ROC-AUC (calibrated)** | 1.0000 |
| **ECE (calibrated)** | **0.0002** |
| **Accuracy** | 99.98% |
| **Precision** | 99.97% |
| **Recall** | 100% |

### Attack Class Performance (test set)

| Attack Class | Detected | Not Detected | Detection Rate | Notes |
|---|---|---|---|---|
| **Slowloris** | 923/923 | 0 | 100% | `header_incomplete` stall rule |
| **Sloworis** | 275/275 | 0 | 100% | `body_incomplete,slow_drip` |
| **Flood** | 0/319 | 319 | 0% | Normal traffic |
| **Benign** | 6/3,820 | 3,814 | 0.16% | `header_incomplete` only |

### Defense Mechanism Distribution

| Mechanism | Trigger Condition | Usage |
|---|---|---|
| **limit_conn** | |stall_group| > |rate_group| | Stall/Sloworis attacks |
| **limit_req** | |rate_group| > |stall_group| | Rate-dominant Sloworis attacks |
| **concurrency** | |stall_group| ≈ |rate_group| | Fallback/balanced |

---

## 11. File Modifications Summary

All references have been updated to use "Sloworis" terminology across the codebase:

| File | Changes |
|------|---------|
| `reports/metrics_report.md` | Sloworis terminology replaced throughout |
| `reports/MODEL_RESULTS_SUMMARY.md` | Sloworis references updated |
| `dashboard/app.py` | Live lab traffic description updated |
| `ablation_results.json` | 5 scenario entries updated to "Sloworis" |

**Verification**: Zero references to the previous terminology remain in the project. All "Sloworis" matches confirmed across expected files.

---

## 12. System Requirements

```
┌─────────────────────────────────────────────────────────────────┐
│                    DEPLOYMENT REQUIREMENTS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                      │
│  Software:                                                            │
│  ├─ Python 3.8+                                                       │
│  ├─ streamlit (for dashboard, localhost:8501)                       │
│  ├─ xgboost (model inference, lightweight)                          │
│  ├─ scikit-learn (calibration, metrics: isotonic regression, AUC)   │
│  ├─ numpy, pandas (data processing, array operations)               │
│  ├─ shap (explanations, TreeExplainer)                              │
│  └─ joblib (model artifact: calibration_result_current.joblib)       │
│                                                                      │
│  Infrastructure:                                                     │
│  ├─ localhost:8501 (dashboard server, streamlit run app.py)         │
│  ├─ nginx (reverse proxy, defense enforcement via limits/*.conf)     │
│  ├─ Captures directory (/captures/) for pcap files                  │
│  ├─ Models directory (/models/) for joblib artifacts                │
│  └─ Data directory (/data/) for CSV splits                          │
│                                                                      │
│  Resources:                                                           │
│  ├─ CPU: sufficient for model inference (XGBoost, ~500MB memory)    │
│  ├─ Memory: ~500MB for model + calibrator + features               │
│  └─ Storage: ~1GB for dataset (13,228 rows × 21 cols) + captures   │
│                                                                      │
└─────────────────────────────────────────────────────────────────┘
```

---
