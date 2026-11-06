# Sentinel-AI Evaluation Metrics

**Computed on the session-based test split** (sessions: runb, runf, rung).
Metrics are **per unique flow**, not per snapshot row.
Threshold: 0.30 (project's own decision boundary).

## Per-Flow Confusion Matrix @ 0.30

| Metric | Value |
|---|---|
| **True Positives** (attack flows flagged) | 2871 |
| **True Negatives** (benign flows not flagged) | 3134 |
| **False Positives** (benign flows flagged) | 1 |
| **False Negatives** (attack flows not flagged) | 0 |
| **Accuracy** | 0.9998 |
| **Precision** | 0.9997 |
| **Recall** | 1.0 |
| **F1 Score** | 0.9998 |

## Flow-Level Detection Rates

- **Attack flows flagged:** 2871 / 2871 (1.0)
- **Benign flows flagged:** 1 / 3135 (0.0003)
- **Total flows:** 6006 (2871 attack, 3135 benign)

## Age at First Flag (Attacks)

- **Median age at first flag:** 60.0 s
- **p90 age at first flag:** 135.0 s
- **Attack flows with a flag:** 2871 / 2871

## Aggregate Metrics (row-level)

- **PR-AUC (calibrated):** 1.0
- **ROC-AUC (calibrated):** 1.0
- **ECE (10 bins, lower is better):** 0.000204

## Test Split Summary

- **Snapshot rows:** 6006
- **Unique flows:** 6006
- **Threshold:** 0.3
- **Attack fraction:** 0.478 (1=attack, 0=benign)

## Notes

- The `profile` heuristic (slowloris/flood/benign guess from flow shape) is
  used only as a display label (`display_guess`), never as ground truth.
- Detailed `attack_type` (slowloris, slow_post, flood, benign) comes from
  the off-the-wire side log written by `gen/generate.py --side-log`, not from
  any string inside the traffic.
