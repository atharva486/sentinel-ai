# Slow-attack detection: why the model missed slowloris, and the fix

**Status:** fixed in the live path (`dashboard/live_lab.py`). Model, features,
calibration and `ablation_results.json` are unchanged. No retraining.

---

## 1. The symptom

In the on-the-wire lab, slow attacks were detected late or not at all:

| Live run | Slowloris flows | Caught |
|---|---|---|
| 30 s mixed | 36 | ~19 % |
| 30 s mixed | 38 | ~34 % |
| 120 s mixed, age <= 30 s | 36 | 0 / 36 |
| 120 s mixed, age >= 30 s | 18 | 18 / 18 (scores 0.87-1.00) |

The detector was not failing at random. It was failing on **young** flows and
working perfectly on **old** ones. That is the signature of a model that learned
flow age instead of the attack's semantics.

RUDY had never been exercised live (`--mode slow` launches slowloris only), so
its live number was unknown. On the labelled dataset it was 0/275 (below).

---

## 2. Root cause (measured, not inferred)

### 2.1 The model's feature importances

Gain importance on the shipped model:

| Feature | Importance |
|---|---|
| `bytes_declared` | 0.3431 |
| `stall_time_s` | 0.1508 |
| `conn_age_s` | 0.1081 |
| `header_complete` | **0.0000** |
| `body_frac_sent` | **0.0000** |
| `concurrent_conns` | **0.0000** |

The three features that *define* a slow attack — an unfinished header, an
unfinished declared body, and many sockets held open — carry **zero** weight.
The features that carry all the weight are proxies for "this flow is old".

### 2.2 The dataset makes age a perfect shortcut

| Class | `conn_age_s` range |
|---|---|
| Benign | up to **33.7 s** |
| Slowloris | **55-80 s** |
| Flood | **25-40 s** |

There is no benign flow older than 33.7 s and no slowloris flow younger than
55 s. A single split on age separates the classes, so the model never needed to
learn the attack.

### 2.3 The model's decision boundary is the clock

Scoring synthetic flows with the shipped model + calibrator:

| Flow | Calibrated score |
|---|---|
| Slowloris, 20 s old | 0.0967 |
| Slowloris, 30 s old | 0.6940 |
| Slowloris, 40 s old | 1.0000 |
| **Normal benign keep-alive, 45 s old** | **1.0000** |

Two consequences:

1. **False negatives for the first ~30 s.** The attack is invisible until it has
   been running for half a minute. That is exactly the window the live lab was
   measuring.
2. **A latent false-positive risk.** A perfectly normal long-lived keep-alive
   (45 s, e.g. a browser holding a connection) scores 1.0000. The dataset never
   contained one, so this was never measured on real benign traffic.

### 2.4 RUDY is actively pushed toward benign

On the labelled dataset at `DETECT_THRESHOLD` (0.30):

| Attack class | Detected by model |
|---|---|
| Flood | 319 / 319 |
| Slowloris | 923 / 923 |
| **RUDY** | **0 / 275** |

SHAP for a RUDY flow (`bytes_declared = 5,000,000`):

```
bytes_declared = 5,000,000  ->  SHAP -3.20
```

Normal benign traffic declares large bodies (3,811 of 3,820 benign rows have
`bytes_declared > 0`). RUDY declares a 5 MB body and sends none of it, and the
model reads "large declared body" as *strong evidence of benign*. The attack's
defining signal points the wrong way.

---

## 3. The fix

Module 2 already contains semantic stall rules (`m2_triggers/stall.py`) that
look for the actual attack shapes: an unterminated header, an unfinished
declared body, a body arriving below 100 B/s. They do not learn from the
dataset, so they do not inherit its age shortcut. They were simply **not in the
live path** — `live_lab.py` scored with the model alone.

The fix is an OR, not a retrain:

```
effective_score = max(model_calibrated_score, stall_rule_severity)
```

Implemented in `dashboard/live_lab.py`:

* `stall_evidence()` runs Module 2's `detect()` on the same feature vector the
  model just scored and keeps the semantic reasons.
* If the rule's severity is higher than the model's score, the verdict, group
  (`stall`), mechanism (connection cap + 10 s timeout) and action come from the
  rule. The model's score is never lowered, so every model detection is
  preserved.
* Enforcement is still driven by `ON_THRESHOLD = 0.55`; the rule's severities
  are 0.60-1.00, so a rule hit escalates immediately.

### Why only three reasons are used

`STALL_REASONS_USED = ("header_incomplete", "body_incomplete", "slow_drip")`.

The other Module 2 rules are age-only (`long_idle_connection` fires at
`conn_age_s > 60`, `zero_req_per_conn` at `conn_age_s > 20`). Because the
dataset contains no benign flow older than 33.7 s, those rules were never
validated against real long-lived benign keep-alives — and a 70 s keep-alive
with one request is normal traffic. They are deliberately excluded from the
live gate.

### Two measurement corrections in the live lab

1. **`COUNT_THRESHOLD = DETECT_THRESHOLD` (0.30).** The confusion matrix used
   the enforcement threshold (0.55). The project's own detection threshold is
   0.30 (the throttle rung), so 0.55 under-counted true positives by a whole
   rung.
2. **`observing` state.** An open flow younger than `STALL_THRESHOLD_S` (10 s)
   has not had a fair chance to show its behaviour. It is reported as
   `observing` and excluded from TP/FP/TN/FN instead of being counted as a miss.

---

## 4. Validation

### 4.1 Offline, through the exact live adapter

Every labelled flow in `data/features.parquet` scored through
`stall_evidence()`:

| Class | Rule fired |
|---|---|
| Slowloris | **923 / 923** |
| RUDY | **275 / 275** |
| Flood | 0 / 319 |
| Benign | **6 / 3,820 (0.16 %)** |

Reasons: slowloris 923 `header_incomplete`; RUDY 275 `body_incomplete` +
275 `slow_drip`; benign 6 `header_incomplete`.

### 4.2 Unit tests

`test_stall_live_gate.py` pins the behaviours that make the OR safe:

* incomplete header at 12 s fires;
* complete header at 12 s does not;
* nothing fires before the 10 s window;
* a 5 MB declared body with 0 % delivered fires;
* a 70 s keep-alive with one request does **not** fire (age-only rule
  excluded);
* a stall verdict is contained by `limit_conn` + timeout, never `limit_req`.

### 4.3 Live, 120 s mixed run

See the run record in `reports/live_lab.log` and `reports/live_decisions.csv`.
Per-attacker recall is computed from the `evidence` and `score` columns of that
CSV; only measured values are reported.

---

## 5. What this does and does not claim

* **Does:** the live detector now catches slowloris and RUDY inside the first
  10 s, with no change to the shipped model or its reported metrics.
* **Does:** the 0.16 % benign rule rate is measured on the labelled dataset.
* **Does not:** prove the model itself generalises to slow attacks. It does not;
  its age shortcut is still in the artifact. The OR is an engineering control
  around a known model limitation, and that limitation is documented here.
* **Does not:** claim long-lived benign keep-alives are safe from the *model*.
  The 45 s keep-alive still scores 1.0000. The stall gate does not make that
  worse, but the model-level false positive remains a known risk.
