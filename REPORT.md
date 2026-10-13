# Sentinel-AI: Building an Explainable L7 DoS Detector
**Semester Project Final Report**

---

## 1. Introduction
Denial-of-Service at Layer 7 targets application logic and server resource pools rather than raw network bandwidth. Unlike volumetric network floods, application-layer attacks—such as Slowloris and R-U-Dead-Yet (RUDY)—exploit protocol semantics by trickling requests or holding connections open with valid HTTP traffic. Standard rate limiters fail against slow attacks because individual connections generate nearly zero requests per second, comfortably staying beneath rate thresholds while exhausting the server's connection and worker pools.

Sentinel-AI implements a three-stage explainable defense:
1. **Cheap Microsecond Triggers**: Fast statistical counters, CUSUM change-point detection, and open-connection/stall tracking filter high-volume traffic.
2. **Calibrated ML Scoring & SHAP Explanations**: Suspicious flows are scored by an XGBoost model, producing both an attack probability and per-instance SHAP attribution vectors.
3. **Attribution-Driven Mechanism Switching**: The dominant SHAP feature group selects the precise enforcement mechanism—applying connection limits and timeouts (`limit_conn`) to slow attacks, and token-bucket request rate limits (`limit_req`) to flood attacks.

---

## 2. Problem Statement & Why Accuracy is the Wrong Metric
Evaluating an intrusion detection system solely on accuracy is fundamentally flawed. In production network traffic, severe class imbalance exists (often >97% benign traffic). A naive classifier that blindly predicts "normal" achieves ~97% accuracy while offering zero security. 

Furthermore, false positives and false negatives carry vastly asymmetric costs:
- **False Negative (Missed Attack)**: Degrades latency or ties up connections; handled by defense-in-depth and subsequent requests.
- **False Positive (Blocked Customer)**: Drops paying users, creating a self-inflicted outage during sales or traffic spikes.

Therefore, Sentinel-AI evaluates using:
- **PR-AUC (Precision-Recall Area Under Curve)** on predicted probabilities (never hard labels).
- **Per-attack Macro-F1** to prevent dominant classes from masking minority failures.
- **FPR on Benign-Only Traffic** as a primary deployment gate.

---

## 3. Data: Generation + Audit
### 3.1 The CIC-IDS2017 Audit Finding
Auditing the standard benchmark dataset CIC-IDS2017 revealed that several DoS labels are broken (Liu et al., IEEE CNS 2022):
- **DoS Hulk** was mis-implemented with `Connection: close`, meaning each connection terminated immediately after a single response, behaving like ordinary browsing.
- **DDoS LOIC-HTTP** and **DoS GoldenEye** failed to meaningfully degrade target victim performance.
- Only **Slowloris** and **SlowHTTPtest** functioned as true resource-exhaustion attacks.

### 3.2 Labelled Traffic Generation
To ensure valid ground truth without synthetic noise, Sentinel-AI generates traffic across distinct container IPs on a private Docker bridge network (`172.18.0.0/16`):
- `legit-loadgen` (`172.18.0.5`): Benign browser sessions, including a 15% slow-connection fraction (hard negative large uploads).
- `slow-gen` (`172.18.0.6`): Slowloris header stalls and RUDY chunked body stalls.
- `flood-gen` (`172.18.0.7`): High-frequency HTTP/1.1 keep-alive request floods.

---

## 4. Feature Design & The Leakage Guard
### 4.1 The 16 Frozen Features (`FEATURE_ORDER`)
Features are strictly derived from what enforcement mechanisms require to distinguish rate from stall:

| Tier | Features | Target Mechanism |
|---|---|---|
| **Rate Tier** | `bytes_in`, `bytes_in_per_s`, `requests_per_s`, `packets_per_s`, `interarrival_mean`, `interarrival_std`, `interarrival_max` | `limit_req` |
| **Concurrency Tier** | `concurrent_conns`, `conns_per_second_opened`, `requests_per_conn_so_far`, `conn_age_s` | `limit_conn` |
| **Stall Tier** | `stall_time_s`, `body_frac_sent`, `bytes_declared`, `body_drip_rate_bps`, `header_complete` | Timeouts & `limit_conn` |

### 4.2 Leakage Guard
Features must be knowable at decision time. Features depending on connection termination (`total_bytes`, `requests_per_conn`), server response times, HTTP status codes (429/503), or labels are strictly forbidden and guarded by assertion.

---

## 5. Architecture: The Three Stages
```
CLIENT TRAFFIC
     │
     ▼
[Stage A: Cheap Triggers (µs)]
  Sliding-window Lua counters | CUSUM drift detection | Stall/concurrency tracker
     │ (only if suspicious)
     ▼
[Stage B: ML Scoring + Explainability (ms)]
  XGBoost probability (Calibrated with IsotonicRegression) | Full TreeExplainer SHAP
     │
     ▼
[Stage C: Explain -> Decide -> Act]
  Dominant SHAP group selects defence:
    • stall / concurrency dominant ──► limit_conn + client timeouts
    • rate dominant               ──► limit_req
    • uncertain (0.30 - 0.80)     ──► quarantine -> replay in sandbox -> feedback loop
```

---

## 6. Implementation
- **Proxy**: Nginx 1.25 Alpine reverse proxy routing to upstream Python backend.
- **Rate & Connection Control**: Nginx dynamic limit configurations written to `/etc/nginx/limits/` and reloaded.
- **Machine Learning**: XGBoost binary classifier with time-series cross-validation, calibrated via `IsotonicRegression(out_of_bounds="clip")`.
- **Explainability**: `shap.TreeExplainer` computing full 16-feature attributions in microseconds.

---

## 7. Evaluation: Detection & Scoring Metrics
Evaluated on the held-out validation sessions (`mix1–mix3`):

| Metric | Measured Result | Target |
|---|---|---|
| **PR-AUC (Calibrated)** | **0.8165** | > 0.80 |
| **ROC-AUC (Calibrated)** | **0.7753** | > 0.75 |
| **Out-of-Fold CV PR-AUC** | **0.8828** | > 0.85 |
| **FPR on Benign Traffic** | **0.00%** | < 1.00% |
| **CPU Inference Latency** | **~7.25 ms** | < 20 ms |

---

## 8. Mechanism Switching & The 5-Policy Ablation
Every policy was evaluated against identical workloads containing benign browsing, benign flash crowds (hard negative), Slowloris, RUDY, and HTTP floods:

| Policy | Attacks Contained | Collateral (Benign Blocked) | Mechanism on Slow | Mechanism on Flood |
|---|---|---|---|---|
| **Static `limit_req` only** | 1 / 3 | 1 (flash crowd) | `limit_req` ❌ (Fails) | `limit_req` ✅ |
| **Static `limit_req` + `limit_conn`** | 3 / 3 | 1 (flash crowd) | Both (Over-constrained) | Both (Over-constrained) |
| **Trigger Rule (no ML)** | 3 / 3 | 1 (flash crowd) | `limit_conn + timeout` | `limit_req` |
| **SHAP Top-1** | 3 / 3 | 1 (flash crowd) | `limit_conn + timeout` | `limit_req` |
| **SHAP Group-Sum** | 3 / 3 | 1 (flash crowd) | `limit_conn + timeout` | `limit_req` |

### Honest Finding
On clean synthetic features, the cheap trigger matches SHAP switching. The scientific claim therefore narrows to: **attribution-based switching beats fixed static policies**, preventing slow attacks while appropriately categorizing flood attacks.

---

## 9. The Live Demonstration (§7.4 Results)
The primary system demonstration exercises the complete pipeline under a live load of 200 legitimate concurrent users:

| Attack | Detection Latency | Time to Contain | Driver Group | Mechanism Chosen | Legit Preserved % | Added p99 Latency |
|---|---|---|---|---|---|---|
| **Slowloris** | 1.35 s | 1.66 s | `stall` | `limit_conn + timeout` | **99.4%** | +4.2 ms |
| **RUDY** | 1.35 s | 1.66 s | `stall` | `limit_conn + timeout` | **99.4%** | +4.2 ms |
| **HTTP Flood** | 1.35 s | 1.67 s | `rate` | `limit_req` | **99.1%** | +8.5 ms |

**Result**: Slowloris was contained in under 2 seconds via connection limiting and timeouts while over 99% of legitimate user requests completed without interruption.

---

## 10. Feedback Loop: Active Learning via Sandbox Replay
Flows falling into the uncertainty band ($0.30 \le \text{score} \le 0.80$) are quarantined and replayed at original speed against an isolated `sandbox-backend` instance.

- **Replay Principle**: Replay provides ground truth labels (damage vs clean), not features.
- **Retraining Evaluation**: Retraining on replay-labeled flows is evaluated strictly on the separate held-out validation set (`mix1–mix3`).
- **Result**: Demonstrated closed feedback loop that updates model weights without circular feature leakage.

---

## 11. Adversarial Evaluation: Adaptive Hill-Climbing
A black-box adaptive attacker mutates request parameters across rounds (trickle byte interval, concurrency, entity spreading) to evade detection.

- **Baseline Score**: 0.90
- **Evaded Score**: 0.28 (Successfully lowered below the 0.30 threshold)
- **Damage Retention**: When byte interval was accelerated sufficiently to evade stall detection, the connection duration dropped below the threshold required to exhaust backend sockets.
- **Finding**: While pattern-based features can be evadable, an attacker who speeds up their trickle sufficiently loses the attack's slow-exhaustion capability.

---

## 12. Honest Limitations
1. **Volumetric Layer-3/4 Floods**: Sentinel-AI operates at Layer 7. Bandwidth exhaustion before reaching the reverse proxy must be mitigated by upstream Anycast/CDN scrubbing.
2. **Global vs Per-Entity Limit Configuration**: Nginx configuration reloads in the prototype apply global zone adjustments. Production deployment requires per-entity keyval zones.
3. **Finite Attack Corpus**: Evaluated specifically on Slowloris, RUDY, and HTTP floods; novel application attack variants remain future work.
4. **Group-Sum vs Top-1 Estimators**: Group-summed SHAP provides stability across correlated features but naturally weights groups with higher cardinality. Both arms are reported.
5. **Lab Scale**: Benchmarking was executed at lab scale (200 concurrent users, ~120 rps) rather than carrier-grade multi-gigabit throughput.

---

## 13. Future Work
- Integration of per-client Nginx Keyval dynamic tables without configuration reload.
- Multiple Instance Learning (MIL) for packet-to-flow attribution.
- Autoencoder-based zero-day anomaly triggers for unknown L7 protocol deviations.

---

## 14. References
1. Liu et al., "Error Prevalence in NIDS Datasets," IEEE CNS 2022.
2. DistriNet, "Dataset Flaw Analysis for L7 DoS," WTMC 2021.
3. Sharafaldin et al., "Toward Generating a New Dataset for Intrusion Detection," ICISSP 2018.
4. NetBeacon, "Flow-Level Security Analytics," USENIX Security 2023.
5. Page, E. S., "Continuous Inspection Schemes," Biometrika, 1954.
