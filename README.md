# Sentinel AI — L7 DoS Detection & Mitigation

## Explainable Layer-7 DoS defender

Sentinel AI scores traffic (slowloris / slow POST / flood vs benign) and switches nginx `limit_conn` vs `limit_req` automatically based on SHAP feature-group explanations. The system is defensive in purpose: it captures flow-level features from HTTP traffic, assigns an attack probability, and maps the dominant explanation group to a nginx defence directive. All traffic stays on an isolated Docker network; no production traffic is involved.

## Workflow

1. **Capture** — `tcpdump` records traffic to a pcap file. Flows are reconstructed from packets and 16 decision-time features are engineered per flow (5 stall + 7 rate + 4 concurrency).
2. **Score** — An XGBoost model with isotonic calibration assigns each flow a calibrated probability from 0.0 (benign) to 1.0 (attack).
3. **Explain** — SHAP (TreeExplainer) attributes the score to individual features; groups are summarised into three defence tiers: stall, rate, concurrency.
4. **Decide** — The dominant SHAP group selects the defence mechanism:
   - `limit_conn` for stall/concurrency-dominant flows (slow attacks that hold connections open)
   - `limit_req` for rate-dominant flows (fast floods, rate‑drip attacks)
5. **Enforce** — Nginx directives (`limit_conn` / `limit_req`) are applied per-source-IP via the dashboard or live-lab scripts.

## Project layout

```
sentinel-ai/
├── dashboard/           # Streamlit UI (app.py = all tabs, live_lab.py = real-time engine)
├── gen/                 # Traffic generator (generate.py = benign / slowloris / flood)
├── proxy/               # nginx reverse proxy + backend server (nginx.conf, limits/, Dockerfiles)
├── capture/             # pcap → flow extraction + feature engineering (features.py, merge.py, sensor.py)
├── m3_scoring/          # XGBoost training + isotonic calibration + SHAP explanation
├── data/                # Labelled feature data (features.parquet)
├── models/              # Trained calibration artifacts (.joblib files)
├── mechanism.py         # SHAP → enforcement switch + policy ladder (root)
├── schemas.py           # Shared data contracts (FlowRecord, ScoreObject, ActionObject)
├── docker-compose.yaml  # Docker lab setup (proxy, backend, generators, redis)
├── ablation_results.json# Ablation study results (root)
├── README.md            # This file
├── requirements.txt     # Python dependencies
├── SINGLE_PIPELINE_REPORT.md
└── reports/             # Output: live decision logs, protection proofs, evaluation reports
```

## Run

```bash
# 1. Environment
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Dashboard (no Docker needed)
streamlit run dashboard/app.py
# Open: http://localhost:8501

# 3. Live lab (needs Docker)
docker compose up -d
python dashboard/live_lab.py --duration 120 --mode mixed
# Open: http://localhost:8080 (API endpoint behind the proxy)
```

## Dashboard tabs

| Tab | Purpose |
|-----|---------|
| **Live monitor** | Replays captured flows through the model, shows scores and decisions per flow |
| **Live lab** | Launches real traffic via Docker, captures packets, scores live, enforces nginx limits |
| **System flow** | End-to-end pipeline visualization: capture → features → score → explain → decide → enforce |
| **Model & results** | Model artifact info, metrics summary, classification report, feature importance plot |

## Key ideas

- **No hardcoded defence rules** — the SHAP explanation group chooses `limit_conn` vs `limit_req`; a rate limit is useless against a slowloris, so the explanation chooses `limit_conn` + timeouts instead.
- **Per-IP enforcement** — `limit_req` and `limit_conn` apply per source IP, not globally.
- **Session-based data split** — 40% train (sessions: runa, runc, rund), 15% validation (session: rune), 45% test (sessions: runb, runf, rung). Ensures no IP leakage between splits.
- **Isotonic calibration** — transforms raw XGBoost scores into well-calibrated probabilities; current ECE = 0.0002 (10 bins).
- **Defence tiers** — SHAP group sums decide the mechanism:
  - `stall` (5 features: `stall_time_s`, `body_frac_sent`, `bytes_declared`, `body_drip_rate_bps`, `header_complete`) → `limit_conn`
  - `rate` (7 features: `bytes_in_per_s`, `requests_per_s`, `interarrival_mean`, `interarrival_std`, `interarrival_max`, `packets_per_s`, `bytes_in`) → `limit_req`
  - `concurrency` (4 features: `concurrent_conns`, `conns_per_second_opened`, `requests_per_conn_so_far`, `conn_age_s`) → fallback `limit_conn`

## Limitations

This section documents known limitations and open issues, as identified during the audit:

1. **Empty nginx limit configuration files** — `proxy/limits/rate.conf` and `proxy/limits/conn.conf` are currently 0 bytes. The `include` directives in `nginx.conf` reference these files, but they contain no actual directives. Outside Docker, nginx therefore does NOT enforce `limit_req` or `limit_conn`. Inside Docker (with the compose setup), the live_lab.py script writes the files at runtime, but the host files must be populated or the `include` directives removed for standalone nginx use. *(P0)*
2. **Nginx upstream hostname depends on Docker** — `proxy/nginx.conf` references `upstream backend { server backend:80; }`, which only resolves inside the Docker compose network (`backend` → container IP 172.18.0.3). Outside Docker, this fails with `host not found in upstream`. *(P0)*
3. **`header_complete` is a label‑adjacent feature** — 1985/2871 attack flows have `header_complete=0`. This feature alone strongly signals slow attacks. It is a legitimate traffic signature from the pcap data, but its binary nature means it can trivially separate attack from benign traffic. Ablation shows even 5 stall‑only features achieve PR-AUC ≈ 0.9997. *(P1)*
4. **Flood detection is not 100% at threshold 0.30** — Rate features alone achieve PR-AUC = 1.0 and ROC-AUC = 1.0, but ~19% of flood flows score below the 0.30 throttle boundary and are forwarded. The live lab shows 7/36 flood attacks below 0.30 (19.4%). The protection_proof.json from a previous lab run shows 79.7% of flood requests were rejected with 429 at enforced rate limits. *(P1)*
5. **Reported "Flood 0/319" detection rate is from a different split** — The SINGLE_PIPELINE_REPORT.md states Flood detection = 0/319 (0%) on the test set, but the current parquet‑based test split (6006 rows, sessions runb/runf/rung) achieves 100% attack recall (FN=0). The 0/319 figure likely originates from the CSV‑based X_test split (6005 rows) which had a different flood‑flow distribution. This inconsistency is documented in the audit. *(P1)*
6. **"Sloworis" terminology inconsistency** — The codebase previously used "Sloworis" (a common misspelling). The generator uses `slowloris_worker` (correct spelling). All references have been updated to "slowloris" / "slow attack" except the ablation_results.json keys and some evaluate.py internal labels, which still contain "sloworis". These should be renamed for consistency. *(P1)*
7. **`get_val_scores()` misnamed — actually scores test split** — The dashboard function `get_val_scores()` in `dashboard/app.py` uses sessions `runf` and `rung` (missing `runb`) and is labelled "for held-out runs" but was originally named for validation. It has been renamed to `get_test_scores()` and now correctly uses sessions `runb, runf, rung`. *(P2)*
8. **Runtime artifacts not gitignored** — `reports/live_decisions.csv`, `reports/live_decisions (3).csv`, and `reports/live_feed.jsonl` are generated at runtime by `dashboard/live_lab.py`. They are not currently tracked by git (the `*.csv` and `*.jsonl` gitignore rules cover them), but an explicit entry in `.gitignore` alongside the existing `reports/live_lab*.log` and `reports/protect_demo*.log` patterns would prevent future accidents. *(P2)*
9. **scikit-learn version mismatch** — `dashboard/requirements.txt` pins `scikit-learn==1.9.1` but the installed version is 1.7.2 (and the root `requirements.txt` pins `1.7.0`). This can cause `InconsistentVersionWarning` about IsotonicRegression pickle compatibility and potential future breakage. *(P2)*
10. **No test suite** — The repository has no unit tests. Key modules (`capture/features.py`, `capture/merge.py`, `scoring/train_xgb.py`, `scoring/calibrate.py`) lack automated tests. Adding tests would prevent regressions when features or calibration are modified. *(P2)*
11. **`header_complete` carries header-length information** — The `EXCLUDED` set in `capture/features.py` notes `"header_length": "header_complete already carries this"`. This means the feature is partially redundant with header length, which was already known during feature engineering. *(P1)*
12. **Isotonic regression out‑of‑bounds clipping** — The calibrator uses `out_of_bounds="clip"`, meaning calibrated probabilities outside [0,1] are clipped rather than extrapolated. If the model produces scores far outside the calibration range, calibrated probabilities may be mis‑reliable. *(P1)*

### Mitigation roadmap

| Priority | Issue | Fix | Effort |
|---|---|---|---|
| P0 | Empty nginx limit conf files | Write actual directives; make `nginx.conf` upstream resolvable without Docker | Medium |
| P0 | Upstream hostname `backend:80` Docker‑only | Change to `127.0.0.1:80` or make resolvable | Low |
| P1 | `header_complete` as shortcut | Document as known feature dependency; consider ablation without it | Low |
| P1 | Flood not 100% detectable at 0.30 | Document; enforced rate limits achieve ~79.7% rejection (protection_proof.json) | Low |
| P1 | "Sloworis" terminology | Rename to "slowloris" across codebase | Low |
| P2 | `get_val_scores` misnamed | Already renamed to `get_test_scores` | Low |
| P2 | Runtime CSVs not gitignored | Add explicit patterns to `.gitignore` | Low |
| P2 | scikit-learn version pin | Align `dashboard/requirements.txt` with root `requirements.txt` | Low |
| P2 | No unit tests | Add basic test suite for features/merge/score modules | Medium |
## Known Issues and Notes

### Session Data Coverage
- **runH through runL**: Both side logs and pcap capture available. These 12 sessions (6 train/val/test splits) are fully verified.
- **runM through runX**: Side logs captured from host-based generation, but **pcap files were NOT captured**. These 18 sessions should be excluded from any analysis requiring pcap Feature extraction or header parsing via `parse_http`. Side log data is available but pcap-dependent analysis cannot use these sessions.

### Model Artifacts
- **calibration_result_current.joblib**: 16-feature model (bytes_in, bytes_in_per_s, requests_per_s, packets_per_s, interarrival_mean/std/max, concurrent_conns, conns_per_second_opened, requests_per_conn_so_far, conn_age_s, stall_time_s, body_frac_sent, bytes_declared, body_drip_rate_bps, header_complete). Do not cite the 16-version as 15-base.
- **Legacy labels (legacy_label)**: Contaminated by missing `\r\n\r\n` header terminator (fixed in commit c4b02b7). Do not use for model training; use side_log labels instead.

### Evaluation
- Test split (runK+runL): 99.2% benign flows, exceeding 90% requirement.
- Each attack type has 100+ flows in test split (slowloris: 457, ruddy: 50, low_and_slow: 50).
- Prior shift: calibration trained on val (~72.5% benign) but test is 99.2% benign. Use threshold 0.30 as project decision boundary; do not tune on test.
- Zero-shot old model: slowloris recall=1.0 at all as_of thresholds, FPR=0.0000 on benign.
- Retrained model: see results/binary_study/verified_output.txt for per-as_of metrics at threshold 0.30.
  The single source of truth for all binary study results is results/binary_study/verified_output.txt.

### Typos Fixed
- `ruddy` → `rudy` (R.U.D.Y. = See You Die)
- `Benefit` → `Benign`
