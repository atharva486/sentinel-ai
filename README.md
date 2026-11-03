# Sentinel AI — L7 DoS Detection & Mitigation

## Workflow 

Sentinel AI is an explainable Layer-7 DoS defender. Here is the end-to-end flow, in simple terms:

1. **Capture** — Real network traffic (pcap) is rebuilt into per-flow records with 16 features (bytes per second, requests per second, concurrent connections, stall time, body drip rate, etc.).
2. **Score** — An XGBoost model with isotonic calibration assigns each flow a score from 0.0 (benign) to 1.0 (attack).
3. **Explain** — SHAP breaks down which features drove the score and groups them into three defence tiers: stall (slow attacks), rate (floods), concurrency (connection hogs).
4. **Decide** — A policy ladder picks an action based on the calibrated score:
   - Score ≥ 0.80 → **Quarantine** (exit ≥ 0.70)
   - Score ≥ 0.55 → **Block** (exit ≥ 0.46)
   - Score ≥ 0.30 → **Throttle** (exit ≥ 0.24)
   - Score < 0.30 → **Forward** (let it through)
5. **Enforce** — Based on the SHAP explanation group, nginx applies:
   - `limit_conn` (max 20 concurrent connections) for stall/concurrency attacks
   - `limit_req` (max 50 requests per second) for rate attacks

### Critical thresholds
| Threshold | Value | Meaning |
|-----------|-------|---------|
| Detect threshold | 0.30 | Below this, traffic is treated as benign |
| Throttle | 0.30 → 0.24 | Enter throttle at 0.30, exit at 0.24 |
| Block | 0.55 → 0.46 | Enter block at 0.55, exit at 0.46 |
| Quarantine | 0.80 → 0.70 | Enter quarantine at 0.80, exit at 0.70 |
| Conn limit | 20 | Max concurrent connections per IP |
| Rate limit | 50 | Max requests per second per IP |
| Stall window | 10 s | Flows younger than 10 s are "observing", not yet judged |

### Critical points
- **No hardcoded rules** — the SHAP explanation chooses which defence to apply (rate limit vs connection limit vs both)
- **Per-IP enforcement** — limits apply per source IP, not globally
- **Observing window** — flows younger than 10 seconds are not yet classified (TP/TN/FP/FN excluded)
- **Docker required for live lab** — real packet capture and nginx reload need Docker; the dashboard works without it

---

## Project layout

```
sentinel-ai/
├── dashboard/           # Streamlit UI (app.py = all tabs, live.py = real-time engine, live_lab.py = packet lab runner)
├── gen/                 # Traffic generator (generate.py = benign / slowloris / flood / mixed traffic)
├── proxy/               # nginx reverse proxy + backend server (nginx.conf, backend_server.py, Dockerfiles, limits/)
├── capture/             # pcap → flow extraction + feature engineering (features.py, merge.py, sensor.py)
├── scoring/             # XGBoost training + isotonic calibration + SHAP explanation (train_xgb.py, calibrate.py, explain.py)
├── data/                # Labelled feature data (features.parquet)
├── models/              # Trained calibration artifacts (.joblib files)
├── reports/             # Output reports and live decision logs
├── sandbox/             # Sandbox environment (Dockerfile)
├── spec-code/           # Ablation study results (ablation_results.json)
├── mechanism.py         # SHAP → enforcement switch + policy ladder (root)
├── schemas.py           # Shared data contracts (FlowRecord, TriggerEvent, ScoreObject, ActionObject)
├── docker-compose.yaml  # Docker lab setup (proxy, backend, generators, redis)
├── requirements.txt     # Python dependencies
├── ablation_results.json# Ablation study results (root)
├── README.md            # ThiS file
```

## What each part does

### Root files
| File | Purpose |
|------|---------|
| `mechanism.py` | SHAP-to-enforcement switch: reads SHAP values, picks defence group, applies policy ladder with hysteresis |
| `schemas.py` | Shared data contracts: FlowRecord, TriggerEvent, ScoreObject, ActionObject dataclasses |
| `docker-compose.yaml` | Defines and links Docker services: proxy, backend, traffic generators, redis, m5 sandbox |
| `requirements.txt` | Python package dependencies |
| `ablation_results.json` | Results from the 5-policy ablation study |
| `REPORT.md` | Full project report |

### dashboard/ — Streamlit UI
| File | Purpose |
|------|---------|
| `app.py` | Main Streamlit app with all tabs: Live monitor, Live lab, System flow, Model & results |
| `live.py` | Real-time engine: LiveEngine (scores flows), LiveSensor (tails pcap), LabRunner (Docker driver), pipeline animation |
| `live_lab.py` | Standalone lab runner: brings up Docker lab, launches traffic, captures packets, scores live, writes nginx limits |
| `README.md` | Dashboard-specific documentation |
| `requirements.txt` | Dashboard-only dependencies (streamlit, plotly) |

### gen/ — Traffic generator
| File | Purpose |
|------|---------|
| `generate.py` | Generates labelled L7 traffic: benign, slowloris, flood, and mixed profiles with per-IP source binding |
| `Dockerfile` | Builds the generator container (stays alive for `docker compose exec` control) |

### proxy/ — nginx + backend
| File | Purpose |
|------|---------|
| `nginx.conf` | nginx reverse proxy config: logs flows in JSON, proxies to backend, applies limit_req/limit_conn |
| `backend_server.py` | Simple Aurora Bank API portal behind the proxy (the attack target) |
| `Dockerfile` | nginx + tcpdocker image for the proxy container |
| `backend.Dockerfile` | Python backend container for the API portal |
| `limits/conn.conf` | nginx connection limit directive (written by live_lab.py) |
| `limits/rate.conf` | nginx rate limit directive (written by live_lab.py) |

### capture/ — pcap → flow → features
| File | Purpose |
|------|---------|
| `features.py` | 16-feature engineering per flow, grouped by defence tier (stall, rate, concurrency) |
| `merge.py` | Labels flows by source container IP (benign / slow / flood ground truth) |
| `sensor.py` | Parses pcap packets, reassembles TCP flows, extracts HTTP features |

### scoring/ — Model pipeline
| File | Purpose |
|------|---------|
| `train_xgb.py` | Trains XGBoost classifier with leakage guard and time-series cross-validation |
| `calibrate.py` | Isotonic calibration of raw model scores into trustworthy probabilities |
| `explain.py` | SHAP TreeExplainer: attributes each flow's score to individual features |

### Data and artifacts
| Path | Purpose |
|------|---------|
| `data/features.parquet` | Labelled feature dataset (5,337 flows) |
| `models/*.joblib` | Trained calibration artifacts (model + calibrator + feature order) |
| `reports/` | Output: live decision logs, protection proofs, evaluation reports |

---

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

---

## Dashboard tabs

| Tab | Purpose |
|-----|---------|
| **Live monitor** | Replays captured flows through the model, shows scores and decisions per flow |
| **Live lab** | Launches real traffic, captures packets, scores live, enforces nginx limits |
| **System flow** | End-to-end pipeline visualization: capture → features → score → explain → decide → enforce |
| **Model & results** | PR-AUC / ROC-AUC / ECE on held-out data, score distribution, policy ablation |
