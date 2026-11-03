# Sentinel AI — L7 DoS Detection & Mitigation

Explainable Layer-7 DoS defender. Scores traffic (slowloris / RUDY / flood vs benign) and switches nginx `limit_conn` vs `limit_req` automatically based on SHAP explanations.

## How it works

1. **Capture** — Packet flows are rebuilt from pcap traffic into 16 features.
2. **Score** — An XGBoost model with isotonic calibration scores each flow as benign or attack.
3. **Explain** — SHAP breaks down which features drove the score (rate / stall / concurrency).
4. **Mitigate** — Based on the explanation, nginx applies `limit_conn` (for slow attacks) or `limit_req` (for floods). No hardcoded rules — the model decides.

## Project layout

```
l7-dos-defender/
├── dashboard/        # Streamlit UI (live monitor + live lab)
├── m1_capture/       # pcap → flow extraction + feature engineering
├── m2_triggers/      # Stall / attack detection rules
├── m3_scoring/       # XGBoost + calibration + SHAP explanation
├── m5_sandbox/       # Adversarial replay tests
├── dashboard/protect_demo.py  # Live enforcement against nginx proxy
├── gen/generate.py   # Traffic generator (benign / slowloris / flood)
├── proxy/            # nginx config + limit directives
├── data/             # Features parquet + train/cal/val CSVs
├── captures/         # PCAP captures (gitignored)
├── models/           # Trained calibration artifacts (.joblib)
├── mechanism.py      # SHAP → enforcement switch
├── schemas.py        # Shared data contracts
├── docker-compose.yaml
├── requirements.txt
└── README.md
```

## Run

```bash
# 1. Environment
python3.12 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Dashboard
streamlit run dashboard/app.py
# Open: http://localhost:8501

# 3. Live lab (needs Docker)
docker compose up -d
python dashboard/live_lab.py --duration 120 --mode mixed
# Open: http://localhost:8080 (simple API endpoint behind the proxy)
```

## What the tabs do

| Tab | Purpose |
|-----|---------|
| **Live monitor** | Replay captured flows, see model scores and decisions per flow |
| **Live lab** | Launch real traffic, capture packets, score live, enforce nginx limits |
| **Protected site** | Simple API endpoint behind the nginx proxy (test the enforcement live) |

## Key ideas

- **No hardcoded thresholds** — detection and directive choice come from the model + SHAP
- **Per-IP enforcement** — `limit_req` and `limit_conn` apply per source IP, not globally
- **Zero false positives target** — benign traffic is never blocked intentionally