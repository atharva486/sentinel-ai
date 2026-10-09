# L7-DoS Detector — Sentinel AI

An explainable Layer-7 DoS detection system. Uses packet-level flow reconstruction, ML scoring with SHAP, and mechanism switching (limit_conn for slow attacks, limit_req for flood attacks).

## Repository Structure
```
l7-dos-defender/
├── m1_capture/        # Module 1: capture, features, dataset, splits, merge
├── gen/               # Traffic generators (benign/slow/rudy/flood)
├── proxy/             # Nginx config + limits (written by Module 4)
├── data/              # Cleaned CIC-IDS2017 + train/val splits
├── captures/          # PCAP captures (gitignored)
├── logs/              # Nginx logs (gitignored)
├── schemas.py         # Shared data contracts (frozen)
├── mechanism.py       # SHAP -> defence switch
├── ablation.py        # Ablation harness
├── test_sensor.py     # Sensor + features tests
├── test_mechanism.py   # Mechanism switch tests
├── docker-compose.yaml
└── requirements.txt
```

## Quick Start

### 1) Clone Repository
```bash
git clone git@github.com:atharva486/sentinel-ai.git
cd l7-dos-defender
```

### 2) Create & Activate Virtual Environment

#### macOS / Linux (Ubuntu/Debian etc.)
```bash
python3 -m venv .venv
source .venv/bin/activate
```

#### Windows (PowerShell)
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

#### Windows (CMD)
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
```

### 3) Install Dependencies
```bash
pip install -r requirements.txt
```

### 4) Set Python Path (for local runs)
Module imports expect `m1_capture/` in path.

#### macOS/Linux
```bash
export PYTHONPATH=$(pwd):$(pwd)/m1_capture
```

#### Windows (PowerShell)
```powershell
$env:PYTHONPATH = "$(Get-Location);$(Get-Location)\m1_capture"
```

### 5) Verify Core Logic (No Docker needed)
```bash
python test_sensor.py
python test_mechanism.py
```

Both should output: `all 20-feature checks passed...` and `mechanism switch verified end to end`

## Dataset
- CIC-IDS2017 Improved (audited)
- Kept: Benign, DoS Slowloris, DoS Slowhttptest
- Excluded: Hulk, GoldenEye, LOIC-HTTP, Attempted flows
- Time-split: `data/train.parquet`, `data/val.parquet`

## Docker Stack (for live pcaps)
```bash
docker compose up -d
docker compose ps
```

## Module 1 Quick Check (Live)
```bash
# capture slowloris
docker compose exec proxy tcpdump -i eth0 -w /captures/test_slow.pcap -s 0 'tcp port 80' &
docker compose exec slow-gen python generate.py --mode slow --duration 30
# stop tcpdump (Ctrl+C in that shell)
# verify
PYTHONPATH=. PYTHONPATH=$PYTHONPATH:m1_capture python -c "
from m1_capture import sensor, features
from sensor import parse_http
from pathlib import Path
recs = sensor.read_pcap(Path('captures/test_slow.pcap'), flush_after=5.0)
win = features.WindowTracker()
r = recs[-1] if recs else None
if r:
  http = parse_http(bytes.fromhex(r['fwd_payload']))
  win.on_connect('e1',r['t_first'])
  f = features.build_features(r,http,win,'e1',r['t_last'])
  print(f['header_complete'], f['stall_time_s'])
"
```

Expected: `0.0 <stall_time_s> > 10` approx, `header_complete 0.0`

## Notes
- Never demo on `127.0.0.1`. Use Docker bridge network (`lab`, 172.18.0.x)
- `schemas.py` is frozen after Week 1
- nginx logs miss slow attacks; we use packet-level reconstruction
