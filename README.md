# L7-DoS Detector — Sentinel AI

An explainable Layer-7 DoS detection system: packet-level flow reconstruction,
ML scoring with SHAP, and mechanism switching (`limit_conn` for slow attacks,
`limit_req` for flood attacks).

> **Status:** Module 1 (capture + features) is the working baseline. The model is
> **not trained yet** — see [Data](#data). Commands below are written to be
> copy-paste exact for **macOS, Linux and Windows**.

---

## 1. Requirements (read this first)

| Tool | Exact version | Why it matters |
|---|---|---|
| **Python** | **3.12.13** (any **3.12.x**) | `shap==0.52.0` requires **Python ≥ 3.12**. 3.9 / 3.10 / 3.11 **fail** at `pip install`. |
| pip | bundled with 3.12 | — |
| Git | any recent | to clone |
| Docker + Compose v2 | current | **only** for the live lab (section 7) |

> ⚠️ **Never use a bare `python3` without checking it.**
> A fresh macOS ships ~3.9 and Ubuntu 22.04 ships 3.10 — both are too old and
> `pip install shap` will fail. Always create the venv with **`python3.12`**.

---

## 2. Repository structure

```
l7-dos-defender/
├── m1_capture/            # Module 1 — capture & features
│   ├── sensor.py          #   pcap -> raw flow records (JSONL, CLI)
│   ├── features.py        #   flow records -> the 20 decision-time features
│   ├── merge.py           #   flows.jsonl -> labelled frame (label = source container IP)
│   ├── splits.py          #   chronological split (refuses a one-class split)
│   └── dataset.py         #   read-only CIC-IDS2017 audit (evidence only)
├── gen/                   # Traffic generators (benign / slow / rudy / flood)
├── proxy/                 # Nginx config + limits (Module 4 writes the limits)
├── data/                  # Raw CIC-IDS2017 (audit evidence); lab captures (gitignored)
├── captures/              # PCAP captures (gitignored)
├── logs/                  # Nginx logs (gitignored)
├── schemas.py             # Shared data contracts (FROZEN after week 1)
├── mechanism.py           # SHAP -> enforcement switch
├── ablation.py            # 5-policy comparison harness
├── test_sensor.py         # sensor + features tests
├── test_mechanism.py      # switch / hysteresis tests
├── docker-compose.yaml
├── requirements.txt
├── DATA_CARD.md
├── AUTHORISATION.md
└── README.md
```

---

## 3. Install Python 3.12

Pick **your** operating system. Do only one.

### 3a. macOS (Homebrew)
```bash
brew install python@3.12
python3.12 --version          # expect: Python 3.12.x
```
No Homebrew? Install it first (`/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`),
or download the installer from <https://www.python.org/downloads/release/python-31213/>
(which provides the `python3.12` command).

### 3b. Ubuntu 22.04 / Debian (deadsnakes PPA)
```bash
sudo apt update
sudo apt install -y software-properties-common
sudo add-apt-repository -y ppa:deadsnakes/ppa
sudo apt update
sudo apt install -y python3.12 python3.12-venv python3.12-dev
python3.12 --version          # expect: Python 3.12.x
```
Other Linux (Fedora/Arch/…): install Python 3.12 with your package manager, or
via [pyenv](https://github.com/pyenv/pyenv) (`pyenv install 3.12.13`).

### 3c. Windows
Download **Python 3.12.13** from <https://www.python.org/downloads/release/python-31213/>,
tick **“Add python.exe to PATH”** during install, then in a **new** terminal:
```powershell
python --version              # expect: Python 3.12.x
```

---

## 4. Clone the repository

```bash
git clone git@github.com:atharva486/sentinel-ai.git l7-dos-defender
cd l7-dos-defender
```

The trailing `l7-dos-defender` **names the folder** — without it you would get a
folder called `sentinel-ai` and the `cd` would fail.

No SSH key set up? Use HTTPS instead:
```bash
git clone https://github.com/atharva486/sentinel-ai.git l7-dos-defender
cd l7-dos-defender
```

---

## 5. Create and activate the virtual environment

Use **`python3.12`** (not `python3`).

### macOS / Linux
```bash
python3.12 -m venv .venv
source .venv/bin/activate
python --version              # MUST print 3.12.x — stop here if it does not
```

### Windows — PowerShell
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version              # MUST print 3.12.x
```
If PowerShell blocks the script, run once:
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Windows — CMD
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
python --version
```

> You must **activate the venv in every new terminal** before running anything
> (you will see `(.venv)` at the start of the prompt).

---

## 6. Install dependencies

Always upgrade pip first, inside the activated venv.

### macOS
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Linux
```bash
python -m pip install --upgrade pip
# Install xgboost with NO dependency resolution, so pip does not download the
# 351 MB nvidia-nccl-cu13 CUDA package (there is no GPU on these machines).
pip install --no-deps xgboost==3.4.1
pip install -r requirements.txt
```
If you skip the special step, plain `pip install -r requirements.txt` **still works**
on Linux — it just downloads ~351 MB of CUDA files you will never use. Either way
is correct; the two-line version above is just leaner.

### Windows
```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

> **Expected Linux warning** (harmless): `xgboost 3.4.1 requires
> nvidia-nccl-cu13, which is not installed`. That is fine — no GPU.

---

## 7. Set `PYTHONPATH` (every new terminal)

The tests import modules from `m1_capture/`, so that folder must be on the path.

### macOS / Linux
```bash
export PYTHONPATH="$PWD:$PWD/m1_capture"
```

### Windows — PowerShell
```powershell
$env:PYTHONPATH = "$(Get-Location);$(Get-Location)\m1_capture"
```

### Windows — CMD
```cmd
set PYTHONPATH=%CD%;%CD%\m1_capture
```

---

## 8. Verify the core logic (no Docker needed)

Run **from the repository root** (`l7-dos-defender/`):

```bash
python test_sensor.py
python test_mechanism.py
```

Expected last line of each:
- `all 20-feature checks passed across 5 traffic shapes`
- `mechanism switch verified end to end`

Optional — reproduce the CIC-IDS2017 audit table (read-only, writes nothing):
```bash
python m1_capture/dataset.py
```

If both tests pass, your baseline works. **The model is not trained yet** — that is
Module 3's job (section 10).

---

## Data

**Training data is generated, not downloaded.**
- Source: traffic from our own Docker lab, captured on the proxy
- Labels: the source container IP (`merge.py`) — objective, exact, no hand-labelling
- Features: the 20 decision-time features in `features.py`
- Split: chronological via `splits.py` (never shuffled)

**CIC-IDS2017 Improved is evidence, not training data.**
- Kept raw on disk for the dataset audit: `python m1_capture/dataset.py`
- It justifies the slow-attack focus: in the CNS 2022 audit, the only two DoS
  attacks that actually worked were DoS Slowloris and DoS Slowhttptest.
- Its 91 CICFlowMeter columns are completion-based and do **not** contain the
  20 decision-time features, so it cannot train this model.

Pipeline (once a capture exists):

```
tcpdump -w cap.pcap 'tcp port 80'
        │
        ▼
python m1_capture/sensor.py cap.pcap -o flows.jsonl
        │
        ▼
python -c "from merge import label_generated; label_generated('flows.jsonl').to_parquet('data/features.parquet')"
        │
        ▼
python m1_capture/splits.py data/features.parquet
        │
        ▼
   (training — Module 3, not built yet)
```

---

## 9. The live lab (needs Docker + Compose v2)

### Install Docker
- **Linux (Ubuntu/Debian):**
  ```bash
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
  # log out and back in (or run: newgrp docker) so the group takes effect
  docker compose version        # expect: Docker Compose version v2.x
  ```
  (Alternative: `sudo apt install -y docker.io` — but on Ubuntu 22.04 that may
  give Compose v1, so prefer the command above.)
- **macOS:** install **Docker Desktop** from <https://www.docker.com/products/docker-desktop/>
  and launch it once. Verify: `docker compose version`.

### Run the stack
```bash
docker compose up -d
docker compose ps
```

### Module 1 live check
```bash
# 1) capture slow traffic on the proxy (background)
docker compose exec proxy tcpdump -i eth0 -w /captures/test_slow.pcap -s 0 'tcp port 80' &
# 2) hammer with slowloris for 30 s
docker compose exec slow-gen python generate.py --mode slow --duration 30
# 3) stop tcpdump (Ctrl+C, or: kill %1)

# 4) turn the pcap into flow records, then check the slow signature
python m1_capture/sensor.py captures/test_slow.pcap -o flows.jsonl
python -c "
from sensor import parse_http
from features import WindowTracker, build_features
from pathlib import Path
import json
r = json.loads(open('flows.jsonl').readline())
http = parse_http(bytes.fromhex(r['fwd_payload']))
win = WindowTracker(); win.on_connect('e1', r['t_first'])
f = build_features(r, http, win, 'e1', r['t_last'])
print('header_complete =', f['header_complete'], '| stall_time_s =', f['stall_time_s'])
"
```
Expected: `header_complete = 0.0` and `stall_time_s` greater than ~10.

---

## 10. What is NOT built yet (so nobody is surprised)

- **No trainer.** There is no `fit()` anywhere in the repo. Training is Module 3.
  When that owner builds it, they must handle the ~**283:1** benign:attack
  imbalance (`scale_pos_weight` / class weights), or the model just predicts "benign".
- **No trained model / real SHAP.** `mechanism.py` currently runs on hand-assigned
  *fixture* scores, not a model.
- **Missing module folders** (`m2_triggers/`, `m3_scoring/`, `m4_decide/`,
  `m5_sandbox/`, `results/`) — left for their owners to create.
- **`merge.py` has placeholder container IPs** — update `CONTAINER_ROLE` after the
  first real capture, or nothing gets labelled.
- **Leakage guards still to add:** split by *session* (not only by time) and a
  near-duplicate check, per the manual.

---

## 11. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `pip` cannot find a compatible `shap` | Wrong Python (< 3.12) | Recreate the venv with `python3.12` (section 5) |
| `ModuleNotFoundError: No module named 'sensor'` | `PYTHONPATH` not set | Run section 7, then rerun |
| `cd: no such file or directory: l7-dos-defender` | Clone omitted the folder name | Re-clone with the trailing `l7-dos-defender` (section 4) |
| `docker: command not found` / `docker compose` missing | Docker / Compose v2 not installed | Section 9 |
| Tests pass but nothing else runs | Expected — only Module 1 exists | See section 10 |

---

## Notes
- Never demo on `127.0.0.1`. Use the Docker bridge network (`lab`, `172.18.0.x`).
- `schemas.py` is frozen after Week 1 — agree changes with the whole team first.
- Nginx logs miss slow attacks; we use packet-level reconstruction on purpose.
