# L7-DoS Detector — Sentinel AI

An explainable Layer-7 DoS detection system: packet-level flow reconstruction,
ML scoring with SHAP, and mechanism switching (`limit_conn` for slow attacks,
`limit_req` for flood attacks).

> **Status:** Module 1 (capture + features) is complete — the final training set
> (`data/features.parquet`, 11 sessions, pure + mixed-role IPs, session-level
> split) is ready. The model is
> **not trained yet** — that is Module 3. Commands below are written to be
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
│   ├── features.py        #   flow records -> the 16 decision-time features (FEATURE_ORDER)
│   ├── merge.py           #   flows.jsonl -> labelled frame (per-flow X-Ground-Truth header, IP fallback)
│   ├── splits.py          #   session-level chronological split (refuses a one-class split)
│   └── dataset_report.py  #   one-command dataset health check (balance / separation / leaks)
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
- `all 16-feature checks passed across 5 traffic shapes`
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
- **Final set: `data/features.parquet` = 5337 flows** (3820 benign / 1517 attack
  = 1198 slow-type + 319 flood), **11 capture sessions** = the 8 pure sessions
  (2b, 3b, 4c, 6d–6h) **plus 3 MIXED-role sessions** (mix1–mix3),
  **910 source IPs** — all captured in-repo with the documented protocol
- **Mixed-role IPs (real-world):** the 3 `mix*` sessions give each source IP a
  real-world profile — pure benign ("innocent user"), pure attack, benign→attack,
  attack→benign, or benign+attack at the same time. **168 source IPs do more
  than one role.** This is deliberate: the model must label each flow from its
  *behaviour at that moment*, not from the IP. It is not leakage — labels stay
  **per-flow** (next bullet) and the IP is never a feature.
- Labels: per-flow `X-Ground-Truth` header embedded by the generator
  (`merge.py`) — exact **per flow even when one IP does mixed roles**; the
  `mix*` pools are deliberately absent from `merge.py`'s IP-prefix fallback so
  their labels can only come from the header. IP prefixes fall back only for the
  legacy pure captures.
- Features: the 16 decision-time features in `features.py` (frozen-schema
  fields `syn_retries`, `bytes_out_per_s`, `bytes_in_ratio` and
  `time_to_first_byte` are structurally constant on the lab and excluded)
- Split: **session-level** chronological via `splits.py` (boundary falls between
  whole sessions; never shuffles). `session` column enables leave-one-session-out.
  Natural cut = **train 4195** (2975 benign / 1220 attack) = the 8 pure sessions;
  **val 1142** (845 benign / 297 attack) = mix1+mix2+mix3. Val is therefore a
  pure→mixed **generalisation** test (the model never trains on a mixed IP).
- Health check after any regen: `python m1_capture/dataset_report.py`

> **Provenance rule.** Only in-repo captures are in the final set. Parquet files
> produced by other agents (`features_campaign_v1_flat_ips`, `features_sA/B/C`)
> are **gitignored and excluded** — their generator code version, capture filter
> and merge code cannot be verified (`campaign_v1` is three sub-runs glued into
> one "session", which breaks leave-one-session-out). See DATA_CARD.

> **Do M2/M3/M4 need Docker? No.** The lab (Docker + Compose) is only needed to
> *regenerate captures* (Module 1). Everyone else just needs Python 3.12,
> `requirements.txt`, and `data/features.parquet` (+ `splits.py` /
> `dataset_report.py`). Nothing in the model / mechanism / report code touches
> Docker.

Raw captures are deleted after processing; only the feature parquets are kept
(they are the ground truth for this project). CIC-IDS2017 stays raw on disk as
audit evidence (`m1_capture/dataset.py`).

**CIC-IDS2017 Improved is evidence, not training data.**
- Kept raw on disk for the dataset audit: `python m1_capture/dataset.py`
- It justifies the slow-attack focus: in the CNS 2022 audit, the only two DoS
  attacks that actually worked were DoS Slowloris and DoS Slowhttptest.
- Its 91 CICFlowMeter columns are completion-based and do **not** contain the
  decision-time features in `features.py`, so it cannot train this model.

Pipeline (once a capture exists):

```
capture on the proxy (tcpdump is baked into the proxy image)
        │
        ▼
python m1_capture/sensor.py cap.pcap -o flows.jsonl
        │
        ▼
label with merge.py  ->  data/features.parquet
        │
        ▼
python m1_capture/splits.py data/features.parquet
        │
        ▼
   (training — Module 3, not built yet)
```

### Build the dataset — capture recipe

With the lab up (`docker compose up -d --build`), from the repo root:

```bash
# 0) (optional, recommended) give each generator a POOL of source IPs so that
#    ONE WORKER = ONE CLIENT IP. Without this, all workers of one container
#    collapse into a single entity and per-entity features (concurrency) get
#    confounded. Needs cap_add: [NET_ADMIN] on the generator services — already
#    in docker-compose.yaml.
docker exec slow-gen sh -c 'for i in $(seq 1 60); do ip addr add 172.18.16.$i/16 dev eth0; done'
#    (legit-loadgen -> 172.18.15.x, flood-gen -> 172.18.17.x for the same run)

# 1) start a capture inside the proxy (detached). Filter = generator SUBNETS ONLY
#    and dst = proxy, so proxy->backend traffic is NEVER captured (that was the
#    run-6 failure: 27k proxy->backend flows swept in by a plain `port 80`).
#    Use the current session's pool octets (15/16/17 for run A, 25/26/27 run B,
#    35/36/37 run C, 45/46/47 run D, ...) and keep dst 172.18.0.2 on every pool.
#    NOTE: `and` binds tighter than `or`, so the whole subnet group MUST be in
#    parentheses — without them only the LAST /24 gets the dst restriction.
docker exec -d proxy tcpdump -i eth0 -w /captures/runA.pcap -s 0 \
    "(src net 172.18.15.0/24 or src net 172.18.25.0/24 or src net 172.18.35.0/24 or src net 172.18.45.0/24 \
      or src net 172.18.16.0/24 or src net 172.18.26.0/24 or src net 172.18.36.0/24 or src net 172.18.46.0/24 \
      or src net 172.18.17.0/24 or src net 172.18.27.0/24 or src net 172.18.37.0/24 or src net 172.18.47.0/24) \
     and dst 172.18.0.2"

# 2) launch benign + all three attacks CONCURRENTLY. Generators connect at
#    staggered times and benign agents reconnect, so both classes are spread
#    across the timeline — required for a chronological split to be valid.
#    Each worker binds its own source IP (--ip-base + --ip-count). Rule:
#      benign  -> 1 IP per agent (--ip-count >= --benign)
#      slow    -> FEW IPs, MANY workers (--ip-count <= --slow/10): a real bot
#                 holds many sockets from a few IPs. Without this, every slow
#                 entity has exactly 1 connection and concurrent_conns dies —
#                 the concurrency tier that justifies limit_conn (see session 4c).
#      flood   -> 1 IP per keep-alive connection (rate attack; no concurrency need)
#      pcap size: pass --req-per-conn 50 to the flood. A paced 50-req burst is
#                 still >100x the benign request rate, while the unpaced default
#                 (200 reqs/burst, no pacing) runs at TCP-drain speed and a
#                 150 s session writes >3 GB of pcap. Paced, it is a few hundred MB.
docker exec -d legit-loadgen python generate.py --mode benign --benign 100 --duration 150 --ip-base 172.18.15 --ip-count 100 --label runA
docker exec -d slow-gen      python generate.py --mode slow   --slow 100  --duration 150 --ip-base 172.18.16 --ip-count 10 --label runA
docker exec -d slow-gen      python generate.py --mode rudy   --rudy 40   --duration 150 --ip-base 172.18.16 --ip-count 10 --label runA
docker exec -d flood-gen     python generate.py --mode flood  --flood 20  --duration 150 --ip-base 172.18.17 --ip-count 40 --req-per-conn 50 --label runA

sleep 124

# 3) stop the capture cleanly (SIGINT lets tcpdump flush the file)
docker exec proxy kill -INT "$(docker exec proxy pidof tcpdump)"

# 4) pcap -> flows -> labelled features -> chronological split
#    (with --req-per-conn 50 the pcap is a few hundred MB per session; delete
#     it + the jsonl right after merging — network data is huge, features are 60 KB)
python m1_capture/sensor.py captures/run1.pcap -o flows.jsonl
PYTHONPATH=m1_capture python -c "from merge import label_generated; label_generated('flows.jsonl').to_parquet('data/features_runX.parquet')"
python m1_capture/splits.py data/features.parquet
```
> then combine sessions into `data/features.parquet` with a `session` column
> (see the combine block in the repo history / DATA_CARD).

> **Source-IP pools and labels.** Each *pure* capture session uses its own pool:
> rotate the third octet per session (run 1 → `15/16/17`, run 2 → `25/26/27`,
> run 3 → `35/36/37`, run 4 → `45/46/47`, …). Labeling is **per-flow first**:
> the generator embeds `X-Ground-Truth: benign|slow|rudy|flood` in every request
> (`gen/generate.py`), and `merge.py` uses it before falling back to
> `role_for_ip()` (third octet `…5` = benign, `…6` = slow-gen, `…7` = flood-gen,
> plus the pinned `172.18.0.5/6/7`). Never reuse a pool for a different class in
> a *pure* run. Pool octet == role is verified by `dataset_report.py` on every
> regeneration. **Mixed sessions (pools 55/56/57) are the exception:** one pool
> carries all roles on purpose, labels come only from the per-flow header, and
> those pools are deliberately kept out of the prefix fallback.
>
> **Slowloris concurrency recipe.** Slowloris workers must SHARE a few IPs
> (`--ip-count ≤ --slow/10`) so `concurrent_conns` separates — session 4c
> (100 workers / 10 IPs) gives attack median 10 vs benign 0. A run that gives
> every slow worker its own IP (1 conn/IP) leaves the `limit_conn` tier dead.
```

> **Why concurrent:** benign agents reconnect and every worker starts at a
> staggered time, so benign and attack flows are interleaved along the timeline.
> If you run benign first and the attacks afterwards, every benign flow sits at
> the start of the capture and a chronological split leaves the validation set
> with **no benign rows** — `splits.py` rejects that on purpose.

> **Only `legit-loadgen` may send benign traffic — except in `mixed` mode.**
> Labels come from the generator's `X-Ground-Truth` header (plus source-IP
> fallback), so a benign flow sent from an attack container in a *pure* run
> would still be recorded as an attack. That is why `--mode slow/rudy/flood`
> spawn zero benign workers — run `legit-loadgen` alongside them for concurrent,
> correctly-labelled benign load. **Mixed mode is the exception:** it deliberately
> emits benign AND attack from the same IP and relies on the per-flow header, so
> each flow is still labelled exactly (see below).

### Mixed-role sessions (`mix*`) — real-world IPs

Real hosts do not stay in one lane. `--mode mixed` gives every source IP one of
12 profiles (`MIXED_PROFILES` in `gen/generate.py`): pure benign, pure slow /
flood / rudy, **benign→attack** and **attack→benign** (the same IP switches
mid-run), and concurrent combinations (benign while holding slowloris sockets,
slow+flood). Phased profiles run their two halves **concurrently with a time
offset** (phase B scheduled at `duration/2`) and every phase is time-bounded, so
a reset or stall in one half can never stop the other — sequencing them with
`await a; await b` silently lost every benign→attack example (phase A resumed a
reset, so phase B never ran).

```bash
# one dedicated pool per mixed session, e.g. 172.18.55.1-100, .56.1-100, .57.1-100
docker exec flood_gen sh -c 'for i in $(seq 1 100); do ip addr add 172.18.55.$i/16 dev eth0; done'
docker exec -d proxy tcpdump -i eth0 -w /captures/mix1.pcap -s 0 \
    "src net 172.18.55.0/24 and dst 172.18.0.2"
docker exec -d flood_gen python generate.py --mode mixed --mixed 100 --duration 150 \
    --ip-base 172.18.55 --ip-count 100 --req-per-conn 50 --label mix1
# then sensor.py -> merge.label_generated -> data/featuresmix1.parquet as usual
```
> The mixed pools (55/56/57) are intentionally **not** listed in
> `merge.py`'s `BENIGN_IP_PREFIXES`/`ATTACK_IP_PREFIXES`: their labels must come
> from the per-flow header, so a label can never be invented from the IP.

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
docker compose up -d --build      # --build: proxy (nginx+tcpdump) and the 3 generators are built images
docker compose ps
```
`docker-compose.yaml` **pins every container IP**. This is deliberate: a flow is
labelled by its source IP (`merge.py`), so `proxy`/`backend` must never take an
address that belongs to a generator. Do not remove the `ipv4_address` lines.

### Module 1 live check
```bash
# 1) capture slow traffic on the proxy (detached; tcpdump is baked into the image)
docker exec -d proxy tcpdump -i eth0 -w /captures/test_slow.pcap -s 0 port 80
# 2) hammer with slowloris for 30 s
docker compose exec -T slow-gen python generate.py --mode slow --duration 30
# 3) stop tcpdump cleanly
docker exec proxy kill -INT "$(docker exec proxy pidof tcpdump)"

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
  The final lab set is deliberately attack-heavy (1517 attack / 3820 benign rows)
  so the model has positives; when the owner builds the trainer they should
  still weight classes (or subsample) and report per-class recall + FPR.
- **No trained model / real SHAP.** `mechanism.py` currently runs on hand-assigned
  *fixture* scores, not a model.
- **Missing module folders** (`m2_triggers/`, `m3_scoring/`, `m4_decide/`,
  `m5_sandbox/`, `results/`) — left for their owners to create.
- **Container IPs are pinned** in `docker-compose.yaml` and mirrored in
  `merge.py`'s `CONTAINER_ROLE`. If the two ever disagree, flows are silently
  dropped (unlabelled), so change them together.
- **Dataset is final for M2–M4.** `data/features.parquet` has a `session`
  column (leave-one-session-out), 16 model features (FEATURE_ORDER), and a
  session-level split. Regenerate a new session only if a feature change makes
  it necessary — then re-run `m1_capture/dataset_report.py`.

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
