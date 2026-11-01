# Module 1 — L7 DoS Detector — Baseline Dataset

**Status:** Complete and verified. The files are present in the working tree but
**not yet committed** — the repository owner commits and pushes them. The dataset
was captured on 12 Oct 2026; this summary was reconciled against the shipped code
and data on 27 Oct 2026.

---

## 1. What was built

### Dataset: `data/features.parquet`
- **5,337 rows × 21 columns** = the 16 decision-time features in `FEATURE_ORDER`
  plus `entity`, `role`, `t`, `y`, `session`
- **3,820 benign / 1,517 attack**. Attack composition from the capture provenance
  is **1,198 slow-type** (slowloris + RUDY) and **319 HTTP flood**; `attack_type`
  is not a dataset column and is never a model input
- **11 capture sessions**: 8 pure (2b, 3b, 4c, 6d–6h) + 3 mixed-role (mix1–mix3)
- **910 distinct source IPs**, of which **168 are mixed-role** (benign and attack
  from the same IP)
- **0 NaN, 0 duplicate rows**; `y == (role == "attack")` holds everywhere
- Feature tiers: **rate 7 / concurrency 4 / stall 5 = 16** (`m1_capture/features.py`)

### Capture protocol (in-repo, reproducible)
- Generator: `gen/generate.py --mode mixed` (12 profiles, per-IP source binding via `--ip-base/--ip-count`)
- tcpdump filter: `src net <pool> and dst 172.18.0.2`
- Sensor: `m1_capture/sensor.py` — parses `X-Ground-Truth` header per flow
- Merge: `m1_capture/merge.py` — GT-first, IP-prefix fallback (mixed pools 55/56/57 are deliberately absent from the prefix fallback)
- Split: `m1_capture/splits.py` — session-level chronological split; every boundary falls between whole sessions

### Key code changes
| File | Change |
|---|---|
| `m1_capture/sensor.py` | Fixed `parse_http`: removed `break` at `Content-Length` so GT is never silently lost — essential for mixed-role labels |
| `gen/generate.py` | Added `--mode mixed` with 12 `MIXED_PROFILES`; phased profiles run halves concurrently with time offset + per-phase timeouts so a reset/stall in one half can't suppress the other |
| `m1_capture/merge.py` | Mixed pools (55/56/57) deliberately absent from `BENIGN_IP_PREFIXES`/`ATTACK_IP_PREFIXES` so labels can only come from the header |
| `m1_capture/dataset_report.py` | New health-check script (run: `python m1_capture/dataset_report.py`) |
| `README.md` + `DATA_CARD.md` | Updated with new counts, mixed-role description, split info, and pool/label notes |

### Verification (re-run 27 Oct 2026)
- `python test_sensor.py` → `all 16-feature checks passed across 5 traffic shapes`
- `python test_mechanism.py` → `mechanism switch verified end to end`
- `python -m pytest -q` → **53 passed** (1 sklearn pickle-version warning — see caveat)
- `python m1_capture/dataset_report.py` → `REPORT DONE`; no dead features; both classes on both sides of the split
- Direct frame checks → shape **(5,337 × 21)**; 0 NaN; 0 duplicate rows; `y == (role == "attack")`; **910 entities / 168 mixed-role**
- Concurrency separates strongly: attack **median 7 / p90 14** vs benign **median 0 / p90 1**; >2 conns **52.8% vs 0.08%** (`dataset_report` rounds the benign side to 0.1%)
- Footprint: repo ≈ **2.9 GB** (1.0 GB venv + 1.1 GB data + 339 MB logs + 409 MB captures); `logs/` and `captures/` are gitignored. Under the 30 GB project ceiling

### Split details
Two whole-session views — both leave every session intact:

**1. Module 3's three-way split (used by the shipped model)**

| Partition | Sessions | Rows | Benign | Attack |
|---|---|---:|---:|---:|
| Model training | 2b, 3b, 4c | 1,328 | 908 | 420 |
| Calibration | 6d, 6e, 6f, 6g, 6h | 2,867 | 2,067 | 800 |
| Validation (untouched) | mix1, mix2, mix3 | 1,142 | 845 | 297 |

**2. `m1_capture/splits.py` default two-way boundary**

- **train:** 4,195 rows = 8 pure sessions (2,975 benign / 1,220 attack)
- **val:** 1,142 rows = 3 mixed sessions (845 benign / 297 attack)

The model split is a **pure → mixed generalisation test** — the model never trains
on a mixed-role IP.

### Known flaws / caveats
- Hulk excluded due to implementation mismatch
- Slow attack visibility requires packet-level reconstruction (nginx logs miss unfinished flows)
- One row = one TCP connection; benign:attack ratio reflects connection shapes, not request volume
- Per-entity features need source-IP diversity; fixed by per-worker IPs + slowloris sharing a few IPs
- The natural chronological split puts all mixed sessions in **val**; if mixed IPs are needed in training, capture additional mixed sessions so the boundary falls inside the mixed block
- **Reproducibility caveat:** the joblib artifact was pickled with scikit-learn **1.7.0**, while `requirements.txt` pins **1.9.1**. Loading emits `InconsistentVersionWarning`. Re-pickle with 1.9.1 (or pin 1.7.0) before claiming bit-exact reproduction

### Handoff state
- **Module 1 is finished**; no re-capture is needed unless a feature change necessitates it
- Downstream code built on this dataset: `m2_triggers/` (triggers), `m3_scoring/` (train/calibrate/SHAP), root `mechanism.py` (decision + `apply_profile_guard`), `m5_sandbox/` (replay/feedback/adversarial), and `dashboard/` (7-tab UI). There is **no** `m4_decide/` directory — the decision layer lives in `mechanism.py`
- **Not committed as of 27 Oct 2026:** the final working-tree changes are
  uncommitted. The repository owner commits them on the final branch

---
*Dataset captured 12 Oct 2026. Reconciled against the shipped code and parquet on 27 Oct 2026.*
