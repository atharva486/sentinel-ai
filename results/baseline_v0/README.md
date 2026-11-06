# baseline_v0 — Pre-Phase 2 live-run baseline

Archived live-lab run before Phase 2 (connection-level, decision-time features)
work began. All files are read-only reference artifacts; future live runs write
to a NEW `reports/runs/<run_id>/` directory and never overwrite this folder.

## Files

| File | Description |
|------|-------------|
| `live_feed.jsonl` | Full decision feed from the run: 616 decision rows, 117 unique flows |
| `live_decisions_export.csv` | User's exported subset: 500 rows (rows 44–616 of the feed), ts 1793980933 → 1793981065 |
| `side_log.jsonl` | Off-the-wire per-connection labels: 113 rows (40 attack/slowloris, 73 benign) |

## Run identity

- Source: `reports/live_feed.jsonl` (captured by `dashboard/live_lab.py`)
- Side log: `reports/runs/run_1793980871/side_log.jsonl` (generator side log, off-the-wire labels)
- Feed timestamps: 1793980880.73 → 1793981065.09 (2026-11-06 21:31:20 → 21:34:25)
- Side-log timestamps: 1793980877.68 → 1793980961.66

## Commit hashes used

| Component | Commit hash |
|-----------|-------------|
| `gen/generate.py` | 2454137d2d1cbc26576b788d677733e84bb1325a |
| `m3_scoring/train_xgb.py` | ba3d8adaa4761a0d5351f05a2cf45f8346e7ebb7 |
| `m3_scoring/calibrate.py` | 4d973438be44501e7699fb78eb07bedba1e4b518 |
| `m1_capture/features.py` | b3ce12e41d8f2732e36503b98b9dddee91a1eb73 |
| `m1_capture/merge.py` | 0a977671c362058621dad3deb45b9816515ce3b7 |
| Repo branch / HEAD | `root-fix` @ 708374e5d264f353bd60849330803d5abf573b72 |

## Label source

Ground truth comes from the **side log** (off-the-wire per-connection labels
written by `gen/generate.py --side-log`), NOT from any string inside the
traffic. The old `X-Ground-Truth` header and IP-prefix fallback were removed
in Phase 1. Flows that could not be joined to the side log are marked
`truth="unmatched"` (4 flows in this feed) and excluded from per-flow metrics.

## Benign slow clients

The `benign_worker` in `gen/generate.py` (with `slow_fraction=0.15`) produces
benign slow clients: ~15% of benign connections do slow multipart uploads
(200 KB–2 MB bodies at 0.3–0.9 s drip intervals). The training data in
`data/features.parquet` predates Phase 1 and had NO such benign slow clients
(it was labelled by IP-prefix fallback with `X-Ground-Truth` headers inside
the traffic). This baseline is the first run with labels purely off the wire.

## Per-flow baseline numbers (computed from `live_feed.jsonl`)

Computed by grouping decision rows by `flow_id`; a flow is "flagged" if any
snapshot has calibrated score >= 0.30 (the model's decision threshold).
First-flag age = flow age at the first flagged snapshot. Unmatched flows
excluded.

| Metric | Value |
|--------|-------|
| Total decision rows | 616 |
| Unique flows | 117 |
| Attack flows | 40 |
| Attack flows flagged | 40 / 40 (100.0%) |
| Benign flows | 73 |
| Benign flows flagged | 61 / 73 (83.6%) |
| Unmatched flows (excluded) | 4 |
| Median age at first flag (attacks) | 12.1 s |
| p90 age at first flag (attacks) | 12.9 s |
| Attack flows with a first flag | 40 / 40 |

### Comparison with user's 500-row export analysis

The user's own analysis of `live_decisions_export.csv` (500 rows, rows 44–616
of the feed) reported approximately:
- 55 / 66 benign flows flagged (~83.3%)
- 40 / 40 attack flows flagged (100%)
- Median first-flag age ~32 s

**Attack recall matches exactly** (40/40 = 100%). **Benign flag rate matches
closely** (83.6% full feed vs 83.3% export); the count differs (61/73 vs 55/66)
because the full feed includes 7 early benign flows (rows 0–43) absent from the
export.

**Median first-flag age differs materially** (12.1 s full feed vs ~32 s export).
Likely causes: (a) the export starts at row index 44 where ages are already
high (first export row is age 31.8 s), so early flags are missing; (b) the user
may have measured "first flag" among final/completed flows only, or used a
different observation window. This baseline reports the honest full-feed number:
12.1 s median, 12.9 s p90.

## Future runs

Live runs started by `dashboard/live_lab.py` write to a fresh
`reports/runs/run_<epoch>/` directory (new `run_id` per run). This folder is
never overwritten by a subsequent run.
