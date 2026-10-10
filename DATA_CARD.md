# DATA_CARD.md — L7 DoS Detector

## Datasets

1. **Lab-generated traffic — PRIMARY, the training set**
   - Source: our Docker lab (`docker-compose.yaml`), captured inside the proxy
     (`tcpdump`, baked into `proxy/Dockerfile`)
   - Labels: `m1_capture/merge.py` — per-flow **`X-Ground-Truth` header** embedded
     by the generator (`gen/generate.py`), so labels are exact even when one IP
     does mixed roles; source-IP mapping falls back for legacy captures.
     - Primary containers are **pinned** in `docker-compose.yaml`:
       `172.18.0.5` legit-loadgen = benign, `172.18.0.6` slow-gen = attack,
       `172.18.0.7` flood-gen = attack
     - Multi-IP captures: the generator binds **each worker to its own source IP**
       (`gen/generate.py --ip-base/--ip-count`, requires `cap_add: NET_ADMIN`).
       `role_for_ip()` labels by prefix — third octet `…5` = benign, `…6` =
       slow-gen, `…7` = flood-gen. One pool per session (15/25/35/45, 16/26/36/46,
       17/27/37/47) so sessions and IPs never overlap between classes.
       **Slowloris must SHARE a few IPs** (`--ip-count` ≪ `--slow`) so
       `concurrent_conns` carries signal (see 4c in the snapshot below).
     - **Mixed-role mode** (`gen/generate.py --mode mixed`, sessions mix1–mix3):
       one dedicated pool (55/56/57) where every IP plays a real-world profile
       (pure benign / pure attack / benign→attack / attack→benign / concurrent).
       Labels come **only** from the per-flow header — 55/56/57 are deliberately
       NOT in the prefix fallback, so no label can be invented from the IP.
       Phased profiles run their halves concurrently with a time offset and each
       phase is time-bounded, so a reset/stall in one half can never suppress the
       other (the earlier `await a; await b` form lost every benign→attack flow).
   - Generation (`gen/generate.py`): benign + attacks run **concurrently** with
     staggered connection starts, and benign agents reconnect, so both classes
     are spread across the timeline (a chronological split needs this).
     In *pure* runs an attack container emits **only** attacks (a benign flow
     from an attack container would be mislabelled by source IP); the `mixed`
     mode is the deliberate exception — it emits both from one IP and relies on
     the per-flow header for exact labels.
   - One row = one TCP connection (flow)
   - Features: the decision-time features in `m1_capture/features.py` (16 model
     features; `syn_retries`, `bytes_out_per_s`, `bytes_in_ratio` and
     `time_to_first_byte` stay in the frozen schema but are structurally
     constant on the lab network and excluded from `FEATURE_ORDER`)

2. **CIC-IDS2017 Improved — EVIDENCE, not training data**
   - Source: https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip
   - Days: monday.csv … friday.csv (kept raw — do NOT delete)
   - Used only for the read-only audit `m1_capture/dataset.py`
   - Cannot train this model: its 91 CICFlowMeter columns are completion-based
     and lack the stall/concurrency features the mechanism switch reads

3. CIC-DDoS2019 (Kaggle: dhoogla/cicidscollection) — optional secondary cross-check

## Current dataset snapshot — FINAL (`data/features.parquet`)

**Final = ONLY sessions captured in this repo with the fixed generator and the
documented protocol (2b, 3b, 4c, 6d–6h, mix1–mix3).** Everything produced by
other agents or older code is excluded below and gitignored; nothing is deleted.

- **5337 flows** = **3820 benign / 1517 attack** (no NaNs, no duplicate rows)
- Attack composition: **1198 slow-type** (slowloris + rudy, incl. complete-header
  RUDY flows trickling a huge body) + **319 HTTP flood**
- **11 capture sessions**: 8 *pure* — 2b (15/16/17), 3b (15/16/17),
  4c (45/46/47), 6d/6g (15/16/17), 6e/6h (25/26/27), 6f (35/36/37) — plus
  3 *mixed-role* — mix1 (55), mix2 (56), mix3 (57), each 100 IPs / ~380 flows
- **910 distinct source IPs** — the model must learn behaviour, not an IP.
  **168 of them are mixed-role** (do benign AND attack): the `mix*` sessions
  give each IP one of 12 real-world profiles (pure benign / pure slow·flood·rudy
  / benign→attack / attack→benign / concurrent combos). This is deliberate
  real-world coverage, **not** leakage — see below.
- Session column present (`df['session']`) → **leave-one-session-out** evaluation
- Session-level split (boundary between whole sessions, verified no session is
  cut): **train 4195** (2975 benign / 1220 attack) = the 8 pure sessions,
  **val 1142** (845 benign / 297 attack) = mix1+mix2+mix3; both classes on both
  sides. The natural chronological cut puts all mixed sessions in val, so this
  is a pure→mixed **generalisation** test (model never trains on a mixed IP).
- Class means: `header_complete` **0.39 attack vs 1.00 benign**;
  `stall_time_s` **42.3 vs 4.1**; `requests_per_s` **917 vs 1.1** (flood-driven);
  `concurrent_conns` **attack median 7 / p90 14 vs benign median 0 / p90 1**
  (>2 conns: **52.8% vs 0.1%**) — the `limit_conn` tier is live (slowloris/rudy
  share a few IPs, each bot holds many sockets; benign flows of mixed IPs barely
  raise the benign side because a browser still opens one socket at a time)
- Leakage status:
  - **labels are per-flow** (`X-Ground-Truth` header, `merge.py` `GT_ROLE`), so
    168 mixed-role entities are labelled correctly flow by flow — NOT a leak
    (the entity/IP is never a model feature; every feature is decision-time
    behavioural)
  - the mixed pools **55/56/57 are deliberately absent** from `merge.py`'s
    `BENIGN_IP_PREFIXES`/`ATTACK_IP_PREFIXES`, so a mixed flow's label can only
    come from its header — it can never be invented from the source IP
  - for the 8 *pure* sessions: source-IP pools ↔ labels 100% pure (benign only
    from `…5` pools, attack only from `…6`/`…7` pools — per-pool table in
    `dataset_report.py` output)
  - features are decision-time only (`features.py` NO LEAKAGE RULE)
  - slowloris headers never terminate (`header_complete=0`); RUDY flows have a
    complete header but a stalled body — both stay in the stall tier
  - CIC-IDS2017 audited only, never trained on

### Sources deliberately EXCLUDED from the final set (kept on disk, gitignored)
1. **Other-agent captures** (`features_campaign_v1_flat_ips.parquet`,
   `features_sA/sB/sC.parquet`, created 10 Oct 11:07–11:35 by another agent) —
   provenance unverifiable: generator code version, capture filter, aliases and
   merge code are unknown. `campaign_v1` is **3 sub-runs glued into one file**
   (two >20 s time-gaps; 9 source-IP pools in one "session"), which breaks
   leave-one-session-out. sA/sB/sC ran only ~54 s. Excluded and gitignored.
2. **run2 / run3 backups** (`features_run2_backup.parquet`,
   `features_run3_backup.parquet`) — old generator (pre-slowloris-fix) produced
   completed headers + `stall≈0`; attack rows looked benign. Poison.
3. A **196-row diagnostic block** (benign flows at ~4400 req/s, entities in the
   benign pool labelled attack) that leaked in from a stale `features.parquet`
   during one combine. Poison.
4. **run5** (`features_run5_backup.parquet`, 672 flows) — verified code but its
   single pinned IP per class aggregates all workers into one entity per class,
   which INVERTS `concurrent_conns` (benign 31 vs attack 26 in that run). It is
   backup-only; the final set uses per-worker IPs throughout.

### Historical snapshots (superseded)
- Run 5 (672 flows = 332 benign / 340 attack) — see exclusion note above; kept
  at `data/features_run5_backup.parquet`
- Run 4 (473 flows = 260 benign / 213 attack) — kept at
  `data/features_run4_final_backup.parquet`

## Audit findings (CIC-IDS2017, read-only)

- Only DoS Slowloris and DoS Slowhttptest actually worked — both slow attacks.
- DoS Hulk was mis-implemented (needs Keep-Alive; traffic used Connection: close).
- DoS GoldenEye and DDoS LOIC-HTTP are ineffective.
- Rows marked "- Attempted" are failed attacks and must not be a separate class.
- Label spelling is `BENIGN` (all caps); match case-insensitively, never assume.

## Features (16 model features)

Split into: rate tier (7), concurrency tier (4), stall tier (5).
See features.py FEATURE_ORDER. `syn_retries`, `bytes_out_per_s`,
`bytes_in_ratio` and `time_to_first_byte` (frozen schema fields) are
structurally constant on the emulated lab network and are deliberately NOT in
FEATURE_ORDER — they carried no signal, and their only non-constant values in
this repo came from captures made by another agent with an unknown sensor
variant (excluded, see above).

Concurrency (`concurrent_conns`, `conns_per_second_opened`) is computed from
connection **intervals** that contain the decision time. It must never be
computed as opens-minus-closes events: `sensor.py` stamps every flow with a
`t_close`, so an events version nets to exactly 0 for every row and the whole
concurrency tier dies. That was a real bug, fixed in `features.WindowTracker` —
verify after any change that `concurrent_conns` is non-zero for slow attacks.

## Known flaws
- Hulk excluded due to implementation mismatch
- Slow attack visibility requires packet-level reconstruction (nginx logs miss unfinished flows)
- One row = one TCP connection, so the benign:attack ratio reflects connection
  shapes, not request volume. Production benign:slow is ~283:1 (CIC audit); the
  lab capture is far more attack-heavy on purpose, to give the model positives.
- Train/val is a **session-level chronological** split: the boundary always
  falls between whole capture sessions (see `splits.py session_time_split`),
  so no session straddles the cut and **leave-one-session-out** is valid. A
  near-duplicate cross-session check is not needed: session source-IP pools are
  disjoint and the sensor keys on (src ip, src port, dst) connections.
  For the 8 *pure* sessions `dataset_report.py` verifies per-pool label purity on
  every run; the mixed pools 55/56/57 are intentionally impure (all roles) and
  are labelled per flow, not per pool.
- The natural chronological split puts the 3 mixed sessions (captured last) all
  in **val**, so the model trains only on pure-IP sessions and is tested on
  mixed-IP sessions. This is a deliberate pure→mixed generalisation test. If a
  future run needs mixed IPs in training, capture additional mixed sessions so
  the boundary falls *inside* the mixed block (or swap a mixed session for a
  pure one at capture time).
- Flood dominates capture size (hundreds of MB for seconds of traffic); the
  capture filter is limited to generator hosts to drop proxy->backend traffic.
- Per-entity features need source-IP diversity: with one container IP per whole
  class, all benign agents collapse into one entity and `concurrent_conns` stops
  separating (observed in run 5: attack 25 vs benign 29 — that run is excluded
  from the final set). Fixed by per-worker source IPs PLUS slowloris sharing a
  few IPs (session 4c: 100 workers over 10 IPs → attack `concurrent_conns`
  median 10 vs benign 0); validate with leave-one-session-out across all 11
  final sessions.

## Citations
- Liu et al., IEEE CNS 2022
- Sharafaldin et al., ICISSP 2018
