# DATA_CARD.md — L7 DoS Detector

## Datasets

1. **Lab-generated traffic — PRIMARY, the training set**
   - Source: our Docker lab (`docker-compose.yaml`), captured on the proxy
   - Labels: the source container IP (`m1_capture/merge.py`), not hand-labelled
   - Features: the 20 decision-time features in `m1_capture/features.py`

2. **CIC-IDS2017 Improved — EVIDENCE, not training data**
   - Source: https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip
   - Days: monday.csv … friday.csv (kept raw — do NOT delete)
   - Used only for the read-only audit `m1_capture/dataset.py`
   - Cannot train this model: its 91 CICFlowMeter columns are completion-based
     and lack the stall/concurrency features the mechanism switch reads

3. CIC-DDoS2019 (Kaggle: dhoogla/cicidscollection) — optional secondary cross-check

## Audit findings (CIC-IDS2017, read-only)

- Only DoS Slowloris and DoS Slowhttptest actually worked — both slow attacks.
- DoS Hulk was mis-implemented (needs Keep-Alive; traffic used Connection: close).
- DoS GoldenEye and DDoS LOIC-HTTP are ineffective.
- Rows marked "- Attempted" are failed attacks and must not be a separate class.
- Label spelling is `BENIGN` (all caps); match case-insensitively, never assume.

## Features (20)

Split into: rate tier (8), concurrency tier (4), stall tier (6), shape (2). See features.py FEATURE_ORDER.

## Known flaws
- Hulk excluded due to implementation mismatch
- Slow attack visibility requires packet-level reconstruction (nginx logs miss unfinished flows)

## Citations
- Liu et al., IEEE CNS 2022
- Sharafaldin et al., ICISSP 2018
