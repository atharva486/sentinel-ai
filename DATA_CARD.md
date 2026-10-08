# DATA_CARD.md — L7 DoS Detector

## Datasets

1. CIC-IDS2017 Improved (DistriNet)
   - Source: https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip
   - Days: monday.csv … friday.csv

2. CIC-DDoS2019 (Kaggle: dhoogla/cicidscollection) — secondary cross-check

## Cleaning (audit-based)

- Drop flows with Attempted Category != -1 (CNS 2022: "Attempted flows must not be treated as a separate label")
- Drop DoS Hulk (mis-implemented; needs Keep-Alive but traffic used Connection: close)
- Drop DoS GoldenEye, DDoS LOIC-HTTP (ineffective per audit)
- Keep only: Benign, DoS Slowloris, DoS Slowhttptest

## Features (20)

Split into: rate tier (8), concurrency tier (4), stall tier (6), shape (2). See features.py FEATURE_ORDER.

## Known flaws
- Hulk excluded due to implementation mismatch
- Slow attack visibility requires packet-level reconstruction (nginx logs miss unfinished flows)

## Citations
- Liu et al., IEEE CNS 2022
- Sharafaldin et al., ICISSP 2018
