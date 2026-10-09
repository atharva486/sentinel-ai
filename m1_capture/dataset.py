#!/usr/bin/env python3
"""dataset.py — read-only audit of the CIC-IDS2017 Improved CSVs.

WHAT THIS FILE IS FOR
---------------------
CIC-IDS2017 is the project's dataset AUDIT and a citation source. It is NOT the
training set.

The model is trained on traffic we generate ourselves in the Docker lab (see
merge.py) and label by source container IP. That is the only data whose labels
are exact and whose feature space (the 20 features in features.py) is the one
the mechanism switch reads.

CIC-IDS2017 is kept because it is the literature EVIDENCE that the project's
slow-attack focus is the right one. The CNS 2022 audit (Liu, Engelen, Lynar,
Essam & Joosen) found the only two DoS attacks that actually worked in it were
DoS Slowloris and DoS Slowhttptest — both slow. Reproduce that table here; it
goes in the report.

THIS FILE WRITES NOTHING AND FILTERS NOTHING. It reads one column and prints
counts. There is no cleaning step to get wrong, so it cannot corrupt or empty
the dataset (the previous version did exactly that: it matched "Benign" against
the real label "BENIGN" and dropped all 324,335 benign rows in Wednesday alone).
"""
from __future__ import annotations

from pathlib import Path

import pandas as pd

RAW = Path("data") / "CICIDS2017_improved"
DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]


def audit_cicids(path: str | Path = RAW, days: list[str] | None = None) -> pd.Series:
    """Return overall raw label counts across the given days.

    Reads ONLY the Label column. Fast, and it never touches the rest of a row,
    so the source CSVs cannot be mutated by running this.
    """
    p = Path(path)
    days = days or DAYS
    total: dict[str, int] = {}
    for d in days:
        csv = p / f"{d}.csv"
        if not csv.exists():
            print(f"{d:10s}: MISSING ({csv})")
            continue
        labels = pd.read_csv(csv, usecols=["Label"], low_memory=False)["Label"]
        print(f"--- {d} ({len(labels)} flows) ---")
        print(labels.value_counts().to_string())
        print()
        for k, v in labels.value_counts().items():
            total[str(k)] = total.get(str(k), 0) + int(v)
    return pd.Series(total).sort_values(ascending=False)


def main() -> None:
    if not RAW.exists():
        raise SystemExit(
            f"No raw CSVs at {RAW}.\n"
            "Download/unzip CIC-IDS2017 Improved there first. This raw data is "
            "the audit evidence and must NOT be deleted."
        )
    print("CIC-IDS2017 Improved — raw label audit (read-only)\n")
    counts = audit_cicids()
    print("=== ALL DAYS ===")
    print(counts.to_string())
    print()
    print("Audit conclusions (Liu et al., IEEE CNS 2022):")
    print("  * DoS Slowloris and DoS Slowhttptest are the only DoS attacks that")
    print("    actually exhausted the victim — both slow attacks.")
    print("  * DoS Hulk was mis-implemented: it needs Keep-Alive, but every Hulk")
    print("    flow used 'Connection: close', so it behaved like browsing.")
    print("  * Rows ending in '- Attempted' are failed attacks. The CNS 2022 paper")
    print("    is explicit: do not treat them as a separate class.")
    print()
    print("NOTE: this script produces no training data. Training data comes from")
    print("      the lab via merge.py (labels = source container IP).")


if __name__ == "__main__":
    main()
