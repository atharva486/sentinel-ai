#!/usr/bin/env python3
"""splits.py — chronological train/val split.

Used on the LAB-GENERATED data (merge.py output). It also works on any frame
that has a time column and a label column.

Why time, not shuffle
---------------------
Attack traffic is localised in time and near-duplicate within a capture session.
A random row split pushes near-duplicates of the same flow into both train and
val: you get ~99% accuracy and a result that means nothing. Always split by time.

Why this file is strict
-----------------------
The previous version's health check was:
    n_atk = len(part) - counts.get("Benign", 0)
The real label is "BENIGN" (all caps), so counts.get("Benign") was always 0 and
every split looked 100% attack. A one-class validation set is worthless (no
false-positive rate, no per-class recall) but nothing complained. This version
matches benign case-insensitively and refuses to return a one-class split.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


def _is_benign(labels: pd.Series) -> pd.Series:
    """Case-insensitive benign test.

    Do NOT assume a spelling. The raw CIC label is 'BENIGN'; lab labels are
    'benign'. A hard-coded 'Benign' matched neither and silently reported zero
    benign rows — the exact bug that emptied the old cleaned.csv.
    """
    s = labels.astype(str).str.strip().str.lower()
    return s.str.startswith("benign")


def time_split(
    df: pd.DataFrame,
    time_col: str = "Timestamp",
    label_col: str = "Label",
    val_frac: float = 0.2,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    if time_col not in df.columns:
        raise KeyError(f"time column {time_col!r} missing; cannot do a time split")
    if not 0.0 < val_frac < 1.0:
        raise ValueError("val_frac must be in (0, 1)")

    df = df.sort_values(time_col).reset_index(drop=True)
    cut = int(len(df) * (1 - val_frac))
    train, val = df.iloc[:cut], df.iloc[cut:]

    assert train[time_col].max() < val[time_col].min(), "TIME LEAK"

    has_labels = label_col in df.columns
    for name, part in (("train", train), ("val", val)):
        total = len(part)
        if total == 0:
            raise AssertionError(f"{name} is empty — split is broken")
        if not has_labels:
            print(f"{name}: {total} rows (no {label_col!r} column; balance unchecked)")
            continue

        counts = part[label_col].value_counts()
        benign = int(_is_benign(part[label_col]).sum())
        atk = total - benign
        print(f"{name}: {total} rows, span "
              f"{part[time_col].min()} .. {part[time_col].max()}")
        print(counts.to_string())
        print(f" -> {atk} attack rows ({atk / total:.1%}), {benign} benign")

        if atk == 0:
            raise AssertionError(f"{name} has NO ATTACKS — split is broken")
        if benign == 0:
            raise AssertionError(
                f"{name} has NO BENIGN rows — false-positive rate is unmeasurable"
            )

    return train, val


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python splits.py <features.parquet|features.csv> [val_frac]")
        print("  Splits LAB-GENERATED features (merge.py output), NOT CIC-IDS2017.")
        raise SystemExit(2)

    path = Path(sys.argv[1])
    frame = pd.read_parquet(path) if path.suffix == ".parquet" else pd.read_csv(path)
    tcol = "Timestamp" if "Timestamp" in frame.columns else "t"
    lcol = "Label" if "Label" in frame.columns else "role"
    time_split(
        frame,
        time_col=tcol,
        label_col=lcol,
        val_frac=float(sys.argv[2]) if len(sys.argv) > 2 else 0.2,
    )
