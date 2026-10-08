from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd


def time_split(df: pd.DataFrame, val_frac: float = 0.2) -> tuple[pd.DataFrame, pd.DataFrame]:
    if "Timestamp" not in df.columns:
        raise KeyError("Timestamp column missing; cannot do time split")

    df = df.sort_values("Timestamp").reset_index(drop=True)
    cut = int(len(df) * (1 - val_frac))
    train, val = df.iloc[:cut], df.iloc[cut:]

    assert train["Timestamp"].max() < val["Timestamp"].min(), "TIME LEAK"

    for name, part in (("train", train), ("val", val)):
        counts = part["Label"].value_counts()
        total = len(part)
        atk = total - counts.get("Benign", 0)
        print(f"{name}: {total} rows, span {part['Timestamp'].min()} .. {part['Timestamp'].max()}")
        print(counts.to_string())
        print(f" -> {atk} attack rows ({atk / max(1, total):.1%})")
        assert atk > 0, f"{name} has NO ATTACKS — split is broken"

    return train, val


if __name__ == "__main__":
    p = Path("data/cleaned.csv")
    if not p.exists():
        print("Run dataset.py first to produce data/cleaned.csv")
        sys.exit(1)
    df = pd.read_csv(p)
    time_split(df)
