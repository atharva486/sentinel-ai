from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

import pandas as pd


def load_cicids2017_audited(path: str | Path, days: Iterable[str] | None = None) -> pd.DataFrame:
    """Load and audit CIC-IDS2017 Improved CSVs.

    Cleaning steps (as per manual):
    1. Drop rows where 'Attempted Category' != -1 (Attempted are not real attacks)
    2. Drop 'DoS Hulk' (mis-implemented in dataset)
    3. Drop 'DoS GoldenEye' and 'DDoS LOIC-HTTP' (ineffective)
    4. Keep ONLY ['Benign', 'DoS Slowloris', 'DoS Slowhttptest']
    """
    p = Path(path)
    if days is None:
        days = ["monday", "tuesday", "wednesday", "thursday", "friday"]

    dfs: list[pd.DataFrame] = []
    for d in days:
        csv = p / f"{d}.csv"
        if not csv.exists():
            raise FileNotFoundError(f"Missing expected CSV: {csv}")
        dfs.append(pd.read_csv(csv))

    df = pd.concat(dfs, ignore_index=True)

    if "Attempted Category" in df.columns:
        df = df[df["Attempted Category"] == -1].copy()

    df = df[df["Label"] != "DoS Hulk"].copy()
    df = df[~df["Label"].isin(["DoS GoldenEye", "DDoS LOIC-HTTP"])].copy()
    df = df[df["Label"].isin(["Benign", "DoS Slowloris", "DoS Slowhttptest"])].copy()

    num = df.select_dtypes(include="number")
    df[num.columns] = num.replace([float("inf"), float("-inf")], pd.NA)
    df = df.dropna().drop_duplicates()

    return df


if __name__ == "__main__":
    base = Path("data") / "CICIDS2017_improved"
    if not base.exists():
        print(f"WARNING: {base} not found. Download/unzip CIC-IDS2017 Improved there.")
        raise SystemExit(0)
    df = load_cicids2017_audited(base)
    print(df["Label"].value_counts().to_string())
