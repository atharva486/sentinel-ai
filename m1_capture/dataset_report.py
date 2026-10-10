#!/usr/bin/env python3
"""
dataset_report.py — one-command health check for data/features.parquet.

The dataset is the project's lifeline, so regenerating it ends with a report
that answers the four questions that matter:

  1. Counts + label balance (chronological split is only valid if both classes
     appear in both train and val — splits.py refuses one-class sides).
  2. Class separation (do the means actually differ?).
  3. Tier aliveness: the project's two contributions need `concurrent_conns`
     non-trivial for attacks (else SHAP can never pick limit_conn) and the
     stall tier spread (else timeouts look arbitrary).
  4. Dead features (constant columns add noise to XGBoost, not signal) and an
     ALERT when something silently broke (e.g. every attack entity having
     exactly 1 connection again).

Usage:
    python m1_capture/dataset_report.py [features.parquet]
"""
from __future__ import annotations

import sys

import pandas as pd

FEATURES = None  # read from the parquet itself


def dead_features(df: pd.DataFrame) -> list[str]:
    feats = [c for c in df.columns if c not in ("entity", "role", "t", "y", "session")]
    return [c for c in feats if df[c].nunique() <= 1]


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "data/features.parquet"
    df = pd.read_parquet(path)
    feats = [c for c in df.columns if c not in ("entity", "role", "t", "y", "session")]

    print(f"file      : {path}")
    print(f"shape     : {df.shape[0]} rows x {df.shape[1]} cols "
          f"({len(feats)} features) | NaNs: {int(df[feats].isna().sum().sum())}")
    print(f"time span : {round(df.t.max() - df.t.min(), 1)} s")

    print("\n== label balance ==")
    print(df["role"].value_counts().to_string())

    print("\n== per-session (source-IP third octet) ==")
    df["_sess"] = df["entity"].str.split(".").str[2]
    print(df.groupby(["_sess", "role"]).size().unstack().fillna(0).astype(int).to_string())

    print("\n== class means (key features) ==")
    cols = ["header_complete", "stall_time_s", "concurrent_conns",
            "conns_per_second_opened", "requests_per_s", "body_frac_sent",
            "bytes_in", "conn_age_s"]
    cols = [c for c in cols if c in df.columns]
    print(df.groupby("role")[cols].mean().round(3).T.to_string())

    print("\n== concurrency tier (contribution #1: limit_conn) ==")
    a = df[df.role == "attack"]
    b = df[df.role == "benign"]
    a_med = a["concurrent_conns"].median()
    b_med = b["concurrent_conns"].median()
    a_p90 = a["concurrent_conns"].quantile(0.9)
    b_p90 = b["concurrent_conns"].quantile(0.9)
    a_share = (a["concurrent_conns"] > 2).mean()
    b_share = (b["concurrent_conns"] > 2).mean()
    print(f"attack median {a_med:.2f} p90 {a_p90:.1f} max {a['concurrent_conns'].max():.0f}"
          f" | benign median {b_med:.2f} p90 {b_p90:.1f} max {b['concurrent_conns'].max():.0f}")
    print(f">2 conns: attack {a_share:.1%} vs benign {b_share:.1%}")
    # The tier is alive if the attack DISTRIBUTION sits above benign: either the
    # median separates (classic shared-IP slowloris, e.g. one entity holding
    # dozens of sockets) or the tail separates AND a material share of attack
    # rows carry raised concurrency. Judging only the median hides a strong tail
    # when most sessions use one-worker-per-IP bots.
    if a_p90 <= b_p90 and a_share <= b_share * 3:
        print("  !! ALERT: concurrent_conns does not separate — SHAP can never "
              "pick limit_conn.")
        print("     Slowloris must SHARE a few IPs (bots hold many sockets).")
    else:
        print("  OK: concurrency separates (slowloris holds many sockets per IP).")

    dead = dead_features(df)
    print(f"\n== dead (constant) features: {dead if dead else 'none'} ==")
    for c in dead:
        print(f"  {c} = {df[c].iloc[0]} — drop or repair before training")

    print("\n== chronological split ==")
    from splits import time_split  # noqa: PLC0415  (single source of truth)

    time_split(df, time_col="t", label_col="role")
    print("split OK — both classes present on both sides")
    print("\nREPORT DONE")

if __name__ == "__main__":
    main()