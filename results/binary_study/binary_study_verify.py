#!/usr/bin/env python3
"""
Independent, reproducible check of the Sentinel-AI binary study.

Usage:  python binary_study_verify.py "data/features_run[HIJKL].parquet"
        (use an explicit glob: *_filtered / *_backup files duplicate the same flows)
Needs:  pandas, numpy, xgboost, pyarrow

Design (everything is per UNIQUE FLOW, never per snapshot row):
  * client-facing flows only (role in {attack, benign}); the proxy->backend leg
    (source 172.18.0.2, role 'legacy') is dropped.
  * flow key = session + flow_id (flow_id alone collides across sessions).
  * train = runH, test = runK + runL, one metric table per as_of time.
  * features are per-connection only; conn_age_s is excluded on purpose because
    in snapshots it just echoes the as_of time (or the lifetime for 'final').
  * labels are by container IP ("ip_role"), so this is a BINARY study.
"""
import glob
import sys
import warnings

import numpy as np
import pandas as pd
import xgboost as xgb

warnings.filterwarnings("ignore")
PATTERN = sys.argv[1] if len(sys.argv) > 1 else "data/features_run[HIJKL].parquet"
THRESHOLD = 0.30
AS_OF = [1, 2, 5, 10, 20, 999]  # 999 = final flow

BASE = ["bytes_in", "bytes_in_per_s", "requests_per_s", "packets_per_s",
        "interarrival_mean", "interarrival_std", "interarrival_max",
        "requests_per_conn_so_far", "stall_time_s", "body_frac_sent",
        "bytes_declared", "body_drip_rate_bps", "header_complete"]


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def load():
    files = sorted(glob.glob(PATTERN))
    if not files:
        sys.exit(f"no files match {PATTERN}")
    print("files used:")
    for f in files:
        print("  ", f)
    df = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    df = df[df.role.isin(["attack", "benign"])].copy()
    df["fid"] = df.session + "|" + df.flow_id
    df["ao"] = df.as_of.map(lambda x: 999.0 if x == "final" else float(x))
    dup = int(df.duplicated(["fid", "as_of"]).sum())
    if dup:
        sys.exit(
            f"\nSTOP: {dup} duplicate (session, flow_id, as_of) rows. Your glob matched "
            "several files for the same session (for example *_filtered.parquet or "
            "*_backup.parquet), so every flow would be counted twice and the "
            "confidence intervals would be too narrow.\n"
            'Use an explicit glob, e.g.  "data/features_run[HIJKL].parquet"'
        )
    return df


def fit(train, feats):
    return xgb.XGBClassifier(
        n_estimators=200, max_depth=4, learning_rate=0.1, subsample=0.8,
        colsample_bytree=0.8, random_state=0, eval_metric="aucpr",
    ).fit(train[feats], (train.role == "attack").astype(int))


def table(model, test, feats, title):
    print(f"\n=== {title}  (threshold {THRESHOLD}, per unique flow)")
    print("as_of  attack  benign   TP  FN  FP    TN   recall   FPR   FPR 95% CI")
    for ao in AS_OF:
        t = test[test.ao == ao]
        p = model.predict_proba(t[feats])[:, 1] >= THRESHOLD
        a = (t.role == "attack").values
        tp, fn = int(p[a].sum()), int((~p[a]).sum())
        fp, tn = int(p[~a].sum()), int((~p[~a]).sum())
        lo, hi = wilson(fp, fp + tn)
        name = "final" if ao == 999 else ao
        print(f"{name!s:>5} {a.sum():>6} {(~a).sum():>7} {tp:>4} {fn:>3} {fp:>3} {tn:>5}"
              f"   {tp / max(1, tp + fn):.3f}  {fp / max(1, fp + tn):.4f}  [{lo:.4f}, {hi:.4f}]")


def behaviour(final_attack):
    def kind(r):
        if r.header_complete == 0:
            return "slowloris-like"
        if r.requests_per_conn_so_far >= 20 or r.bytes_in_per_s > 50000:
            return "flood-like"
        if r.stall_time_s > 1 or r.body_frac_sent < 1:
            return "slow-POST-like"
        return "other"
    return final_attack.assign(kind=final_attack.apply(kind, axis=1))[["fid", "kind"]]


def main():
    df = load()
    print(f"client rows: {len(df)}   unique flows: {df.fid.nunique()}")
    fin = df[df.as_of == "final"]
    print("\nfinal flows by session x role:")
    print(pd.crosstab(fin.session, fin.role))

    train = df[df.session == "runH"]
    test = df[df.session.isin(["runK", "runL"])]

    model = fit(train, BASE)
    table(model, test, BASE, "13 per-connection features")

    for name, drop in [("drop bytes_in, bytes_declared", ["bytes_in", "bytes_declared"]),
                       ("drop all size/volume features",
                        ["bytes_in", "bytes_declared", "packets_per_s", "bytes_in_per_s"])]:
        feats = [f for f in BASE if f not in drop]
        table(fit(train, feats), test, feats, name)

    # recall by attack behaviour (behaviour label is a heuristic, not ground truth)
    kinds = behaviour(fin[(fin.role == "attack") & fin.session.isin(["runK", "runL"])])
    print("\n=== recall by attack behaviour (heuristic grouping of final-flow behaviour)")
    for ao in (1, 5):
        t = test[(test.ao == ao) & (test.role == "attack")].merge(kinds, on="fid")
        t["hit"] = model.predict_proba(t[BASE])[:, 1] >= THRESHOLD
        print(f"as_of={ao}:")
        print(t.groupby("kind").hit.agg(["mean", "size"]).round(3).to_string())

    # what do benign flows with an incomplete header look like at 1 s?
    t = df[(df.ao == 1) & (df.header_complete == 0)]
    zero = int(((t.role == "benign") & (t.bytes_in == 0)).sum())
    ben = int((t.role == "benign").sum())
    print(f"\nbenign flows with an incomplete header at 1 s: {ben}; of those, {zero} "
          f"have sent 0 bytes (idle connection, not a slow sender)")


if __name__ == "__main__":
    main()
