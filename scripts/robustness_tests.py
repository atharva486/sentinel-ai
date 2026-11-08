#!/usr/bin/env python3
"""
Robustness tests for the Sentinel-AI binary study. Everything is per UNIQUE FLOW
(key = session + flow_id); metrics at as-of snapshots; Wilson 95% intervals.
Nothing here is tuned on the test split.

Usage:  python robustness_tests.py "data/binary_study_client_flows.parquet"
Needs:  pandas, numpy, xgboost, pyarrow

A  threshold chosen on VALIDATION (runI) for a false-positive budget, applied to test
B  leave-one-attack-BEHAVIOUR-out (behaviour groups are a heuristic, see behaviour())
C  leave-one-SESSION-out over the sessions that contain attacks
D  seed stability of the main result
E  idealised static-rule baseline (an offline APPROXIMATION of timeouts and a rate
   limit; it is NOT nginx, and the benign data has no slow legitimate header
   senders, so the false-positive cost of timeouts is understated)
"""
import glob
import sys
import warnings

import numpy as np
import pandas as pd
import xgboost as xgb

warnings.filterwarnings("ignore")
PATTERN = sys.argv[1] if len(sys.argv) > 1 else "data/binary_study_client_flows.parquet"
BASE = ["bytes_in", "bytes_in_per_s", "requests_per_s", "packets_per_s",
        "interarrival_mean", "interarrival_std", "interarrival_max",
        "requests_per_conn_so_far", "stall_time_s", "body_frac_sent",
        "bytes_declared", "body_drip_rate_bps", "header_complete"]
AO = [1, 2, 5, 10, 20, 999]
NAME = {999: "final"}


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
    df = pd.concat([pd.read_parquet(f) for f in files], ignore_index=True)
    df = df[df.role.isin(["attack", "benign"])].copy()
    df["fid"] = df.session + "|" + df.flow_id
    df["ao"] = df.as_of.map(lambda x: 999.0 if x == "final" else float(x))
    if df.duplicated(["fid", "as_of"]).any():
        sys.exit("duplicate (session, flow_id, as_of) rows: use an explicit file list")
    return df


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


def fit(train, seed=0):
    return xgb.XGBClassifier(n_estimators=200, max_depth=4, learning_rate=0.1, subsample=0.8,
                             colsample_bytree=0.8, random_state=seed, eval_metric="aucpr"
                             ).fit(train[BASE], (train.role == "attack").astype(int))


def counts(flag, a):
    return int(flag[a].sum()), int((~flag[a]).sum()), int(flag[~a].sum()), int((~flag[~a]).sum())


def row(label, tp, fn, fp, tn):
    lo, hi = wilson(fp, fp + tn)
    return (f"{label:>6} {tp + fn:>6} {tp:>5} {tp / max(1, tp + fn):.3f}   "
            f"{fp + tn:>6} {fp:>4} {fp / max(1, fp + tn):.4f} [{lo:.4f}, {hi:.4f}]")


HEAD = "as_of attack  caught recall   benign   FP  FPR [95% CI]"


def main():
    df = load()
    fin = df[df.as_of == "final"]
    kinds = behaviour(fin[fin.role == "attack"])
    train, val = df[df.session == "runH"], df[df.session == "runI"]
    test = df[df.session.isin(["runK", "runL"])]
    print(f"flows: {df.fid.nunique()}  | test = runK+runL, train = runH, validation = runI")

    # ---------------- A
    print("\n==== A. threshold chosen on VALIDATION (runI, as_of = 1) for an FPR budget")
    m = fit(train)
    v1 = val[val.ao == 1]
    vb = np.sort(m.predict_proba(v1[BASE])[:, 1][(v1.role == "benign").values])[::-1]
    print(f"validation benign flows at 1 s: {len(vb)}")
    for budget in (0.005, 0.002):
        k = int(np.floor(budget * len(vb)))
        thr = float(vb[k]) if k < len(vb) else 0.0
        print(f"\n-- budget {budget:.1%}: threshold {thr:.4f} (flag if score > threshold)")
        print(HEAD)
        for ao in AO:
            t = test[test.ao == ao]
            p = m.predict_proba(t[BASE])[:, 1] > thr
            print(row(NAME.get(ao, int(ao)), *counts(p, (t.role == "attack").values)))
    print("\n-- reference: fixed 0.30")
    print(HEAD)
    for ao in AO:
        t = test[test.ao == ao]
        p = m.predict_proba(t[BASE])[:, 1] >= 0.30
        print(row(NAME.get(ao, int(ao)), *counts(p, (t.role == "attack").values)))

    # ---------------- B
    print("\n==== B. leave-one-attack-BEHAVIOUR-out (heuristic groups from final-flow features)")
    print("train: runH benign + attacks NOT in the held-out group; test: runK+runL, threshold 0.30")
    kmap = dict(zip(kinds.fid, kinds.kind))
    for G in ["slowloris-like", "flood-like", "slow-POST-like"]:
        keep = ~((train.role == "attack") & (train.fid.map(kmap) == G))
        mG = fit(train[keep])
        print(f"\n-- held out: {G} (train attack flows left: {train[keep & (train.role == 'attack')].fid.nunique()})")
        print("as_of  unseen_n unseen_recall | seen_n seen_recall | benign FP / n")
        for ao in (1, 5, 999):
            t = test[test.ao == ao].copy()
            t["p"] = mG.predict_proba(t[BASE])[:, 1] >= 0.30
            t["g"] = t.fid.map(kmap)
            un, se = t[(t.role == "attack") & (t.g == G)], t[(t.role == "attack") & (t.g != G)]
            bn = t[t.role == "benign"]
            print(f"{NAME.get(ao, int(ao)):>5}  {len(un):>8} {un.p.mean():>13.3f} | {len(se):>6} {se.p.mean():>11.3f} | "
                  f"{int(bn.p.sum())} / {len(bn)}")

    # ---------------- C
    print("\n==== C. leave-one-SESSION-out (runJ is benign-only and is always in training)")
    print("fold  as_of attack caught recall  benign FP  FPR")
    agg = {1: [], 5: [], 999: []}
    pool = {1: [0, 0, 0, 0], 5: [0, 0, 0, 0], 999: [0, 0, 0, 0]}
    for S in ["runH", "runI", "runK", "runL"]:
        tr = df[(df.session != S)]
        te = df[df.session == S]
        mS = fit(tr)
        for ao in (1, 5, 999):
            t = te[te.ao == ao]
            p = mS.predict_proba(t[BASE])[:, 1] >= 0.30
            tp, fn, fp, tn = counts(p, (t.role == "attack").values)
            agg[ao].append((tp / max(1, tp + fn), fp / max(1, fp + tn)))
            for i, v in enumerate((tp, fn, fp, tn)):
                pool[ao][i] += v
            print(f"{S:>5} {NAME.get(ao, int(ao)):>6} {tp + fn:>6} {tp:>5} {tp / max(1, tp + fn):.3f} {fp + tn:>7} {fp:>3} {fp / max(1, fp + tn):.4f}")
    print("\nmean (min-max) over the 4 folds:")
    for ao, v in agg.items():
        r, f = np.array(v).T
        print(f"  as_of {NAME.get(ao, int(ao)):>5}: recall {r.mean():.3f} ({r.min():.3f}-{r.max():.3f})   FPR {f.mean():.4f} ({f.min():.4f}-{f.max():.4f})")

    print("\npooled over the 4 folds (each flow counted once per as_of):")
    for ao, (tp, fn, fp, tn) in pool.items():
        ra, rf = wilson(tp, tp + fn), wilson(fp, fp + tn)
        print(f"  as_of {NAME.get(ao, int(ao)):>5}: recall {tp}/{tp + fn} = {tp / (tp + fn):.4f} [{ra[0]:.4f}, {ra[1]:.4f}]"
              f"   FP {fp}/{fp + tn} = {fp / (fp + tn):.4f} [{rf[0]:.4f}, {rf[1]:.4f}]")

    # ---------------- D
    print("\n==== D. seed stability (train runH, test runK+runL, threshold 0.30)")
    print("seed  as_of=1: recall  FP/benign | as_of=5: recall  FP/benign")
    res = []
    for s in range(5):
        ms = fit(train, seed=s)
        out = []
        for ao in (1, 5):
            t = test[test.ao == ao]
            tp, fn, fp, tn = counts(ms.predict_proba(t[BASE])[:, 1] >= 0.30, (t.role == "attack").values)
            out.append((tp / max(1, tp + fn), fp, fp + tn))
        res.append(out)
        print(f"{s:>4}  {out[0][0]:.3f}  {out[0][1]}/{out[0][2]}  |  {out[1][0]:.3f}  {out[1][1]}/{out[1][2]}")
    r1 = [o[0][0] for o in res]
    f1 = [o[0][1] for o in res]
    print(f"as_of=1 recall {np.mean(r1):.3f} (min {min(r1):.3f}, max {max(r1):.3f}); FP {np.mean(f1):.1f} (min {min(f1)}, max {max(f1)})")

    # ---------------- E
    print("\n==== E. idealised static baseline vs the model (test = runK+runL)")
    print("APPROXIMATION from per-flow features, NOT nginx. 'timeout T': header or body incomplete AND")
    print("largest packet gap so far >= T s.  'rate R': requests_per_s >= R.  Benign data has no slow")
    print("legitimate header senders, so timeout false positives are understated.")
    for T, R in [(5, 20), (10, 20), (30, 20)]:
        print(f"\n-- timeout T={T}s + rate R={R}/s")
        print(HEAD)
        for ao in (1, 2, 5, 10):
            t = test[test.ao == ao]
            flag = ((((t.header_complete == 0) | (t.body_frac_sent < 1)) & (t.interarrival_max >= T))
                    | (t.requests_per_s >= R)).values
            print(row(NAME.get(ao, int(ao)), *counts(flag, (t.role == "attack").values)))
    print("\n(the 'final' snapshot is left out of E: benign flows that live under 50 ms get requests_per_s > 20 there)")
    print("\n-- model, fixed 0.30 (same flows)")
    print(HEAD)
    for ao in (1, 2, 5, 10):
        t = test[test.ao == ao]
        print(row(NAME.get(ao, int(ao)), *counts(m.predict_proba(t[BASE])[:, 1] >= 0.30, (t.role == "attack").values)))
    a = fin[fin.role == "attack"].assign(kind=lambda x: x.fid.map(kmap))
    print("\nlargest packet gap (s) per attack flow at final, by behaviour (an idle-gap timeout can only fire above its gap):")
    print(a.groupby("kind").interarrival_max.describe().round(2)[["count", "min", "25%", "50%", "75%", "max"]].to_string())
    for G in ["slowloris-like", "flood-like", "slow-POST-like"]:
        t = test[(test.ao == 5) & (test.role == "attack") & (test.fid.map(kmap) == G)]
        fl = ((((t.header_complete == 0) | (t.body_frac_sent < 1)) & (t.interarrival_max >= 10)) | (t.requests_per_s >= 20)).mean()
        print(f"   as_of 5, {G:15}: static (T=10,R=20) catches {fl:.3f}, model catches "
              f"{(m.predict_proba(t[BASE])[:, 1] >= 0.30).mean():.3f}  (n={len(t)})")


if __name__ == "__main__":
    main()
