#!/usr/bin/env python3
"""
Per-flow evaluation of replay decisions against the side log.

Usage:
  python eval_replay.py DECISIONS.parquet SIDE_LOG.jsonl

DECISIONS.parquet needs: flow_key, client_ip, client_port, t_first, cycle_time,
age, score, flagged.   The side log needs: src_ip, src_port, start_ts, end_ts,
role, attack_type.

Rules (everything is per UNIQUE FLOW, one point per flow):
  * join key: (client_ip, client_port) must exist in the side log AND the
    flow's first packet time must lie in [start_ts - 2 s, end_ts + 2 s].
  * flows without a side-log row are "unlabelled": counted and reported,
    never included in the metrics.
  * "ever flagged"  = any decision of the flow had flagged == True.
  * detection-time table: among flows whose observed lifetime >= t, the share
    flagged at some decision with age <= t. Decisions run on a fixed clock
    (ages are d, 1+d, 2+d, ... with d the flow's offset inside the cycle), so
    "age <= 1" covers the first decision only.
"""
import json
import sys

import numpy as np
import pandas as pd

TOL = 2.0


def wilson(k, n, z=1.96):
    if n == 0:
        return (float("nan"), float("nan"))
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (c - h, c + h)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    d = pd.read_parquet(sys.argv[1])
    sl = pd.DataFrame([json.loads(l) for l in open(sys.argv[2]) if l.strip()])
    sl["k"] = sl.src_ip + ":" + sl.src_port.astype(int).astype(str)
    dup_keys = int(sl.k.duplicated().sum())
    sl = sl.drop_duplicates("k")
    d["k"] = d.client_ip + ":" + d.client_port.astype(int).astype(str)
    d = d.sort_values(["flow_key", "age"])

    g = d.groupby("flow_key")
    fl = pd.DataFrame({
        "k": g.k.first(), "t_first": g.t_first.first(), "n_dec": g.size(),
        "max_age": g.age.max(), "ever": g.flagged.any(),
        "first_flag_age": g.apply(lambda x: x.loc[x.flagged, "age"].min() if x.flagged.any() else np.nan),
    }).reset_index()
    fl = fl.merge(sl[["k", "start_ts", "end_ts", "role", "attack_type"]], on="k", how="left")
    ok = fl.start_ts.notna() & (fl.t_first >= fl.start_ts - TOL) & (fl.t_first <= fl.end_ts + TOL)
    fl.loc[~ok, ["role", "attack_type"]] = "unlabelled"

    print(f"decisions: {len(d)}   flows seen: {len(fl)}   side-log rows: {len(sl)} "
          f"(duplicate (ip,port) keys dropped: {dup_keys})")
    print(f"join coverage: labelled flows / flows seen = {int(ok.sum())}/{len(fl)} = {100 * ok.mean():.1f}%")
    print(f"               side-log rows seen as a flow  = {fl[ok].k.nunique()}/{len(sl)}")
    print("\nflows by label:")
    print(fl.groupby(["role", "attack_type"]).size().to_string())
    older = fl[fl.max_age > 2]
    print(f"\nflows older than 2 s: {len(older)}; with >= 2 decisions: {int((older.n_dec >= 2).sum())}")

    print("\n== per flow, flagged at least once during its life")
    for r in ["attack", "benign"]:
        s = fl[fl.role == r]
        k, n = int(s.ever.sum()), len(s)
        lo, hi = wilson(k, n)
        print(f"{r:7} flows {n:5}  flagged {k:5}  rate {k / max(n, 1):.4f}  95% CI [{lo:.4f}, {hi:.4f}]")
    for a in sorted(set(fl[fl.role == "attack"].attack_type)):
        s = fl[fl.attack_type == a]
        k, n = int(s.ever.sum()), len(s)
        lo, hi = wilson(k, n)
        print(f"   {a:12} flows {n:5}  flagged {k:5}  rate {k / max(n, 1):.4f}  95% CI [{lo:.4f}, {hi:.4f}]")
    u = fl[fl.role == "unlabelled"]
    pk = int(d[d.k.isin(u.k)].shape[0])
    print(f"unlabelled flows {len(u)} (excluded from all metrics): flagged {int(u.ever.sum())}, decisions {pk}")

    print("\n== detection time, one point per flow")
    print("  t | attack: flows flagged  rate [95% CI]        | benign: flows flagged  rate [95% CI]")
    for t in [1, 2, 3, 5, 10, 20, 30]:
        A = fl[(fl.role == "attack") & (fl.max_age >= t)]
        B = fl[(fl.role == "benign") & (fl.max_age >= t)]
        ka, kb = int((A.first_flag_age <= t).sum()), int((B.first_flag_age <= t).sum())
        la, lb = wilson(ka, len(A)), wilson(kb, len(B))
        print(f"{t:>3} | {len(A):12} {ka:7}  {ka / max(len(A), 1):.3f} [{la[0]:.3f}, {la[1]:.3f}]"
              f" | {len(B):12} {kb:7}  {kb / max(len(B), 1):.4f} [{lb[0]:.4f}, {lb[1]:.4f}]")
    a = fl[(fl.role == "attack") & fl.ever]
    print(f"\nattack age at first flag: median {a.first_flag_age.median():.2f} s, "
          f"p90 {a.first_flag_age.quantile(.9):.2f} s  (n = {len(a)} flagged of {(fl.role == 'attack').sum()})")
    print(f"attack flows never flagged: {int(((fl.role == 'attack') & ~fl.ever).sum())}")
    b = fl[fl.role == "benign"]
    print(f"benign observed lifetime (s): median {b.max_age.median():.1f}, p90 {b.max_age.quantile(.9):.1f}, max {b.max_age.max():.1f}")


if __name__ == "__main__":
    main()
