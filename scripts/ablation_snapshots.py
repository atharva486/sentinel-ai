#!/usr/bin/env python3
"""Feature ablations and zero-shot baseline on snapshot datasets.

Two analyses:

1. ABLATION (legacy flows, session-split):
   Train XGBoost on snapshot training flows (sessions runa, runc, rund),
   validate on val (rune), test on test (runb, runf, rung).
   Configurations:
     - base set (15 per-connection features)
     - base - conn_age_s
     - base - bytes_in, bytes_declared
     - base + ip_context (3 extra IP-level features)
   Reports PR-AUC / ROC-AUC on the test split for each.
   Also reports whether conn_age_s alone separates classes
   (attacks live ~125s, benign at most ~43s in this lab).

2. ZERO-SHOT BASELINE (score the OLD model on snapshot features):
   Load the shipped model artifact (calibration_result_current.joblib).
   Score snapshot features at each as_of time (1,2,3,5,10,20,final).
   Report per-as_of: attack recall and benign FPR (per flow).
   Separate tables for:
     - baseline (side_log labels, live_capture.pcap)
     - legacy (legacy_label labels, runA-G pcaps)

Usage:
    python3 scripts/ablation_snapshots.py
"""

from __future__ import annotations

import json
import math
import tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import xgboost as xgb
import joblib
import os as _os

sys_path = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(sys_path))

from m1_capture.features import FEATURE_ORDER, IPCONTEXT_FEATURES, LEGACY_FEATURE_ORDER

REPO = Path(__file__).resolve().parent.parent
SNAPSHOTS = REPO / "data" / "features_snapshots.parquet"
FEATURES_PQ = REPO / "data" / "features.parquet"
ART_PATH = REPO / "models" / "calibration_result_current.joblib"

# Map pcap-name -> session for legacy flows (derived from flow_id IP ranges)
# runA->runa, runB->runb, etc.  We match snapshot flows to features.parquet
# by (entity, session) to recover the session label.
SESSION_BY_ENTITY = {}
_df = pd.read_parquet(FEATURES_PQ)
for _, r in _df.iterrows():
    SESSION_BY_ENTITY[(r["entity"], r["session"])] = r["y"]


def load_snapshots() -> pd.DataFrame:
    df = pd.read_parquet(SNAPSHOTS)
    # Add session by matching legacy flows to features.parquet
    # (baseline side_log flows have no session -> NaN)
    sessions = []
    for _, r in df.iterrows():
        if r["label_source"] == "side_log":
            sessions.append(None)
        else:
            # Match by entity + approximate t_first to features.parquet
            ent = r["entity"]
            t_first = r["t_first"]
            cand = _df[(_df["entity"] == ent) &
                       (abs(_df["t"] - t_first) < 1.0)]
            if len(cand) > 0:
                sessions.append(cand.iloc[0]["session"])
            else:
                sessions.append(None)
    df["session"] = sessions
    return df


def train_xgb(X_train, y_train, X_val, y_val, feature_cols,
              params: dict | None = None):
    """Train XGBoost, return (model, best_iteration)."""
    if params is None:
        params = dict(
            n_estimators=400, max_depth=5, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            eval_metric="aucpr", random_state=42, base_score=0.5,
        )
    model = xgb.XGBClassifier(**params)
    model.fit(X_train[feature_cols], y_train,
              eval_set=[(X_val[feature_cols], y_val)],
              verbose=False)
    return model


def eval_model(model, X, y, feature_cols, threshold=0.30):
    """Return dict of metrics."""
    proba = model.predict_proba(X[feature_cols])[:, 1]
    pred = proba >= threshold
    y = y.to_numpy()
    tp = int(((pred) & (y == 1)).sum())
    tn = int((~pred & (y == 0)).sum())
    fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum())
    from sklearn.metrics import average_precision_score, roc_auc_score
    pr_auc = average_precision_score(y, proba)
    roc_auc = roc_auc_score(y, proba)
    return {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "pr_auc": round(pr_auc, 4),
        "roc_auc": round(roc_auc, 4),
    }


def ablation_table(df: pd.DataFrame):
    """Train+test models with different feature subsets on legacy flows.

    Runs each config with 3 random seeds and reports mean +/- std dev.
    Confirms no flow_id appears in more than one split.
    """
    legacy = df[df.label_source == "legacy_label"].copy()
    legacy = legacy.dropna(subset=["session"])
    print(f"Legacy flows with session: {legacy.flow_id.nunique()}")
    print(f"Sessions: {sorted(legacy.session.unique())}")

    train_sessions = ["runa", "runc", "rund"]
    val_sessions = ["rune"]
    test_sessions = ["runb", "runf", "rung"]

    train = legacy[legacy.session.isin(train_sessions)].copy()
    val = legacy[legacy.session.isin(val_sessions)].copy()
    test = legacy[legacy.session.isin(test_sessions)].copy()

    # Confirm no flow_id appears in more than one split
    all_flow_ids = {s: set(df.flow_id.unique()) for s, df in
                    [("train", train), ("val", val), ("test", test)]}
    train_val = all_flow_ids["train"] & all_flow_ids["val"]
    train_test = all_flow_ids["train"] & all_flow_ids["test"]
    val_test = all_flow_ids["val"] & all_flow_ids["test"]
    print(f"\nFlow split integrity:")
    print(f"  Train flows: {len(all_flow_ids['train'])}, rows: {len(train)}")
    print(f"  Val flows:   {len(all_flow_ids['val'])}, rows: {len(val)}")
    print(f"  Test flows:  {len(all_flow_ids['test'])}, rows: {len(test)}")
    print(f"  Train∩Val: {len(train_val)}, Train∩Test: {len(train_test)}, "
          f"Val∩Test: {len(val_test)}")
    assert len(train_val) == 0 and len(train_test) == 0 and len(val_test) == 0, \
        "Flow leakage between splits!"

    print(f"\nTest split: {len(all_flow_ids['test'])} unique flows, {len(test)} rows")

    base_cols = [c for c in FEATURE_ORDER]
    ip_ctx_cols = [c for c in IPCONTEXT_FEATURES]

    configs = {
        "base (15 per-conn)": base_cols,
        "base - conn_age_s": [c for c in base_cols if c != "conn_age_s"],
        "base - bytes_in, bytes_declared":
            [c for c in base_cols if c not in ("bytes_in", "bytes_declared")],
        "base + ip_context (18)": base_cols + list(ip_ctx_cols),
    }

    # conn_age_s alone: does it separate classes?
    print("\n=== conn_age_s alone: attack vs benign age distribution ===")
    test_attack = test[test.y == 1]
    test_benign = test[test.y == 0]
    print(f"Attack conn_age_s: mean={test_attack.conn_age_s.mean():.1f}s, "
          f"median={test_attack.conn_age_s.median():.1f}s, "
          f"min={test_attack.conn_age_s.min():.1f}, max={test_attack.conn_age_s.max():.1f}")
    print(f"Benign conn_age_s: mean={test_benign.conn_age_s.mean():.1f}s, "
          f"median={test_benign.conn_age_s.median():.1f}s, "
          f"min={test_benign.conn_age_s.min():.1f}, max={test_benign.conn_age_s.max():.1f}")
    overlap = (test_benign.conn_age_s.max() > test_attack.conn_age_s.min())
    print(f"Benign max ({test_benign.conn_age_s.max():.1f}s) > "
          f"Attack min ({test_attack.conn_age_s.min():.1f}s): {overlap}")
    print(f"=> conn_age_s {'DOES NOT' if overlap else 'does'} cleanly separate classes")

    print("\n=== Ablation table (test split, session-based, 3 seeds) ===")
    print(f"{'Config':32s} {'n_feat':>6} {'test_flows':>10} {'PR-AUC':>9} {'ROC-AUC':>9} "
          f"{'recall':>9} {'precision':>10}")
    results = []
    for name, cols in configs.items():
        seed_results = []
        for seed in [42, 123, 777]:
            model = train_xgb(train, train.y, val, val.y, cols,
                              params={"random_state": seed,
                                      "n_estimators": 400, "max_depth": 5,
                                      "learning_rate": 0.1, "subsample": 0.8,
                                      "colsample_bytree": 0.8,
                                      "eval_metric": "aucpr", "base_score": 0.5})
            m = eval_model(model, test, test.y, cols)
            seed_results.append(m)
        pr_aucs = [r["pr_auc"] for r in seed_results]
        roc_aucs = [r["roc_auc"] for r in seed_results]
        recalls = [r["recall"] for r in seed_results]
        precisions = [r["precision"] for r in seed_results]
        import statistics
        result = {
            "config": name,
            "n_features": len(cols),
            "test_flows": len(all_flow_ids["test"]),
            "pr_auc_mean": statistics.mean(pr_aucs),
            "pr_auc_std": statistics.stdev(pr_aucs) if len(pr_aucs) > 1 else 0.0,
            "roc_auc_mean": statistics.mean(roc_aucs),
            "roc_auc_std": statistics.stdev(roc_aucs) if len(roc_aucs) > 1 else 0.0,
            "recall_mean": statistics.mean(recalls),
            "recall_std": statistics.stdev(recalls) if len(recalls) > 1 else 0.0,
            "precision_mean": statistics.mean(precisions),
            "precision_std": statistics.stdev(precisions) if len(precisions) > 1 else 0.0,
        }
        results.append(result)
        print(f"{name:32s} {len(cols):>6} {len(all_flow_ids['test']):>10} "
              f"{result['pr_auc_mean']:.4f}±{result['pr_auc_std']:.4f}  "
              f"{result['roc_auc_mean']:.4f}±{result['roc_auc_std']:.4f}  "
              f"{result['recall_mean']:.4f}±{result['recall_std']:.4f}  "
              f"{result['precision_mean']:.4f}±{result['precision_std']:.4f}")

    return results


def zero_shot_baseline(df: pd.DataFrame):
    """Score the OLD model on snapshot features at each as_of time.

    Uses LEGACY_FEATURE_ORDER (16 features) built from the snapshot's
    base + ip_context columns.  Scores each snapshot row, then aggregates
    per flow: a flow is "flagged" if ANY of its snapshots (up to that
    as_of time) scores >= threshold.
    """
    import joblib, tempfile, os as _os
    import xgboost as xgb

    artifact = joblib.load(str(ART_PATH))
    model_json = artifact["model_json"]
    calibrator = artifact["calibrator"]
    with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as tmp:
        tmp.write(model_json)
        tmp_path = tmp.name
    try:
        model = xgb.XGBClassifier(n_estimators=10, base_score=0.5)
        model.load_model(tmp_path)
    finally:
        _os.unlink(tmp_path)
    threshold = 0.30

    print("\n=== Zero-shot baseline: old model on snapshot features ===")
    print(f"Model artifact loaded. Threshold: {threshold}")

    # Build legacy 16-feature matrix once
    legacy_cols = [c for c in LEGACY_FEATURE_ORDER]
    missing = [c for c in legacy_cols if c not in df.columns]
    if missing:
        print(f"Missing legacy columns: {missing}")
        return

    X_all = df[legacy_cols].copy()
    proba_all = model.predict_proba(X_all)[:, 1]
    cal_all = np.clip(calibrator.predict(proba_all), 0, 1)
    df = df.copy()
    df["cal"] = cal_all
    df["flagged"] = df["cal"] >= threshold

    aof_order = ["1.0", "2.0", "3.0", "5.0", "10.0", "20.0", "final"]

    for label_src in ["side_log", "legacy_label"]:
        sub = df[df.label_source == label_src].copy()
        if sub.empty:
            continue
        print(f"\n--- {label_src} ({sub.flow_id.nunique()} flows, {len(sub)} rows) ---")

        # Overall row-level
        y = sub.y.to_numpy()
        pred = sub.flagged.to_numpy()
        tp = int(((pred) & (y == 1)).sum())
        tn = int((~pred & (y == 0)).sum())
        fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum())
        print(f"Row-level: TP={tp} FP={fp} TN={tn} FN={fn} "
              f"recall={tp/(tp+fn) if (tp+fn) else 0:.3f} "
              f"FPR={fp/(fp+tn) if (fp+tn) else 0:.4f}")

        # Per-as_of flow-level ever-flagged
        print(f"\nPer as_of (flow-level ever-flagged @ {threshold}):")
        print(f"{'as_of':>8} {'n_flows':>8} {'attack_flagged':>14} {'attack_total':>13} "
              f"{'attack_recall':>12} {'benign_flagged':>14} {'benign_total':>13} {'benign_FPR':>10}")
        allowed = set()
        for aof in aof_order:
            allowed.add(aof)
            sub_aof = sub[sub.as_of.isin(allowed)]
            flows_aof = sub_aof.flow_id.unique()
            n_flows = len(flows_aof)
            attack_f = 0; attack_t = 0; benign_f = 0; benign_t = 0
            for fid in flows_aof:
                frows = sub_aof[sub_aof.flow_id == fid]
                truth = int(frows.iloc[0]["y"])
                flagged = bool(frows["flagged"].any())
                if truth == 1:
                    attack_t += 1
                    if flagged:
                        attack_f += 1
                else:
                    benign_t += 1
                    if flagged:
                        benign_f += 1
            ar = attack_f / attack_t if attack_t else 0
            bfpr = benign_f / benign_t if benign_t else 0
            print(f"{aof:>8} {n_flows:>8} {attack_f:>14} {attack_t:>13} "
                  f"{ar:>12.3f} {benign_f:>14} {benign_t:>13} {bfpr:>10.4f}")


def main():
    df = load_snapshots()
    print(f"Loaded snapshots: {len(df):,} rows, {df.flow_id.nunique()} flows")
    print(f"Label sources: {df.label_source.value_counts().to_dict()}")
    print(f"Flows with session: {df.session.notna().sum()}")

    ablation_table(df)
    zero_shot_baseline(df)


if __name__ == "__main__":
    main()
