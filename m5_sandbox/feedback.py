#!/usr/bin/env python3
"""feedback.py — Active learning loop using sandbox replay as a ground-truth label source.

Manual Part 7 §7.2:
- Replay is a LABEL SOURCE, not a feature source.
- Flow quarantine target: UNCERTAIN band (0.30 <= score <= 0.80).
- Replay at original speed against sandbox-backend -> did it do damage? -> label.
- Retrain Module 3 XGBoost with augmented labels.
- Measure on HELD-OUT data — never on the replayed flows themselves.
"""
from __future__ import annotations

import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, roc_auc_score

# Ensure project modules are importable
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("./m1_capture"))
sys.path.insert(0, os.path.abspath("./m3_scoring"))

from m1_capture.features import FEATURE_ORDER
from m3_scoring.calibrate import CalibrationResult, calibrate
from m3_scoring.train_xgb import leakage_guard, train as train_xgb
from m5_sandbox.replay import SANDBOX, is_uncertain, replay_sync


def extract_uncertain_flows(
    df: pd.DataFrame,
    artifact: CalibrationResult,
    n_recent: int = 200,
) -> List[Dict[str, Any]]:
    """Identify flows falling into the uncertain score band (0.30 <= score <= 0.80).

    Parameters
    ----------
    df : pd.DataFrame
        DataFrame containing flows with columns in FEATURE_ORDER.
    artifact : CalibrationResult
        Calibrated model artifact used to compute flow suspicion scores.
    n_recent : int
        Maximum number of uncertain flows to sample.

    Returns
    -------
    list of dict
        Flow feature dictionaries for uncertain flows.
    """
    leakage_guard(df)
    uncertain_rows = []

    # Iterate chronologically (newest first or tail)
    for idx, row in df.iterrows():
        flow_dict = row.to_dict()
        score = artifact.calibrated_score(flow_dict)
        if is_uncertain(score):
            flow_dict["_pre_replay_score"] = score
            flow_dict["flow_id"] = str(flow_dict.get("flow_id", f"flow_{idx}"))
            uncertain_rows.append(flow_dict)
            if len(uncertain_rows) >= n_recent:
                break

    return uncertain_rows


def label_from_replay(
    flows: List[Dict[str, Any]],
    sandbox_url: str = SANDBOX,
    replay_fn: Optional[Callable[[Union[Dict[str, Any], FlowRecord]], Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Replay uncertain flows at original speed and assign label based on damage.

    Parameters
    ----------
    flows : list of dict
        Candidate uncertain flows to replay.
    sandbox_url : str
        Target sandbox URL.
    replay_fn : callable, optional
        Custom replay function for testing and simulation hooks.

    Returns
    -------
    list of dict
        Each dict contains original features plus 'y' (1 if caused_damage, else 0).
    """
    labeled_records = []
    for fl in flows:
        if replay_fn is not None:
            replay_res = replay_fn(fl)
        else:
            replay_res = replay_sync(fl, sandbox_url=sandbox_url)
        caused_damage = bool(replay_res.get("caused_damage", False))
        record = dict(fl)
        record["y"] = 1 if caused_damage else 0
        record["_replay_duration_s"] = replay_res.get("replay_duration_s", 0.0)
        record["_replay_damage"] = caused_damage
        labeled_records.append(record)
    return labeled_records


def evaluate_on_heldout(
    model: Any,
    calibrator: Any,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    threshold: float = 0.5,
) -> Dict[str, float]:
    """Evaluate calibrated model performance strictly on held-out data.

    Returns
    -------
    dict
        {"pr_auc": float, "roc_auc": float, "macro_f1": float, "fpr": float}
    """
    leakage_guard(X_val)
    X_aligned = X_val[FEATURE_ORDER]
    raw_probs = model.predict_proba(X_aligned)[:, 1]
    cal_probs = calibrator.predict(raw_probs)
    cal_probs = np.clip(cal_probs, 0.0, 1.0)

    yhat = (cal_probs >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_val, yhat).ravel()
    fpr = float(fp / max(1, fp + tn))

    return {
        "pr_auc": float(average_precision_score(y_val, cal_probs)),
        "roc_auc": float(roc_auc_score(y_val, cal_probs)),
        "macro_f1": float(f1_score(y_val, yhat, average="macro")),
        "fpr": fpr,
    }


def retrain_with_labels(
    base_X_train: pd.DataFrame,
    base_y_train: pd.Series,
    new_labeled_flows: List[Dict[str, Any]],
    X_cal: pd.DataFrame,
    y_cal: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    params: Optional[Dict[str, Any]] = None,
) -> Tuple[Any, Any]:
    """Augment training set with newly labeled flows, retrain XGBoost and recalibrate.

    Guarantees:
    - Never trains or calibrates on the held-out validation set.
    - Preserves exact FEATURE_ORDER and checks leakage.
    """
    if new_labeled_flows:
        new_df = pd.DataFrame(new_labeled_flows)
        new_X = new_df[[col for col in FEATURE_ORDER if col in new_df.columns]].copy()
        # Fill any missing feature with 0.0
        for col in FEATURE_ORDER:
            if col not in new_X.columns:
                new_X[col] = 0.0
        new_X = new_X[FEATURE_ORDER]
        new_y = new_df["y"].astype(int)

        aug_X_train = pd.concat([base_X_train[FEATURE_ORDER], new_X], ignore_index=True)
        aug_y_train = pd.concat([base_y_train, new_y], ignore_index=True)
    else:
        aug_X_train = base_X_train[FEATURE_ORDER].copy()
        aug_y_train = base_y_train.copy()

    # Retrain model via Module 3
    new_model = train_xgb(
        X_train=aug_X_train,
        y_train=aug_y_train,
        X_val=X_val[FEATURE_ORDER],
        y_val=y_val,
        params=params,
    )

    # Recalibrate via Module 3
    cal_res = calibrate(new_model, X_cal[FEATURE_ORDER], y_cal)
    return new_model, cal_res.calibrator


def close_the_loop(
    base_X_train: pd.DataFrame,
    base_y_train: pd.Series,
    X_cal: pd.DataFrame,
    y_cal: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    candidate_flows_df: pd.DataFrame,
    artifact: CalibrationResult,
    n_recent: int = 200,
    sandbox_url: str = SANDBOX,
    replay_fn: Optional[Callable[[Union[Dict[str, Any], FlowRecord]], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Execute the full feedback loop workflow per Manual §7.2.

    1. Take UNCERTAIN quarantined flows (0.30 <= score <= 0.80)
    2. Replay them at original speed against sandbox
    3. Use did-damage as the LABEL
    4. Retrain
    5. Measure on HELD-OUT data — never on the replayed flows themselves

    Returns
    -------
    dict
        Before/after evaluation comparison table.
    """
    # 0. Measure performance BEFORE retraining
    before = evaluate_on_heldout(artifact.model, artifact.calibrator, X_val, y_val)

    # 1. Take UNCERTAIN quarantined flows
    uncertain = extract_uncertain_flows(candidate_flows_df, artifact, n_recent=n_recent)

    if not uncertain:
        return {
            "flows_replayed": 0,
            "damaged": 0,
            "pr_auc_before": before["pr_auc"],
            "pr_auc_after": before["pr_auc"],
            "improvement": 0.0,
            "fpr_before": before["fpr"],
            "fpr_after": before["fpr"],
            "status": "No uncertain flows found to replay",
        }

    # 2 & 3. Replay at original speed -> did-damage is the LABEL
    labeled_rows = label_from_replay(uncertain, sandbox_url=sandbox_url, replay_fn=replay_fn)

    # 4. Retrain
    new_model, new_calibrator = retrain_with_labels(
        base_X_train=base_X_train,
        base_y_train=base_y_train,
        new_labeled_flows=labeled_rows,
        X_cal=X_cal,
        y_cal=y_cal,
        X_val=X_val,
        y_val=y_val,
    )

    # 5. Measure on HELD-OUT data
    after = evaluate_on_heldout(new_model, new_calibrator, X_val, y_val)

    report = {
        "flows_replayed": len(labeled_rows),
        "damaged": sum(r["_replay_damage"] for r in labeled_rows),
        "pr_auc_before": before["pr_auc"],
        "pr_auc_after": after["pr_auc"],
        "improvement": after["pr_auc"] - before["pr_auc"],
        "fpr_before": before["fpr"],
        "fpr_after": after["fpr"],
    }
    return report


if __name__ == "__main__":
    print("=" * 70)
    print("MODULE 5: ACTIVE LEARNING FEEDBACK LOOP (§7.2)")
    print("=" * 70)
    artifact = CalibrationResult.load("calibration_result_candidate.joblib")
    X_tr = pd.read_csv("data/X_train.csv")[FEATURE_ORDER]
    y_tr = pd.read_csv("data/y_train.csv").squeeze("columns")
    X_c = pd.read_csv("data/X_cal.csv")[FEATURE_ORDER]
    y_c = pd.read_csv("data/y_cal.csv").squeeze("columns")
    X_v = pd.read_csv("data/X_val.csv")[FEATURE_ORDER]
    y_v = pd.read_csv("data/y_val.csv").squeeze("columns")

    rep = close_the_loop(
        base_X_train=X_tr,
        base_y_train=y_tr,
        X_cal=X_c,
        y_cal=y_c,
        X_val=X_v,
        y_val=y_v,
        candidate_flows_df=X_tr,
        artifact=artifact,
        n_recent=50,
    )
    print("\nFeedback Loop Report:")
    for k, v in rep.items():
        if isinstance(v, float):
            print(f"  {k:<16}: {v:.4f}")
        else:
            print(f"  {k:<16}: {v}")
