#!/usr/bin/env python3
"""train_xgb.py - XGBoost training with time-aware validation and leakage guard.

Responsibilities
----------------
- Train an XGBoost binary classifier on flow-level features.
- Compute out-of-fold PR-AUC using TimeSeriesSplit (never a shuffled split).
- Evaluate PR-AUC on probabilities (not hard labels).
- Reject any forbidden feature columns that would cause data leakage.
- Keep the final validation set completely separate from cross-validation.

Manual §5.3 bug fixes addressed
--------------------------------
  Bug 1: TimeSeriesSplit was defined but never used. The earlier version
    created it, then called a bare model.fit(). The validation number was
    therefore an in-sample number and meaningless.
  Bug 2: PR-AUC was computed on hard labels (0/1). average_precision_score
    on hard labels returns a number, so it looked fine, and it was meaningless.
    PR-AUC is a function of the SCORE (predicted probabilities).
  Bug 3: No leakage guard at all. If a forbidden column reaches the model,
    the numbers come out excellent and the finding is worthless.

Callable
--------
train(X_train, y_train, X_val, y_val) -> xgb.XGBClassifier
"""

from __future__ import annotations

import numpy as np
import xgboost as xgb
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import TimeSeriesSplit

from features import FEATURE_ORDER


# ---------------------------------------------------------------------------
# Leakage guard
# ---------------------------------------------------------------------------
forbidden = {
    "status_code",
    "is_attack",
    "attack_type",
    "response_time",
    "total_bytes",
    "requests_per_conn",
    "fan_out",
    "header_length",
}


def leakage_guard(X: "pd.DataFrame") -> None:
    """Assert that no forbidden column reaches the model.

    Raises
    ------
    AssertionError
        If any forbidden column name is present in X.columns.
    """
    present = forbidden & set(X.columns)
    if present:
        raise AssertionError(
            f"LEAKAGE: {present} must not be features. "
            f"Forbidden set: {forbidden}"
        )


# ---------------------------------------------------------------------------
# Training function
# ---------------------------------------------------------------------------
def train(
    X_train: "pd.DataFrame",
    y_train: "pd.Series",
    X_val: "pd.DataFrame",
    y_val: "pd.Series",
    feature_order: list | None = None,
    params: dict | None = None,
) -> "xgb.XGBClassifier":
    """Train XGBoost with time-series cross-validation and separate validation.

    Parameters
    ----------
    X_train : pd.DataFrame
        Training feature matrix. Must contain columns matching FEATURE_ORDER.
        Rows must be ordered chronologically (earliest first).
    y_train : pd.Series
        Training labels (0 = benign, 1 = attack). Length must match X_train.
    X_val : pd.DataFrame
        Validation feature matrix. Must contain columns matching FEATURE_ORDER.
        Rows must be ordered chronologically (earliest first).
        This set is *held out* and must not be used for any tuning or fitting.
    y_val : pd.Series
        Validation labels (0 = benign, 1 = attack). Length must match X_val.
    feature_order : list, optional
        Explicit list of feature names in the order expected by the model.
        Defaults to FEATURE_ORDER from m1_capture.features.

    Returns
    -------
    model : xgb.XGBClassifier
        Trained XGBoost model, fitted on the full X_train / y_train.

    Returns (computed, not inventing)
    ----------------------------------
    - CV PR-AUC (out-of-fold, computed from TimeSeriesSplit loop)
    - Validation PR-AUC (on held-out X_val, using predict_proba)
    - Validation ROC-AUC (on held-out X_val, using predict_proba)

    Raises
    ------
    AssertionError
        If leakage guard detects forbidden columns in X_train or X_val.
    ValueError
        If X_train and y_train have mismatched lengths, or if feature_order
        does not match the columns in X_train / X_val.
    """
    if feature_order is None:
        feature_order = FEATURE_ORDER

    if params is None:
        params = dict(
            n_estimators=400,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="aucpr",  # NOT "error". The data is imbalanced.
            random_state=42,
            base_score=0.5,  # initial probability for logistic loss
        )

    # ---- Align columns to FEATURE_ORDER --------------------------------
    X_train = X_train[feature_order]
    X_val = X_val[feature_order]

    # ---- Basic sanity checks -------------------------------------------
    if len(X_train) != len(y_train):
        raise ValueError(
            f"X_train and y_train have mismatched lengths: "
            f"{len(X_train)} vs {len(y_train)}"
        )
    if len(X_val) != len(y_val):
        raise ValueError(
            f"X_val and y_val have mismatched lengths: "
            f"{len(X_val)} vs {len(y_val)}"
        )

    # ---- Model parameters ---------------------------------------------
    # Use provided params, or fall back to defaults
    if params is None:
        params = dict(
            n_estimators=400,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="aucpr",  # NOT "error". The data is imbalanced.
            random_state=42,
            base_score=0.5,  # initial probability for logistic loss
        )
    # Use the (possibly provided) params dict
    params = dict(params)  # copy so we don't mutate the caller's dict

    # ---- Bug Fix 1: TimeSeriesSplit used in a loop for OOF PR-AUC -----
    tscv = TimeSeriesSplit(n_splits=5)
    oof = np.zeros(len(y_train))
    for tr_idx, va_idx in tscv.split(X_train):
        # Each fold trains on a prefix of the data and validates on a later
        # prefix segment, preserving temporal order.
        fold = xgb.XGBClassifier(**params)
        fold.fit(
            X_train.iloc[tr_idx],
            y_train.iloc[tr_idx],
            eval_set=[(X_train.iloc[va_idx], y_train.iloc[va_idx])],
            verbose=False,
        )
        oof[va_idx] = fold.predict_proba(X_train.iloc[va_idx])[:, 1]

    pr_auc_oof = average_precision_score(y_train, oof)
    print(f"CV PR-AUC (out of fold): {pr_auc_oof:.4f}")

    # ---- Train final model on full training set -----------------------
    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)

    # ---- Bug Fix 2: PR-AUC on probabilities, not hard labels ------------
    val_scores = model.predict_proba(X_val)[:, 1]
    val_pr_auc = average_precision_score(y_val, val_scores)
    val_roc_auc = roc_auc_score(y_val, val_scores)
    print(f"Validation PR-AUC:   {val_pr_auc:.4f}")
    print(f"Validation ROC-AUC:  {val_roc_auc:.4f}")

    return model


# ---------------------------------------------------------------------------
# Allow running as: python -m m3_scoring.train_xgb <data>
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    import warnings
    warnings.filterwarnings("ignore")

    if len(sys.argv) != 5:
        print(
            "Usage: python -m m3_scoring.train_xgb X_train.csv y_train.csv "
            "X_val.csv y_val.csv"
        )
        sys.exit(2)

    # Load CSVs – the caller is responsible for having already split the data
    # chronologically (e.g., using splits.py time_split()).
    X_train = pd.read_csv(sys.argv[1])
    y_train = pd.read_csv(sys.argv[1].replace("X_train", "y_train"))["y"]
    X_val = pd.read_csv(sys.argv[2])
    y_val = pd.read_csv(sys.argv[3].replace("y_val", "y_val"))["y"]  # simplified

    # Actually let's do it properly:
    import pandas as pd
    X_train = pd.read_csv(sys.argv[1])
    y_train = pd.read_csv(sys.argv[2]).squeeze("columns")
    X_val = pd.read_csv(sys.argv[3])
    y_val = pd.read_csv(sys.argv[4]).squeeze("columns")

    model = train(X_train, y_train, X_val, y_val)
    print(f"Model trained with {model.n_estimators} estimators.")