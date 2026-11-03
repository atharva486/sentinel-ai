#!/usr/bin/env python3
from __future__ import annotations

import numpy as np
import xgboost as xgb
from sklearn.metrics import average_precision_score, roc_auc_score
from sklearn.model_selection import TimeSeriesSplit

from features import FEATURE_ORDER

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
    present = forbidden & set(X.columns)
    if present:
        raise AssertionError(
            f"LEAKAGE: {present} must not be features. "
            f"Forbidden set: {forbidden}"
        )


def train(
    X_train: "pd.DataFrame",
    y_train: "pd.Series",
    X_val: "pd.DataFrame",
    y_val: "pd.Series",
    feature_order: list | None = None,
    params: dict | None = None,
) -> "xgb.XGBClassifier":
    if feature_order is None:
        feature_order = FEATURE_ORDER

    if params is None:
        params = dict(
            n_estimators=400,
            max_depth=5,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric="aucpr",
            random_state=42,
            base_score=0.5,
        )

    X_train = X_train[feature_order]
    X_val = X_val[feature_order]

    leakage_guard(X_train)
    leakage_guard(X_val)

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

    params = dict(params)

    tscv = TimeSeriesSplit(n_splits=5)
    oof = np.zeros(len(y_train))
    for tr_idx, va_idx in tscv.split(X_train):
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

    model = xgb.XGBClassifier(**params)
    model.fit(X_train, y_train, eval_set=[(X_val, y_val)], verbose=False)

    val_scores = model.predict_proba(X_val)[:, 1]
    val_pr_auc = average_precision_score(y_val, val_scores)
    val_roc_auc = roc_auc_score(y_val, val_scores)
    print(f"Validation PR-AUC:   {val_pr_auc:.4f}")
    print(f"Validation ROC-AUC:  {val_roc_auc:.4f}")

    return model


if __name__ == "__main__":
    import sys
    import warnings
    import pandas as pd
    warnings.filterwarnings("ignore")

    if len(sys.argv) != 5:
        print(
            "Usage: python -m scoring.train_xgb X_train.csv y_train.csv "
            "X_val.csv y_val.csv"
        )
        sys.exit(2)

    X_train = pd.read_csv(sys.argv[1])
    y_train = pd.read_csv(sys.argv[2]).squeeze("columns")
    X_val = pd.read_csv(sys.argv[3])
    y_val = pd.read_csv(sys.argv[4]).squeeze("columns")

    model = train(X_train, y_train, X_val, y_val)
    print(f"Model trained with {model.n_estimators} estimators.")
