#!/usr/bin/env python3
from __future__ import annotations

from typing import Dict, List

import numpy as np
import shap

from features import FEATURE_ORDER


def explain(model, flow_features: dict) -> dict:
    row = np.array(
        [float(flow_features.get(k, 0.0)) for k in FEATURE_ORDER],
        dtype=np.float64,
    )

    explainer = shap.TreeExplainer(model)
    row_2d = row.reshape(1, -1)
    shap_values = explainer.shap_values(row_2d)

    if shap_values is None:
        raise RuntimeError("SHAP returned None")

    if isinstance(shap_values, list):
        if len(shap_values) == 2 and isinstance(shap_values[1], np.ndarray):
            values = shap_values[1]
        else:
            raise RuntimeError(f"Unexpected SHAP list shape: {shap_values}")
    elif shap_values.ndim == 2:
        if shap_values.shape[0] == 1:
            values = shap_values[0]
        else:
            values = shap_values[0]
    elif shap_values.ndim == 1:
        values = shap_values
    else:
        raise RuntimeError(f"Unexpected SHAP values ndim: {shap_values.ndim}, "
                           f"shape: {getattr(shap_values, 'shape', '?')}")

    if len(values) != len(FEATURE_ORDER):
        if len(values) < len(FEATURE_ORDER):
            values = np.pad(values, (0, len(FEATURE_ORDER) - len(values)),
                            mode='constant', constant_values=0.0)
        else:
            values = values[:len(FEATURE_ORDER)]

    result: dict = {}
    for i, name in enumerate(FEATURE_ORDER):
        val = float(values[i])
        if not np.isfinite(val):
            raise ValueError(
                f"SHAP value for feature '{name}' is not finite: {val}. "
                "SHAP output must be finite scalar numbers."
            )
        result[name] = val

    return result


def top_k(shap_values: dict, k: int = 5) -> List[tuple]:
    if not isinstance(shap_values, dict):
        raise TypeError("top_k expects a dict, got: " + type(shap_values).__name__)
    if k < 1:
        raise ValueError("k must be >= 1, got: " + str(k))
    items = list(shap_values.items())
    if k < len(items):
        items = sorted(items, key=lambda kv: -abs(kv[1]))[:k]
    else:
        items = sorted(items, key=lambda kv: -abs(kv[1]))
    return items


def build_flow_dict(**kwargs) -> dict:
    return {k: float(kwargs.get(k, 0.0)) for k in FEATURE_ORDER}
