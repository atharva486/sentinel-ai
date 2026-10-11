#!/usr/bin/env python3
"""explain.py - Full per-instance SHAP explanations.

Manual §5.5 requirement:
  Return the FULL {feature: shap_value} mapping, not a top-k list.
  Why this changed: Module 4's group-sum ablation needs to sum SHAP over
  every feature in each group. Passing only top-k made that impossible —
  the ablation could not be run at all.

Use shap.TreeExplainer, not LIME. TreeExplainer is exact for tree models
and takes microseconds. LIME is a slow approximation that gives different
answers on repeated runs of the same input — unacceptable when the output
drives a defence decision.

Call signature:
    explain(model, flow_features) -> dict

Returns a dict mapping every feature in FEATURE_ORDER to its SHAP value.
Optional: top_k(shap_values, k=5) returns the highest-|SHAP| entries for
display only; it does not modify or replace the full dictionary.
"""

from __future__ import annotations

from typing import Dict, List

import numpy as np
import shap

from features import FEATURE_ORDER


# ---------------------------------------------------------------------------
# Full SHAP explanation
# ---------------------------------------------------------------------------
def explain(model, flow_features: dict) -> dict:
    """Per-instance SHAP: which features pushed THIS prediction.

    Returns the FULL {feature: shap_value} mapping keyed by FEATURE_ORDER.

    Parameters
    ----------
    model : xgb.Booster or xgb.XGBClassifier
        A trained XGBoost model.
    flow_features : dict
        Feature dict with keys that should match FEATURE_ORDER. Missing keys
        are treated as 0.0; extra keys are ignored.

    Returns
    -------
    dict
        Mapping feature_name -> shap_value for ALL features in FEATURE_ORDER.
        Every value is a finite scalar float.
    """
    # Build the row aligned to FEATURE_ORDER, treating missing features as 0.0
    row = np.array(
        [float(flow_features.get(k, 0.0)) for k in FEATURE_ORDER],
        dtype=np.float64,
    )

    # Compute SHAP values using TreeExplainer (exact for tree models)
    explainer = shap.TreeExplainer(model)
    # shap.TreeExplainer.shap_values expects a 2D array with shape (1, n_features)
    row_2d = row.reshape(1, -1)
    shap_values = explainer.shap_values(row_2d)

    # For binary classification, shap_values may be a 2D array or a list.
    # We need the per-feature values for the attack class (class 1).
    # Handle several common return shapes:
    #   - 1D array of length n_features (when model is already reduced to one class)
    #   - 2D array of shape (1, n_features) or (n_features,)
    #   - list of 2 arrays [base_values, per_feature_values]
    if shap_values is None:
        raise RuntimeError("SHAP returned None — model may not be fitted or "
                           "is incompatible with TreeExplainer")

    # Normalize to a 1D array of per-feature SHAP values for class 1
    if isinstance(shap_values, list):
        # shap.TreeExplainer sometimes returns [base, values]
        if len(shap_values) == 2 and isinstance(shap_values[1], np.ndarray):
            values = shap_values[1]
        else:
            raise RuntimeError(f"Unexpected SHAP list shape: {shap_values}")
    elif shap_values.ndim == 2:
        # Shape (1, n_features) or (n_samples, n_features) — take first row
        if shap_values.shape[0] == 1:
            values = shap_values[0]
        else:
            # If multiple samples, take the first; our caller always passes one row
            values = shap_values[0]
    elif shap_values.ndim == 1:
        values = shap_values
    else:
        raise RuntimeError(f"Unexpected SHAP values ndim: {shap_values.ndim}, "
                           f"shape: {getattr(shap_values, 'shape', '?')}")

    # Ensure we have exactly len(FEATURE_ORDER) values
    if len(values) != len(FEATURE_ORDER):
        # If we got fewer, pad with 0.0; if more, truncate
        if len(values) < len(FEATURE_ORDER):
            values = np.pad(values, (0, len(FEATURE_ORDER) - len(values)),
                            mode='constant', constant_values=0.0)
        else:
            values = values[:len(FEATURE_ORDER)]

    # Build the dict mapping FEATURE_ORDER -> SHAP value
    result: dict = {}
    for i, name in enumerate(FEATURE_ORDER):
        val = float(values[i])
        # Explicitly check for finiteness (reject NaN/Inf)
        if not np.isfinite(val):
            raise ValueError(
                f"SHAP value for feature '{name}' is not finite: {val}. "
                "SHAP output must be finite scalar numbers."
            )
        result[name] = val

    return result


# ---------------------------------------------------------------------------
# Optional display helper: top-k by |SHAP value|
# ---------------------------------------------------------------------------
def top_k(shap_values: dict, k: int = 5) -> List[tuple]:
    """Return the k features with highest |SHAP value| for display.

    Does NOT modify or replace the full dictionary returned by explain().

    Parameters
    ----------
    shap_values : dict
        Full dict from explain(), keyed by feature name.
    k : int
        Number of entries to return. If k > len(shap_values), returns all.

    Returns
    -------
    list of (feature, shap_value) tuples, sorted by |SHAP| descending.
    """
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


# ---------------------------------------------------------------------------
# Convenience: build a flow_features dict from the 20 features
# ---------------------------------------------------------------------------
def build_flow_dict(**kwargs) -> dict:
    """Produce a flow_features dict aligned to FEATURE_ORDER.

    Useful for testing: pass exactly the 20 feature names as keyword args;
    missing keys default to 0.0.
    """
    return {k: float(kwargs.get(k, 0.0)) for k in FEATURE_ORDER}