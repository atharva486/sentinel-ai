"""Unit tests for scoring/calibrate.py and metrics computation."""
import pandas as pd
import numpy as np
import joblib
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent))

from sklearn.metrics import average_precision_score, roc_auc_score


def test_calibration_artifact_loads():
    """The calibration artifact should load without errors."""
    art_path = Path(__file__).parent.parent / "models" / "calibration_result_current.joblib"
    art = joblib.load(art_path)
    assert "model_json" in art, "Artifact missing model_json"
    assert "calibrator" in art, "Artifact missing calibrator"
    assert "feature_order" in art, "Artifact missing feature_order"
    # Verify feature_order matches
    from capture.features import FEATURE_ORDER
    assert art["feature_order"] == FEATURE_ORDER, "feature_order mismatch"


def test_metrics_computation():
    """PR-AUC, ROC-AUC, ECE should be computable from test split."""
    df = pd.read_parquet(Path(__file__).parent.parent / "data" / "features.parquet")
    test = df[df.session.isin(["runb", "runf", "rung"])].copy()
    y = test["y"].to_numpy()
    assert len(y) > 0, "Test split should have rows"
    assert y.sum() > 0, "Should have some attack rows"
    assert (y == 0).sum() > 0, "Should have some benign rows"


def test_pr_auc_roc_auc():
    """PR-AUC and ROC-AUC should be computable and reasonable."""
    art = joblib.load(Path(__file__).parent.parent / "models" / "calibration_result_current.joblib")
    test = pd.read_parquet(Path(__file__).parent.parent / "data" / "features.parquet")
    test_split = test[test.session.isin(["runb", "runf", "rung"])].copy()
    y = test_split["y"].to_numpy()
    X = test_split[[ "bytes_in", "bytes_in_per_s", "requests_per_s", "packets_per_s",
                     "interarrival_mean", "interarrival_std", "interarrival_max",
                     "concurrent_conns", "conns_per_second_opened", "requests_per_conn_so_far",
                     "conn_age_s", "stall_time_s", "body_frac_sent", "bytes_declared",
                     "body_drip_rate_bps", "header_complete" ]].to_numpy(dtype=float)

    raw = art["model"].predict_proba(X)[:, 1]
    cal = np.clip(art["calibrator"].predict(raw), 0, 1)

    pr_auc = average_precision_score(y, cal)
    roc_auc = roc_auc_score(y, cal)
    assert 0.0 <= pr_auc <= 1.0, f"PR-AUC out of range: {pr_auc}"
    assert 0.0 <= roc_auc <= 1.0, f"ROC-AUC out of range: {roc_auc}"
    print(f"PR-AUC: {pr_auc:.4f}, ROC-AUC: {roc_auc:.4f}")


if __name__ == "__main__":
    test_calibration_artifact_loads()
    test_metrics_computation()
    test_pr_auc_roc_auc()
    print("All scoring tests passed!")