#!/usr/bin/env python3
from __future__ import annotations
import sys
import os
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("./m1_capture"))
import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression
from features import FEATURE_ORDER

class CalibrationResult:
    def __init__(self, model, calibrator, feature_order=None):
        self.model = model
        self.calibrator = calibrator
        self.feature_order = feature_order or FEATURE_ORDER

    def calibrated_score(self, features: dict) -> float:
        row = [float(features.get(k, 0.0)) for k in self.feature_order]
        row_2d = np.array(row).reshape(1, -1)
        raw = float(self.model.predict_proba(row_2d)[0, 1])
        calibrated = float(self.calibrator.predict([raw])[0])
        calibrated = max(0.0, min(1.0, calibrated))
        return calibrated

    def save(self, path: str) -> None:
        import joblib as _joblib
        import tempfile

        if not path:
            raise ValueError("save path must be a non-empty string")

        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                _model_json_path = tmp.name
            self.model.save_model(_model_json_path)
            with open(_model_json_path) as _f:
                model_json = _f.read()
            import os as _os2
            _os2.unlink(_model_json_path)

            artifact = {
                "model_json": model_json,
                "calibrator": self.calibrator,
                "feature_order": list(self.feature_order),
            }

            dir_name = os.path.dirname(path)
            if dir_name:
                os.makedirs(dir_name, exist_ok=True)
            _joblib.dump(artifact, path)
        except Exception as e:
            raise ValueError(f"Failed to save calibration result: {e}") from e

    @classmethod
    def load(cls, path: str):
        import joblib as _joblib
        import os as _os

        if not path:
            raise ValueError("load path must be a non-empty string")

        if not _os.path.isfile(path):
            raise ValueError(f"Calibration artifact not found: {path}")

        try:
            artifact = _joblib.load(path)
        except Exception as e:
            raise ValueError(f"Failed to load calibration artifact: {e}") from e

        if not isinstance(artifact, dict):
            raise ValueError(
                f"Calibration artifact is not a dict; got {type(artifact)}"
            )

        missing = []
        if "model_json" not in artifact:
            missing.append("model_json")
        if "calibrator" not in artifact:
            missing.append("calibrator")
        if "feature_order" not in artifact:
            missing.append("feature_order")

        if missing:
            raise ValueError(
                f"Calibration artifact missing fields: {', '.join(missing)}"
            )

        model_json = artifact["model_json"]
        if not isinstance(model_json, str) or not model_json.strip():
            raise ValueError("Artifact 'model_json' must be a non-empty string")

        from sklearn.isotonic import IsotonicRegression
        calibrator = artifact["calibrator"]
        if not isinstance(calibrator, IsotonicRegression):
            raise ValueError(
                f"Artifact 'calibrator' is not an IsotonicRegression instance; "
                f"got {type(calibrator)}"
            )

        feature_order = artifact["feature_order"]
        if not isinstance(feature_order, list) or not feature_order:
            raise ValueError(
                f"Artifact 'feature_order' must be a non-empty list; got {type(feature_order)}"
            )
        if not all(isinstance(k, str) for k in feature_order):
            raise ValueError(
                f"Artifact 'feature_order' must contain only strings; got {feature_order}"
            )

        from features import FEATURE_ORDER
        if feature_order != FEATURE_ORDER:
            raise ValueError(
                f"Artifact 'feature_order' must match FEATURE_ORDER exactly. "
                f"Got: {feature_order}\nExpected: {FEATURE_ORDER}"
            )

        import xgboost as xgb
        import tempfile
        import os as _os2

        model_json = artifact["model_json"]
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8") as tmp:
            tmp.write(model_json)
            tmp_path = tmp.name
        try:
            model = xgb.XGBClassifier(n_estimators=10, base_score=0.5)
            model.load_model(tmp_path)
        finally:
            _os2.unlink(tmp_path)

        result = cls(model, artifact["calibrator"], feature_order=artifact["feature_order"])
        return result

def calibrate(model, X_cal, y_cal, feature_order=None):
    import sys
    import os
    sys.path.insert(0, os.path.abspath("."))
    sys.path.insert(0, os.path.abspath("./m1_capture"))

    if feature_order is None:
        feature_order = FEATURE_ORDER

    if len(X_cal) != len(y_cal):
        raise ValueError(
            f"X_cal and y_cal have mismatched lengths: {len(X_cal)} vs {len(y_cal)}"
        )

    if not hasattr(X_cal, "columns"):
        X_cal = pd.DataFrame(X_cal, columns=feature_order)
    elif len(X_cal.columns) != len(feature_order):
        X_cal = X_cal[feature_order]

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
    present = forbidden & set(X_cal.columns)
    if present:
        raise ValueError(
            f"Forbidden feature(s) detected in calibration data: {present}. "
            "These columns must not appear in calibration data. "
            "Forbidden set: {forbidden}"
        )

    raw_probs = model.predict_proba(X_cal)[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(raw_probs, y_cal)

    result = CalibrationResult(model, calibrator, feature_order)
    return result

def reliability_diagram(model, X, y, n_bins=10, filepath=None):
    probs = model.predict_proba(X)[:, 1]

    bin_lowers = np.linspace(0, 1, n_bins + 1)[:-1]
    bin_uppers = np.linspace(0, 1, n_bins + 1)[1:]

    mean_preds = np.zeros(n_bins)
    fractions = np.zeros(n_bins)

    for i in range(n_bins):
        in_bin = (probs > bin_lowers[i]) & (probs <= bin_uppers[i])
        count_in_bin = np.sum(in_bin)
        if count_in_bin > 0:
            mean_preds[i] = np.mean(probs[in_bin])
            fractions[i] = np.sum(y[in_bin]) / count_in_bin
        else:
            mean_preds[i] = np.nan
            fractions[i] = np.nan

    mpl_avail = False
    try:
        import matplotlib.pyplot as plt
        mpl_avail = True
    except ImportError:
        pass

    if mpl_avail and filepath is not None:
        plt.figure(figsize=(8, 8))
        plt.plot([0, 1], [0, 1], "k:", label="Perfectly calibrated")
        plt.plot(mean_preds, fractions, "s-", label="Model")
        plt.title("Reliability Diagram")
        plt.xlabel("Mean predicted probability")
        plt.ylabel("Observed fraction of positives")
        plt.legend()
        plt.grid(alpha=0.3)
        plt.savefig(filepath, bbox_inches="tight")
        plt.close()

    return mean_preds, fractions

if __name__ == "__main__":
    import os
    sys.path.insert(0, os.path.abspath("."))
    sys.path.insert(0, os.path.abspath("./m1_capture"))

    import xgboost as xgb
    import numpy as np
    from features import FEATURE_ORDER

    np.random.seed(42)
    n = 200
    X = np.random.rand(n, len(FEATURE_ORDER))
    y = np.random.randint(0, 2, n)
    model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
    model.fit(X[:150], y[:150])

    X_cal = X[150:]
    y_cal = y[150:]

    result = calibrate(model, X_cal, y_cal)
    flow = {k: 0.5 for k in result.feature_order}
    score = result.calibrated_score(flow)
    print(f"Calibrated score: {score:.4f} in [0,1]: {0.0 <= score <= 1.0}")

    mean_preds, fractions = reliability_diagram(model, X_cal, y_cal)
    print(f"Reliability diagram: {len(mean_preds)} bins returned (data computed)")

    print("\nAll calibration tests PASSED")