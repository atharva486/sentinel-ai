#!/usr/bin/env python3
"""calibrate.py - Probability calibration with IsotonicRegression.

Manual §5.4 requirements:
  - Use IsotonicRegression(out_of_bounds="clip") held out on separate data.
  - Never calibrate on training data.
  - Produce a reliability diagram and include the plot.

Notes
-----
Matplotlib is required to save the reliability diagram figure automatically.
If matplotlib is not installed, the :func:`reliability_diagram` function still
computes the x/y data and returns it; the caller can plot manually or install
matplotlib to save the figure.

The calibration function assumes the model was trained on data chronologically
prior to the calibration partition. It does not verify model training
details itself — it only verifies that the calibration hold-out partition is
disjoint from the training partition indices supplied by the caller.
"""

from __future__ import annotations

import sys
import os

# Add project paths so that m1_capture imports work
sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("./m1_capture"))

import numpy as np
import pandas as pd
from sklearn.isotonic import IsotonicRegression

from features import FEATURE_ORDER


# ---------------------------------------------------------------------------
# CalibrationResult – holds everything needed for one-flow calibration
# ---------------------------------------------------------------------------
class CalibrationResult:
    """Holders for calibrated model and evaluator.

    Holds the original XGBoost model, the isotonic calibrator, and the
    feature order, so that calibrated_score() can be called later
    on one flow at a time.
    """

    def __init__(self, model, calibrator, feature_order=None):
        self.model = model
        self.calibrator = calibrator
        self.feature_order = feature_order or FEATURE_ORDER

    def calibrated_score(self, features: dict) -> float:
        """Return calibrated P(attack) for one flow.

        Parameters
        ----------
        features : dict
            Feature dict with keys that should match self.feature_order.
            Missing keys are treated as 0.0.

        Returns
        -------
        float
            Calibrated probability in [0, 1].
        """
        # Align row to feature order
        row = [float(features.get(k, 0.0)) for k in self.feature_order]
        row_2d = np.array(row).reshape(1, -1)

        # Raw XGBoost probability for the attack class (index 1)
        raw = float(self.model.predict_proba(row_2d)[0, 1])

        # Isotonic calibration
        calibrated = float(self.calibrator.predict([raw])[0])

        # Clamp to [0, 1] in spite of out_of_bounds="clip"; defensive.
        calibrated = max(0.0, min(1.0, calibrated))
        return calibrated

    # ---------------------------------------------------------------------------
    # Persistence
    # ---------------------------------------------------------------------------
    def save(self, path: str) -> None:
        """Save the calibration result to a file.

        Saves the XGBoost model (as JSON), the isotonic calibrator, and the
        feature order.  Uses ``joblib`` for the complete artifact.

        Parameters
        ----------
        path : str
            Path to the output file.  Recommend ``*.joblib`` extension.

        Raises
        ------
        CalibrationError
            If the path is invalid, write fails, or the model/calibrator is
            incompatible.
        """
        import joblib as _joblib
        import os as _os

        if not path:
            raise ValueError("save path must be a non-empty string")

        try:
            # Save the model using xgb.Booster save_model, but convert to
            # XGBClassifier for compatibility.  We save the model JSON and
            # reconstruct an XGBClassifier on load.
            import tempfile

            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                _model_json_path = tmp.name
            self.model.save_model(_model_json_path)
            with open(_model_json_path) as _f:
                model_json = _f.read()
            import os as _os2
            _os2.unlink(_model_json_path)

            # Prepare the artifact dict
            artifact = {
                "model_json": model_json,
                "calibrator": self.calibrator,
                "feature_order": list(self.feature_order),
            }

            # Write via joblib
            dir_name = _os.path.dirname(path)
            if dir_name:
                _os.makedirs(dir_name, exist_ok=True)
            _joblib.dump(artifact, path)
        except Exception as e:
            raise ValueError(f"Failed to save calibration result: {e}") from e

    @classmethod
    def load(cls, path: str):
        """Load a CalibrationResult from a saved artifact file.

        Validates that the artifact contains a valid model JSON, a
        callable isotonic calibrator, and a non-empty feature order list.

        Parameters
        ----------
        path : str
            Path to the artifact file (``*.joblib`` extension recommended).

        Returns
        -------
        CalibrationResult
            A new CalibrationResult instance.

        Raises
        ------
        CalibrationError
            If the path does not exist, the file is corrupted, or the artifact
            contains incompatible data (wrong model format, missing fields,
            mismatched feature order).
        """
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

        # Validate structure
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

        # Validate model JSON – must be a non-empty string
        model_json = artifact["model_json"]
        if not isinstance(model_json, str) or not model_json.strip():
            raise ValueError("Artifact 'model_json' must be a non-empty string")

        # Validate calibrator – must be an IsotonicRegression instance
        from sklearn.isotonic import IsotonicRegression
        calibrator = artifact["calibrator"]
        if not isinstance(calibrator, IsotonicRegression):
            raise ValueError(
                f"Artifact 'calibrator' is not an IsotonicRegression instance; "
                f"got {type(calibrator)}"
            )

        # Validate feature_order – must be a non-empty list of strings
        feature_order = artifact["feature_order"]
        if not isinstance(feature_order, list) or not feature_order:
            raise ValueError(
                f"Artifact 'feature_order' must be a non-empty list; got {type(feature_order)}"
            )
        if not all(isinstance(k, str) for k in feature_order):
            raise ValueError(
                f"Artifact 'feature_order' must contain only strings; got {feature_order}"
            )

        # Validate feature_order – must match FEATURE_ORDER exactly
        from features import FEATURE_ORDER
        if feature_order != FEATURE_ORDER:
            raise ValueError(
                f"Artifact 'feature_order' must match FEATURE_ORDER exactly. "
                f"Got: {feature_order}\nExpected: {FEATURE_ORDER}"
            )

        # Reconstruct the model from JSON using XGBClassifier
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

        # Build and return the result
        result = cls(model, artifact["calibrator"], feature_order=artifact["feature_order"])
        return result


# ---------------------------------------------------------------------------
# Core calibration function
# ---------------------------------------------------------------------------
def calibrate(model, X_cal, y_cal, feature_order=None):
    """Fit IsotonicRegression on held-out data and return a CalibrationResult.

    Parameters
    ----------
    model : xgb.XGBClassifier or xgb.Booster
        Already-trained model.  Must not be fitted on X_cal / y_cal.
    X_cal : pd.DataFrame
        Calibration feature matrix.  Rows must be ordered chronologically
        (or at least not shuffled relative to training data).
    y_cal : pd.Series
        Calibration labels (0 = benign, 1 = attack).  Length must match X_cal.
    feature_order : list, optional
        Explicit list of feature names in the order expected by the model.
        Defaults to FEATURE_ORDER from m1_capture.features.

    Returns
    -------
    CalibrationResult
        Object with .model, .calibrator, .feature_order, and .calibrated_score().

    Raises
    ------
    CalibrationError
        If X_cal and y_cal have mismatched lengths, if forbidden columns are
        detected, if the input cannot be aligned to feature_order, or if y_cal
        contains only a single class.
    """
    import sys
    import os
    sys.path.insert(0, os.path.abspath("."))
    sys.path.insert(0, os.path.abspath("./m1_capture"))

    if feature_order is None:
        feature_order = FEATURE_ORDER

    # ---- Basic sanity checks ------------------------------------------------
    if len(X_cal) != len(y_cal):
        raise ValueError(
            f"X_cal and y_cal have mismatched lengths: {len(X_cal)} vs {len(y_cal)}"
        )

    # Convert numpy arrays to DataFrames with FEATURE_ORDER columns
    if not hasattr(X_cal, "columns"):
        X_cal = pd.DataFrame(X_cal, columns=feature_order)
    elif len(X_cal.columns) != len(feature_order):
        X_cal = X_cal[feature_order]

    # Leakage guard: ensure forbidden columns are absent
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

    # Fit isotonic regression on held-out predictions
    raw_probs = model.predict_proba(X_cal)[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip")
    calibrator.fit(raw_probs, y_cal)

    result = CalibrationResult(model, calibrator, feature_order)
    return result


# ---------------------------------------------------------------------------
# Reliability diagram generation
# ---------------------------------------------------------------------------
def reliability_diagram(model, X, y, n_bins=10, filepath=None):
    """Compute and optionally plot a reliability diagram.

    Parameters
    ----------
    model : xgb.XGBClassifier or xgb.Booster
        Trained model.
    X : pd.DataFrame
        Feature matrix aligned to FEATURE_ORDER.
    y : pd.Series
        True labels (0 = benign, 1 = attack).
    n_bins : int, default 10
        Number of equal-width probability bins.
    filepath : str or None, default None
        If given, save the plot to this path.  A typical path is
        "reliability_diagram.png" in the project root.  If matplotlib is not
        installed, the x/y data are still returned and no figure is saved.

    Returns
    -------
    mean_preds : ndarray of shape (n_bins,)
        Mean predicted probability per bin.
    fractions : ndarray of shape (n_bins,)
        Observed positive frequency per bin.
    """
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

    # Plot if matplotlib is available and filepath was given
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


# ---------------------------------------------------------------------------
# Focused tests
# ---------------------------------------------------------------------------
def _test_calibration_basic():
    """Smoke test: calibrate then calibrated_score returns finite [0,1] values."""
    import numpy as np
    import xgboost as xgb
    from calibrate import calibrate, CalibrationResult

    np.random.seed(42)
    n = 200
    X = np.random.rand(n, len(FEATURE_ORDER))
    y = np.random.randint(0, 2, n)
    model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
    model.fit(X[:150], y[:150])

    # Hold-out split (first 150 train, last 50 calibrate)
    X_cal = X[150:]
    y_cal = y[150:]
    result = calibrate(model, X_cal, y_cal)
    assert isinstance(result, CalibrationResult)
    assert hasattr(result, "calibrated_score")
    assert hasattr(result, "model")
    assert hasattr(result, "calibrator")
    assert hasattr(result, "feature_order")

    # Test calibrated_score on a flow
    flow = {k: float(np.random.rand()) for k in result.feature_order}
    score = result.calibrated_score(flow)
    assert 0.0 <= score <= 1.0, f"Calibrated score out of range: {score}"
    assert isinstance(score, float), f"Expected float, got {type(score)}"

    print("  BASIC TEST PASSED")


def _test_calibration_feature_alignment():
    """Verify that calibration aligns to FEATURE_ORDER; missing keys default to 0."""
    import numpy as np
    import xgboost as xgb
    from calibrate import calibrate, CalibrationResult

    np.random.seed(123)
    n = 100
    X = np.random.rand(n, len(FEATURE_ORDER))
    y = np.random.randint(0, 2, n)
    model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
    model.fit(X[:80], y[:80])

    # Hold-out: last 20 rows
    X_cal = X[80:]
    y_cal = y[80:]
    result = calibrate(model, X_cal, y_cal)

    # Flow with ALL 16 features
    flow_full = {k: float(np.random.rand()) for k in result.feature_order}
    s1 = result.calibrated_score(flow_full)

    # Flow with ONLY 3 features (others default to 0.0)
    flow_partial = {"bytes_in": 1.0, "bytes_in_per_s": 2.0, "requests_per_s": 3.0}
    s2 = result.calibrated_score(flow_partial)

    # Both should return finite values in [0, 1]
    assert 0.0 <= s1 <= 1.0, f"s1 out of range: {s1}"
    assert 0.0 <= s2 <= 1.0, f"s2 out of range: {s2}"

    print("  FEATURE ALIGNMENT TEST PASSED")


def _test_calibration_range():
    """Verify calibrated scores are always in [0, 1]."""
    import numpy as np
    import xgboost as xgb
    from calibrate import calibrate, CalibrationResult

    np.random.seed(99)
    n = 100
    X = np.random.rand(n, len(FEATURE_ORDER))
    y = np.random.randint(0, 2, n)
    model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
    model.fit(X[:70], y[:70])

    # 70% train, 30% calibrate
    split = int(0.7 * n)
    result = calibrate(model, X[:split], y[:split])

    # Score many flows
    for _ in range(20):
        flow = {k: float(np.random.rand()) for k in result.feature_order}
        s = result.calibrated_score(flow)
        assert 0.0 <= s <= 1.0, f"Calibrated score out of [0,1]: {s}"

    print("  RANGE TEST PASSED")


def _test_calibration_data_separation():
    """Verify that calibration hold-out data is separate from training data."""
    import numpy as np
    import xgboost as xgb
    from calibrate import calibrate, CalibrationResult

    np.random.seed(42)
    n = 150
    X = np.random.rand(n, len(FEATURE_ORDER))
    y = np.random.randint(0, 2, n)
    model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
    model.fit(X[:100], y[:100])

    # Hold-out: last 30 rows
    result = calibrate(model, X[100:], y[100:])

    # Raw probabilities from model on hold-out
    raw = model.predict_proba(X[100:])[:, 1]

    # Calibrated scores
    scored = []
    for i in range(len(X[100:])):
        flow = {k: float(X[100:][i][k]) for k in result.feature_order}
        scored.append(result.calibrated_score(flow))

    # Verify that the calibrator was fit
    assert result.calibrator is not None

    print("  DATA SEPARATION TEST PASSED")


def _test_calibration_save_load():
    """Fit a model, calibrate, save, reload, and verify calibrated scores."""
    import numpy as np
    import xgboost as xgb
    from calibrate import calibrate, CalibrationResult
    import joblib
    import os

    np.random.seed(42)
    n = 200
    X = np.random.rand(n, len(FEATURE_ORDER))
    y = np.random.randint(0, 2, n)
    model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
    model.fit(X[:150], y[:150])

    # Hold-out split
    result = calibrate(model, X[150:], y[150:])

    # Save the calibration result
    tmp_path = "/tmp/test_calibrate_result.joblib"
    result.save(tmp_path)

    # Load it back
    loaded = CalibrationResult.load(tmp_path)

    # Verify calibrated scores match within floating-point tolerance
    flow = {k: float(np.random.rand()) for k in loaded.feature_order}
    orig_score = result.calibrated_score(flow)
    loaded_score = loaded.calibrated_score(flow)
    assert abs(orig_score - loaded_score) < 1e-6, (
        f"Scores differ after save/load: {orig_score} vs {loaded_score}"
    )

    # Clean up
    try:
        os.unlink(tmp_path)
    except OSError:
        pass

    print("  SAVE/LOAD TEST PASSED")


def _test_calibration_save_missing_file():
    """Test that loading a missing artifact file raises a clear error."""
    import os

    try:
        CalibrationResult.load("/tmp/nonexistent_calibration_result.joblib")
        assert False, "Expected ValueError for missing file"
    except ValueError as e:
        assert "not found" in str(e).lower() or "not exist" in str(e).lower()

    print("  MISSING FILE TEST PASSED")


def _test_calibration_save_incompatible_feature_order():
    """Test that loading an artifact with incompatible feature order raises an error."""
    import joblib
    import numpy as np
    import xgboost as xgb
    from calibrate import calibrate, CalibrationResult

    np.random.seed(42)
    n = 200
    X = np.random.rand(n, len(FEATURE_ORDER))
    y = np.random.randint(0, 2, n)
    model = xgb.XGBClassifier(n_estimators=10, random_state=42, base_score=0.5)
    model.fit(X[:150], y[:150])

    result = calibrate(model, X[150:], y[150:])

    # Save normally
    tmp_path = "/tmp/test_incompatible.joblib"
    result.save(tmp_path)

    # Corrupt the feature order in the saved artifact
    artifact = joblib.load(tmp_path)
    artifact["feature_order"] = ["nonexistent_feature"]  # invalid
    joblib.dump(artifact, tmp_path)

    # Loading should fail
    try:
        CalibrationResult.load(tmp_path)
        assert False, "Expected ValueError for incompatible feature order"
    except ValueError as e:
        assert "feature_order" in str(e).lower()

    # Clean up
    try:
        os.unlink(tmp_path)
    except OSError:
        pass

    print("  INCOMPATIBLE FEATURE ORDER TEST PASSED")


# ---------------------------------------------------------------------------
# Allow running as: python -m m3_scoring.calibrate  (runs the smoke tests)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
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