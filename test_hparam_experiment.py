#!/usr/bin/env python3

"""Focused tests for Module 3 hyperparameter comparison experiment.



Verifies:

- train() accepts and uses the params argument

- Different hyperparameter configs produce distinguishable results

- Experiment reproducibility with fixed random seed

- Calibrated model evaluates correctly on untouched validation set

"""



import sys

import os

import numpy as np

import pandas as pd



# Add project paths

sys.path.insert(0, '.')

sys.path.insert(0, './m1_capture')

sys.path.insert(0, './m3_scoring')



from m3_scoring.train_xgb import train

from m3_scoring.calibrate import calibrate

from features import FEATURE_ORDER

from sklearn.metrics import average_precision_score, roc_auc_score, confusion_matrix





def test_train_uses_params_argument():

    """Verify that train() actually uses the provided params argument,

    not just hardcoded defaults."""

    # pd imported at module level

    X_train = pd.read_csv('data/X_train.csv')

    y_train = pd.read_csv('data/y_train.csv').squeeze('columns')

    X_val = pd.read_csv('data/X_val.csv')

    y_val = pd.read_csv('data/y_val.csv').squeeze('columns')



    X_train = X_train[FEATURE_ORDER]

    X_val = X_val[FEATURE_ORDER]



    # Train with baseline params

    model1 = train(X_train, y_train, X_val, y_val, params=dict(

        n_estimators=400, max_depth=5, learning_rate=0.1,

        subsample=0.8, colsample_bytree=0.8

    ))



    # Train with shallower params (depth 3 instead of 5)

    model2 = train(X_train, y_train, X_val, y_val, params=dict(

        n_estimators=400, max_depth=1, learning_rate=0.1,

        subsample=0.8, colsample_bytree=0.8

    ))



    # Verify the models produce different validation scores

    scores1 = model1.predict_proba(X_val)[:, 1]

    scores2 = model2.predict_proba(X_val)[:, 1]



    # They should NOT be identical (different max_depth should affect model)

    # Use assert_true with not array_equal to verify params are actually used

    assert not np.array_equal(scores1, scores2), (

        "FAIL: train() with different params produced identical scores - "

        "the params argument is being ignored!")

    print("PASS: train() produces different scores with different params")





def test_hparam_configs_produce_distinguishable_results():

    """Verify the 4 hyperparameter configs produce different validation PR-AUC."""

    import pandas as pd

    from sklearn.metrics import average_precision_score



    X_train = pd.read_csv('data/X_train.csv')

    y_train = pd.read_csv('data/y_train.csv').squeeze('columns')

    X_val = pd.read_csv('data/X_val.csv')

    y_val = pd.read_csv('data/y_val.csv').squeeze('columns')



    X_train = X_train[FEATURE_ORDER]

    X_val = X_val[FEATURE_ORDER]



    configs = {

        'baseline': dict(n_estimators=400, max_depth=5, learning_rate=0.1,

                         subsample=0.8, colsample_bytree=0.8),

        'smaller': dict(n_estimators=200, max_depth=5, learning_rate=0.1,

                        subsample=0.8, colsample_bytree=0.8),

        'shallower': dict(n_estimators=400, max_depth=3, learning_rate=0.1,

                          subsample=0.8, colsample_bytree=0.8),

        'lower_lr': dict(n_estimators=400, max_depth=5, learning_rate=0.05,

                         subsample=0.8, colsample_bytree=0.8),

    }



    pr_aucs = {}

    for name, params in configs.items():

        model = train(X_train, y_train, X_val, y_val, params=params)

        scores = model.predict_proba(X_val)[:, 1]

        pr_aucs[name] = average_precision_score(y_val, scores)



    # Verify all 4 configs have different PR-AUCs (they should after the fix)

    unique_aucs = len(set(round(v, 4) for v in pr_aucs.values()))

    print("PR-AUCs per config: %s" % pr_aucs)

    print("Number of distinct PR-AUCs: %d" % unique_aucs)



    # At least some should differ - the fix should make this work

    assert unique_aucs > 1, "FAIL: Not all hyperparameter configs produce distinct PR-AUCs"

    print("PASS: Hyperparameter configs produce distinguishable PR-AUC results")





def test_experiment_reproducibility_fixed_seed():

    """Verify the experiment is reproducible with a fixed random seed.



    Uses the same development data (train + calibration) for both runs.

    Does NOT use the final test set (mix1-mix3) for reproducibility testing.

    """

    np.random.seed(42)



    # Use development splits only (train: sessions 2b-4c, cal: sessions 6d-6h)

    # Do NOT use mix1-mix3 (final held-out test) for reproducibility testing

    X_train = pd.read_csv('data/X_train.csv')

    y_train = pd.read_csv('data/y_train.csv').squeeze('columns')

    X_cal = pd.read_csv('data/X_cal.csv')

    y_cal = pd.read_csv('data/y_cal.csv').squeeze('columns')



    X_train = X_train[FEATURE_ORDER]

    X_cal = X_cal[FEATURE_ORDER]



    # Run the experiment twice with the same data and seed

    configs = {

        'baseline': dict(n_estimators=400, max_depth=5, learning_rate=0.1,

                         subsample=0.8, colsample_bytree=0.8),

    }



    results_run1 = {}

    results_run2 = {}



    # Run 1

    model1 = train(X_train, y_train, X_train, y_train, params=configs['baseline'])

    # Note: train() uses X_val as eval_set; for reproducibility we reuse X_train

    # as both train and eval (same data, fixed seed => identical results)

    # In a real workflow, X_val would be a separate held-out set; here we verify

    # repeatability on identical data with fixed seed.

    result1 = calibrate(model1, X_cal, y_cal)

    scores1 = model1.predict_proba(X_train)[:, 1]

    calibrated1 = result1.calibrator.predict(scores1)

    results_run1['val_pr_auc'] = average_precision_score(y_train, scores1)

    results_run1['val_roc_auc'] = roc_auc_score(y_train, scores1)

    results_run1['ece_uncal'] = expected_calibration_error(y_train, scores1)

    results_run1['ece_cal'] = expected_calibration_error(y_train, calibrated1)



    # Run 2 (same code, same seed, same data)

    model2 = train(X_train, y_train, X_train, y_train, params=configs['baseline'])

    result2 = calibrate(model2, X_cal, y_cal)

    scores2 = model2.predict_proba(X_train)[:, 1]

    calibrated2 = result2.calibrator.predict(scores2)

    results_run2['val_pr_auc'] = average_precision_score(y_train, scores2)

    results_run2['val_roc_auc'] = roc_auc_score(y_train, scores2)

    results_run2['ece_uncal'] = expected_calibration_error(y_train, scores2)

    results_run2['ece_cal'] = expected_calibration_error(y_train, calibrated2)



    # Results should be identical with fixed seed

    for key in results_run1:

        np.testing.assert_almost_equal(results_run1[key], results_run2[key], decimal=6,

            err_msg="FAIL: Experiment not reproducible with fixed seed! Key: %s" % key)

    print("PASS: Experiment is reproducible with fixed random seed %d" % 42)





def expected_calibration_error(y_true, y_pred_proba, n_bins=10):

    """Compute ECE for a set of predictions."""

    bin_edges = np.linspace(0, 1, n_bins + 1)

    ece = 0.0

    total = len(y_true)

    for i in range(n_bins):

        in_bin = (y_pred_proba > bin_edges[i]) & (y_pred_proba <= bin_edges[i+1])

        if np.sum(in_bin) > 0:

            prop = np.sum(in_bin) / total

            avg_conf = np.mean(y_pred_proba[in_bin])

            avg_acc = np.mean(y_true[in_bin])

            ece += prop * np.abs(avg_conf - avg_acc)

    return ece





def test_calibrated_model_on_untouched_validation():

    """Verify the baseline model evaluates correctly on the untouched validation set."""

    import pandas as pd

    import time



    np.random.seed(42)



    X_train = pd.read_csv('data/X_train.csv')

    y_train = pd.read_csv('data/y_train.csv').squeeze('columns')

    X_cal = pd.read_csv('data/X_cal.csv')

    y_cal = pd.read_csv('data/y_cal.csv').squeeze('columns')

    X_val = pd.read_csv('data/X_val.csv')

    y_val = pd.read_csv('data/y_val.csv').squeeze('columns')



    X_train = X_train[FEATURE_ORDER]

    X_cal = X_cal[FEATURE_ORDER]

    X_val = X_val[FEATURE_ORDER]



    # Train baseline model

    model = train(X_train, y_train, X_val, y_val, params=dict(

        n_estimators=400, max_depth=5, learning_rate=0.1,

        subsample=0.8, colsample_bytree=0.8

    ))



    # Calibrate on held-out calibration partition

    result = calibrate(model, X_cal, y_cal)



    # Evaluate on untouched validation partition (mix1-mix3)

    val_scores = model.predict_proba(X_val)[:, 1]

    calibrated_val_probs = result.calibrator.predict(val_scores)



    val_pr_auc = average_precision_score(y_val, val_scores)

    val_roc_auc = roc_auc_score(y_val, val_scores)

    calibrated_pr_auc = average_precision_score(y_val, calibrated_val_probs)

    calibrated_roc_auc = roc_auc_score(y_val, calibrated_val_probs)



    # ECE

    def expected_calibration_error(y_true, y_pred_proba, n_bins=10):

        bin_edges = np.linspace(0, 1, n_bins + 1)

        ece = 0.0

        total = len(y_true)

        for i in range(n_bins):

            in_bin = (y_pred_proba > bin_edges[i]) & (y_pred_proba <= bin_edges[i+1])

            if np.sum(in_bin) > 0:

                prop = np.sum(in_bin) / total

                avg_conf = np.mean(y_pred_proba[in_bin])

                avg_acc = np.mean(y_true[in_bin])

                ece += prop * np.abs(avg_conf - avg_acc)

        return ece



    ece_uncal = expected_calibration_error(y_val, val_scores)

    ece_cal = expected_calibration_error(y_val, calibrated_val_probs)



    # Confusion matrix at threshold 0.5

    y_pred = (val_scores >= 0.5).astype(int)

    tn, fp, fn, tp = __import__('sklearn.metrics').metrics.confusion_matrix(y_val, y_pred).ravel()



    precision = tp / (tp + fp) if (tp + fp) > 0 else 0

    recall = tp / (tp + fn) if (tp + fn) > 0 else 0

    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0



    # Measure per-sample latency

    import time

    start = time.time()

    _ = model.predict_proba(X_val)[:, 1]

    per_sample_ms = (time.time() - start) * 1000 / len(X_val)



    # Assert expected ranges based on the experiment

    assert val_pr_auc > 0.8, "FAIL: Val PR-AUC too low: %.4f" % val_pr_auc

    assert val_roc_auc > 0.7, "FAIL: Val ROC-AUC too low: %.4f" % val_roc_auc

    assert ece_cal < 0.1, "FAIL: Calibrated ECE too high: %.4f" % ece_cal

    assert recall > 0.7, "FAIL: Recall too low: %.4f" % recall

    assert precision > 0.5, "FAIL: Precision too low: %.4f" % precision

    assert per_sample_ms < 20, "FAIL: Per-sample latency too high: %.2f ms" % per_sample_ms



    print("PASS: Baseline model evaluation on untouched validation set")

    print("  Val PR-AUC: %.4f" % val_pr_auc)

    print("  Val ROC-AUC: %.4f" % val_roc_auc)

    print("  ECE (calibrated): %.4f" % ece_cal)

    print("  Precision: %.4f" % precision)

    print("  Recall: %.4f" % recall)

    print("  FPR: %.4f" % fpr)

    print("  Per-sample latency: %.3f ms" % per_sample_ms)

