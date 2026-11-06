#!/usr/bin/env python3
"""Evaluate Sentinel-AI model on the held-out test split.

Computes PER-FLOW metrics at threshold 0.30:
  - per-flow confusion matrix (TP/FP/TN/FN by flow, not by snapshot row)
  - benign flows flagged / total benign flows
  - attack flows flagged / total attack flows
  - median and p90 age at first flag for attacks
Also computes row-level PR-AUC, ROC-AUC, ECE (threshold-independent).

DO NOT tune on the test set.  Use the session-based test split
(sessions runb, runf, rung) only — do not reuse the test split for
hyperparameter selection.
"""

import json, os, tempfile
from collections import Counter

import numpy as np, pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

import joblib
import xgboost as xgb
from sklearn.isotonic import IsotonicRegression

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ART_PATH = os.path.join(REPO, "models", "calibration_result_current.joblib")
DATA_PQ = os.path.join(REPO, "data", "features.parquet")
FO = [ "bytes_in", "bytes_in_per_s", "requests_per_s", "packets_per_s",
       "interarrival_mean", "interarrival_std", "interarrival_max",
       "concurrent_conns", "conns_per_second_opened", "requests_per_conn_so_far",
       "conn_age_s", "stall_time_s", "body_frac_sent", "bytes_declared",
       "body_drip_rate_bps", "header_complete" ]


def load_artifact(path=ART_PATH):
    art = joblib.load(path)
    data = json.loads(art["model_json"])
    bs = data["learner"]["learner_model_param"].get("base_score")
    if isinstance(bs, str):
        data["learner"]["learner_model_param"]["base_score"] = "0.5"
    elif isinstance(bs, (int, float)):
        data["learner"]["learner_model_param"]["base_score"] = "0.5"
    tmp = tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False, encoding="utf-8")
    tmp.write(json.dumps(data))
    tmp_path = tmp.name
    tmp.close()
    model = xgb.XGBClassifier(n_estimators=10, base_score=0.5)
    model.load_model(tmp_path)
    os.unlink(tmp_path)
    return model, art["calibrator"], art["feature_order"]


def load_test_split(data_path=DATA_PQ):
    """Session-based test: sessions runb, runf, rung."""
    df = pd.read_parquet(data_path)
    test = df[df.session.isin(["runb", "runf", "rung"])].copy()
    return test.reset_index(drop=True)


def _per_flow_metrics(test: pd.DataFrame, threshold: float) -> dict:
    """Aggregate snapshot rows into per-flow decisions.

    For each flow_id:
      - ever_flagged: any snapshot row has calibrated score >= threshold
      - first_flag_age: snapshot_t - t_first at the first flagged snapshot

    If the parquet has one row per flow (no flow_id column), each row is
    treated as a complete flow and conn_age_s is used as the age at flag.
    """
    test = test.copy()
    test["pred"] = test["cal"] >= threshold

    if "flow_id" in test.columns:
        # Multiple snapshots per flow: aggregate by flow_id
        flow_records = []
        for fid, group in test.groupby("flow_id"):
            y_flow = int(group["y"].iloc[0])
            t_first = float(group["t"].iloc[0])
            flagged = group[group["pred"]]
            ever_flagged = len(flagged) > 0
            first_flag_age = None
            if ever_flagged:
                first_row = flagged.sort_values("snapshot_t").iloc[0]
                first_flag_age = float(first_row["snapshot_t"] - t_first)
            flow_records.append({
                "flow_id": fid,
                "y": y_flow,
                "ever_flagged": ever_flagged,
                "first_flag_age": first_flag_age,
                "n_snapshots": int(len(group)),
            })
        flow_df = pd.DataFrame(flow_records)
    else:
        # One row per flow: each row is a complete flow
        flow_df = test[["y", "pred", "conn_age_s"]].copy()
        flow_df.columns = ["y", "ever_flagged", "conn_age_s"]
        flow_df["ever_flagged"] = flow_df["ever_flagged"].astype(bool)
        flow_df["first_flag_age"] = flow_df.apply(
            lambda r: float(r["conn_age_s"]) if r["ever_flagged"] else None,
            axis=1,
        )
        flow_df["flow_id"] = [f"row_{i}" for i in range(len(flow_df))]
        flow_df["n_snapshots"] = 1

    attack_flows = flow_df[flow_df["y"] == 1]
    benign_flows = flow_df[flow_df["y"] == 0]

    tp = int(attack_flows["ever_flagged"].sum())
    fn = int((~attack_flows["ever_flagged"]).sum())
    fp = int(benign_flows["ever_flagged"].sum())
    tn = int((~benign_flows["ever_flagged"]).sum())

    n_flows = len(flow_df)
    n_attack = len(attack_flows)
    n_benign = len(benign_flows)

    acc = (tp + tn) / n_flows if n_flows > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    confusion = {
        "threshold": threshold,
        "TP": tp,
        "TN": tn,
        "FP": fp,
        "FN": fn,
        "n_flows": n_flows,
        "n_attack_flows": n_attack,
        "n_benign_flows": n_benign,
        "accuracy": round(acc, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "benign_flows_flagged": fp,
        "benign_flows_total": n_benign,
        "attack_flows_flagged": tp,
        "attack_flows_total": n_attack,
        "benign_flow_flag_rate": round(fp / n_benign, 4) if n_benign > 0 else 0.0,
        "attack_flow_flag_rate": round(tp / n_attack, 4) if n_attack > 0 else 0.0,
    }

    # Age at first flag for attacks that were flagged
    flagged_attacks = attack_flows[attack_flows["ever_flagged"]]
    ages = flagged_attacks["first_flag_age"].dropna()
    if len(ages) > 0:
        confusion["attack_first_flag_age_median"] = round(float(ages.median()), 3)
        confusion["attack_first_flag_age_p90"] = round(float(ages.quantile(0.90)), 3)
        confusion["attack_flows_with_first_flag"] = int(len(ages))
    else:
        confusion["attack_first_flag_age_median"] = None
        confusion["attack_first_flag_age_p90"] = None
        confusion["attack_flows_with_first_flag"] = 0

    return confusion


def main():
    model, calibrator, fo = load_artifact()
    test = load_test_split()
    y = test["y"].to_numpy()
    n = len(y)

    Xt = test[fo]
    raw = model.predict_proba(Xt)[:, 1]
    cal = np.clip(calibrator.predict(raw), 0.0, 1.0)

    # --- Per-flow confusion matrix ---
    threshold = 0.30
    test_with_scores = test.copy()
    test_with_scores["cal"] = cal
    flow_confusion = _per_flow_metrics(test_with_scores, threshold)

    # --- PR-AUC, ROC-AUC (row-level, threshold-independent) ---
    pr_auc = round(average_precision_score(y, cal), 4)
    roc_auc = round(roc_auc_score(y, cal), 4)

    # --- ECE (10 bins) ---
    edges = np.linspace(0.0, 1.0, 11)
    ece = 0.0
    for i in range(10):
        lo, hi = edges[i], edges[i + 1]
        mask = (cal > lo) & (cal <= hi) if i > 0 else (cal >= lo) & (cal <= hi)
        if mask.any():
            ece += float(mask.mean()) * abs(float(y[mask].mean() - cal[mask].mean()))
    ece = round(ece, 6)

    # --- Build output ---
    metrics = {
        "confusion": flow_confusion,
        "pr_auc": pr_auc,
        "roc_auc": roc_auc,
        "ece": ece,
        "test_rows": int(n),
        "threshold_used": 0.30,
    }

    # --- Write results/metrics.json ---
    out_dir = os.path.join(REPO, "results")
    os.makedirs(out_dir, exist_ok=True)
    json_path = os.path.join(out_dir, "metrics.json")
    with open(json_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Wrote {json_path}")

    # --- Write metrics.md ---
    md_path = os.path.join(REPO, "results", "metrics.md")
    c = metrics["confusion"]
    with open(md_path, "w") as f:
        f.write("# Sentinel-AI Evaluation Metrics\n\n")
        f.write("**Computed on the session-based test split** (sessions: runb, runf, rung).\n")
        f.write("Metrics are **per unique flow**, not per snapshot row.\n")
        f.write("Threshold: 0.30 (project's own decision boundary).\n\n")

        f.write("## Per-Flow Confusion Matrix @ 0.30\n\n")
        f.write(f"| Metric | Value |\n")
        f.write(f"|---|---|\n")
        f.write(f"| **True Positives** (attack flows flagged) | {c['TP']} |\n")
        f.write(f"| **True Negatives** (benign flows not flagged) | {c['TN']} |\n")
        f.write(f"| **False Positives** (benign flows flagged) | {c['FP']} |\n")
        f.write(f"| **False Negatives** (attack flows not flagged) | {c['FN']} |\n")
        f.write(f"| **Accuracy** | {c['accuracy']} |\n")
        f.write(f"| **Precision** | {c['precision']} |\n")
        f.write(f"| **Recall** | {c['recall']} |\n")
        f.write(f"| **F1 Score** | {c['f1']} |\n\n")

        f.write("## Flow-Level Detection Rates\n\n")
        f.write(f"- **Attack flows flagged:** {c['attack_flows_flagged']} / {c['attack_flows_total']} "
                f"({c['attack_flow_flag_rate']})\n")
        f.write(f"- **Benign flows flagged:** {c['benign_flows_flagged']} / {c['benign_flows_total']} "
                f"({c['benign_flow_flag_rate']})\n")
        f.write(f"- **Total flows:** {c['n_flows']} "
                f"({c['n_attack_flows']} attack, {c['n_benign_flows']} benign)\n\n")

        f.write("## Age at First Flag (Attacks)\n\n")
        if c["attack_first_flag_age_median"] is not None:
            f.write(f"- **Median age at first flag:** {c['attack_first_flag_age_median']} s\n")
            f.write(f"- **p90 age at first flag:** {c['attack_first_flag_age_p90']} s\n")
            f.write(f"- **Attack flows with a flag:** {c['attack_flows_with_first_flag']} "
                    f"/ {c['attack_flows_total']}\n\n")
        else:
            f.write("- No attack flows were flagged; no age-at-first-flag data.\n\n")

        f.write("## Aggregate Metrics (row-level)\n\n")
        f.write(f"- **PR-AUC (calibrated):** {metrics['pr_auc']}\n")
        f.write(f"- **ROC-AUC (calibrated):** {metrics['roc_auc']}\n")
        f.write(f"- **ECE (10 bins, lower is better):** {metrics['ece']}\n\n")

        f.write("## Test Split Summary\n\n")
        f.write(f"- **Snapshot rows:** {metrics['test_rows']}\n")
        f.write(f"- **Unique flows:** {c['n_flows']}\n")
        f.write(f"- **Threshold:** {metrics['threshold_used']}\n")
        f.write(f"- **Attack fraction:** {round(y.sum() / y.size, 4)} (1=attack, 0=benign)\n\n")

        f.write("## Notes\n\n")
        f.write("- The `profile` heuristic (slowloris/flood/benign guess from flow shape) is\n")
        f.write("  used only as a display label (`display_guess`), never as ground truth.\n")
        f.write("- Detailed `attack_type` (slowloris, slow_post, flood, benign) comes from\n")
        f.write("  the off-the-wire side log written by `gen/generate.py --side-log`, not from\n")
        f.write("  any string inside the traffic.\n")

    print(f"Wrote {md_path}")

    # --- Attempt to update README to read from metrics.json ---
    readme_path = os.path.join(REPO, "README.md")
    try:
        with open(readme_path, "r") as _f:
            readme_text = _f.read()
        if "results/metrics.json" not in readme_text:
            insert_marker = "Sentinel-AI is an explainable L7 DoS defender."
            if insert_marker in readme_text:
                replacement = readme_text.replace(
                    insert_marker,
                    insert_marker
                    + "\n\n*Model metrics (PR-AUC, ROC-AUC, ECE, per-flow confusion matrix) are computed\n"
                    "from the session-based test split and stored in `results/metrics.json`.\n"
                    "See `results/metrics.md` for the full report.",
                )
                with open(readme_path, "w") as _f:
                    _f.write(replacement)
                print("Updated README.md with metrics source note.")
    except FileNotFoundError:
        print("README.md not found; skipping.")

    print("\nDone.  Metrics JSON and Markdown are in results/.")
    print(f"  JSON: {json_path}")
    print(f"  MD:   {md_path}")


if __name__ == "__main__":
    main()
