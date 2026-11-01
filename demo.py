#!/usr/bin/env python3
"""demo.py — end-to-end pipeline on held-out flows: M2 -> M3 -> SHAP -> M4.

Every flow goes through the same path the live system is meant to take:

    M2 cheap triggers (rules + stall)        no ML
    M3 calibrated score (XGBoost + isotonic)
    M3 SHAP, full {feature: value} mapping   only for flows the ladder acts on
    M4 policy ladder + SHAP group-sum switch  -> mechanism actually enforced

and the result is written to detector_state*.json so m5_sandbox.bench reads
real decisions instead of its modelled fallback.

The held-out set (mix1-mix3) labels flows only attack/benign. The attack
profile shown here (slowloris / rudy / flood) is inferred from the flow's
shape, not from a ground-truth column, and the output says so.

Run:
    .venv/bin/python demo.py
    .venv/bin/python demo.py --profile slowloris --show 5
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import warnings
from collections import Counter

sys.path.insert(0, os.path.abspath("."))
sys.path.insert(0, os.path.abspath("./m1_capture"))
sys.path.insert(0, os.path.abspath("./m3_scoring"))

import pandas as pd

from schemas import FlowRecord
from m2_triggers.rules import detect_rules
from m2_triggers.stall import detect as detect_stall
from calibrate import CalibrationResult
from explain import explain, top_k
from mechanism import Mechanism, Policy, choose_by_shap_group, choose_by_trigger

PROFILES = ["benign", "slowloris", "rudy", "flood"]
# the defence that actually contains each profile (manual §6, mechanism.contains)
EXPECTED = {"slowloris": "limit_conn+timeout", "rudy": "limit_conn+timeout",
            "flood": "limit_req"}
ACT_THRESHOLD = 0.30   # below this the ladder forwards, so no SHAP is needed


def profile_of(row) -> str:
    """Attack profile from the flow's shape. Dataset only says attack/benign."""
    if row["role"] != "attack":
        return "benign"
    if row["header_complete"] == 0:
        return "slowloris"
    if row["bytes_declared"] > 0 and row["body_frac_sent"] < 1:
        return "rudy"
    return "flood"


def mechanism_name(m: Mechanism) -> str:
    parts = []
    if m.rate_limit:
        parts.append("limit_req")
    if m.conn_limit:
        parts.append("limit_conn")
    if m.timeout_s:
        parts.append("timeout")
    return "+".join(parts) or "forward"


def flow_record(row, idx: int) -> FlowRecord:
    feats = {k: float(row[k]) for k in FlowRecord.__dataclass_fields__ if k in row}
    t = float(row.get("t", 0.0))
    return FlowRecord(
        flow_id=f"{row['session']}-{idx}", entity_key=str(row["entity"]),
        ts_start=t, ts_end=t, src_ip=str(row["entity"]), src_port=0,
        dst_ip="proxy", dst_port=80, **feats,
    )


def run(data: str, artifact_path: str, only: str | None) -> list[dict]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")   # sklearn version note on the calibrator
        artifact = CalibrationResult.load(artifact_path)
    df = pd.read_csv(data)
    policy = Policy()
    out = []
    for idx, row in df.iterrows():
        prof = profile_of(row)
        if only and prof != only:
            continue
        feats = {k: float(row[k]) for k in artifact.feature_order}
        t0 = time.perf_counter()

        # M2: cheap triggers
        fr = flow_record(row, idx)
        triggers = [e.trigger for e in detect_rules(fr)]
        stall = detect_stall(fr)
        if stall is not None:
            triggers.append(stall.trigger)

        # M3: calibrated score
        score = artifact.calibrated_score(feats)

        # M4: ladder decides whether to act; SHAP decides how
        action = policy.decide(str(row["entity"]), score)
        rec = {
            "flow_id": fr.flow_id, "entity": fr.entity_key, "profile": prof,
            "y": int(row["y"]), "triggers": triggers, "score": round(score, 4),
            "action": action, "mechanism": "forward", "driver_group": "none",
            "reason": "score below action threshold", "shap_top": [],
            # what the cheap-trigger switch would enforce, for comparison
            "trigger_mechanism": (mechanism_name(choose_by_trigger(triggers[0], score))
                                  if triggers else "forward"),
        }
        if score >= ACT_THRESHOLD:
            shap_values = explain(artifact.model, feats)
            mech = choose_by_shap_group(shap_values, score)
            rec.update(
                mechanism=mechanism_name(mech), driver_group=mech.driver_group,
                reason=mech.reason,
                shap_top=[(k, round(v, 3)) for k, v in top_k(shap_values, 3)],
            )
        rec["decision_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        out.append(rec)
    return out


def _correct_pct(rows: list[dict], prof: str, key: str) -> float | None:
    """% of a profile's flows that end with the containing defence enforced."""
    if prof not in EXPECTED:
        return None
    return round(100 * sum(r[key] == EXPECTED[prof] for r in rows) / len(rows), 1)


def summarise(results: list[dict]) -> dict:
    summary = {}
    for prof in PROFILES:
        rows = [r for r in results if r["profile"] == prof]
        if not rows:
            continue
        acted = [r for r in rows if r["action"] != "forward"]
        summary[prof] = {
            "flows": len(rows),
            "acted_on": len(acted),
            "acted_pct": round(100 * len(acted) / len(rows), 1),
            "trigger_fired_pct": round(100 * sum(bool(r["triggers"]) for r in rows) / len(rows), 1),
            "mean_score": round(sum(r["score"] for r in rows) / len(rows), 3),
            "driver_groups": dict(Counter(r["driver_group"] for r in acted)),
            "mechanisms": dict(Counter(r["mechanism"] for r in acted)),
            "shap_switch_correct_pct": _correct_pct(rows, prof, "mechanism"),
            "trigger_switch_correct_pct": _correct_pct(rows, prof, "trigger_mechanism"),
            "p99_decision_ms": sorted(r["decision_ms"] for r in rows)[int(0.99 * (len(rows) - 1))],
        }
    return summary


def state_for(rows: list[dict]) -> dict:
    """The shape m5_sandbox.bench.read_system_state() expects, from the top flow."""
    top = max(rows, key=lambda r: r["score"])
    return {
        "max_score": top["score"],
        "top_group": top["driver_group"],
        "driver_group": top["driver_group"],
        "mechanism": top["mechanism"],
        "action": top["action"],
        "reason": top["reason"],
        "flow_id": top["flow_id"],
        "generated_by": "demo.py (held-out mix1-mix3, offline)",
        "generated_at": time.time(),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--data", default="data/X_val.csv")
    ap.add_argument("--artifact", default="calibration_result_candidate.joblib")
    ap.add_argument("--profile", choices=PROFILES, default=None)
    ap.add_argument("--show", type=int, default=2, help="example flows per profile")
    ap.add_argument("--state-file",
                    default=os.getenv("DETECTOR_STATE_FILE", "detector_state.json"))
    args = ap.parse_args()

    results = run(args.data, args.artifact, args.profile)

    print("=" * 78)
    print("SENTINEL-AI PIPELINE DEMO   M2 triggers -> M3 score + SHAP -> M4 mechanism")
    print(f"data: {args.data} (held-out)   model: {args.artifact}")
    print("profile is inferred from flow shape; ground truth is attack/benign only")
    print("=" * 78)

    for prof in PROFILES:
        rows = [r for r in results if r["profile"] == prof]
        if not rows:
            continue
        print(f"\n--- {prof.upper()} : example decisions ---")
        examples = sorted(rows, key=lambda r: -r["score"])[: args.show]
        for r in examples:
            print(f"  flow {r['flow_id']:<12} entity {r['entity']:<14} "
                  f"triggers={r['triggers'] or '-'}")
            print(f"    score {r['score']:.3f} -> action {r['action']:<10} "
                  f"SHAP switch: {r['mechanism']:<20} trigger switch: {r['trigger_mechanism']}")
            if r["shap_top"]:
                print(f"    SHAP top: {r['shap_top']}")
                print(f"    why: {r['reason']}")

    summary = summarise(results)
    print("\n" + "=" * 78)
    print(f"{'profile':<10} {'flows':>6} {'model acted':>12} {'trigger fired':>14} "
          f"{'score':>6}  {'right defence: SHAP / trigger'}")
    print("-" * 78)
    for prof, s in summary.items():
        right = ("-" if s["shap_switch_correct_pct"] is None else
                 f"{s['shap_switch_correct_pct']:.0f}% / {s['trigger_switch_correct_pct']:.0f}%"
                 f"   ({EXPECTED[prof]})")
        print(f"{prof:<10} {s['flows']:>6} {s['acted_pct']:>11.1f}% "
              f"{s['trigger_fired_pct']:>13.1f}% {s['mean_score']:>6.3f}  {right}")
    print("=" * 78)
    if "benign" in summary:
        print(f"benign collateral: {summary['benign']['acted_pct']}% of benign flows acted on")

    # State files for m5_sandbox.bench
    stem, ext = os.path.splitext(args.state_file)
    written = []
    for prof in PROFILES[1:]:
        rows = [r for r in results if r["profile"] == prof]
        if rows:
            path = f"{stem}_{prof}{ext}"
            with open(path, "w") as f:
                json.dump(state_for(rows), f, indent=2)
            written.append(path)
    if results:
        with open(args.state_file, "w") as f:
            json.dump({**state_for(results), "summary": summary}, f, indent=2)
        written.append(args.state_file)
    print("state written: " + ", ".join(written))


if __name__ == "__main__":
    main()
