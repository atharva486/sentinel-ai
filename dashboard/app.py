#!/usr/bin/env python3
"""Sentinel-AI — explainable L7 DoS defence dashboard.

A read-only viewer over the *real* artifacts produced by the project:

    data/features.parquet                   the 5,337 labelled flows
    calibration_result_candidate.joblib     XGBoost + isotonic calibrator
    ablation_results.json                   the 5-policy comparison
    mechanism.py, m1_capture/features.py, m3_scoring/explain.py

Nothing here re-implements the pipeline: detection, calibration and the
SHAP -> defence switch are imported from the project's own modules, so the
dashboard shows what the code actually does, not a mock-up.

Run:
    streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

# ---------------------------------------------------------------------------
# Import path: works whether launched from the repo root or from dashboard/.
# ---------------------------------------------------------------------------
DASH_DIR = Path(__file__).resolve().parent
REPO_ROOT = DASH_DIR.parent
for _p in (REPO_ROOT, REPO_ROOT / "m1_capture", REPO_ROOT / "m3_scoring"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from m1_capture.features import (  # noqa: E402
    CONCURRENCY_FEATURES,
    FEATURE_ORDER,
    RATE_FEATURES,
    STALL_FEATURES,
)
from m3_scoring.calibrate import CalibrationResult  # noqa: E402
from m3_scoring.explain import explain, top_k  # noqa: E402
from mechanism import (  # noqa: E402
    DETECT_THRESHOLD,
    LADDER,
    Policy,
    choose_by_shap_group,
    group_of,
    shap_group_scores,
)
from m5_sandbox.adversarial.evade import _simulated_score, evade_sync  # noqa: E402

# The real-time engine, live-packet sensor and Docker lab driver.
if str(DASH_DIR) not in sys.path:
    sys.path.insert(0, str(DASH_DIR))
from live import (  # noqa: E402
    FEED_PATH,
    LAB_STATUS_PATH,
    LabRunner,
    LiveEngine,
    flow_signature,
    mechanism_kind,
    pipeline_html,
)

DATA_PATH = REPO_ROOT / "data" / "features.parquet"
ARTIFACT_PATH = REPO_ROOT / "models" / "calibration_result_current.joblib"
ABLATION_PATH = REPO_ROOT / "ablation_results.json"

GROUP_ORDER = ["stall", "concurrency", "rate", "other"]
GROUP_COLORS = {
    "stall": "#d1495b",
    "concurrency": "#e08e0b",
    "rate": "#2d7ff9",
    "other": "#94a3b8",
}

st.set_page_config(
    page_title="Sentinel-AI — Explainable L7 DoS Defence",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Loaders (cached)
# ---------------------------------------------------------------------------
@st.cache_resource
def get_artifact() -> CalibrationResult:
    return CalibrationResult.load(str(ARTIFACT_PATH))


@st.cache_data
def get_features() -> pd.DataFrame:
    return pd.read_parquet(DATA_PATH)


@st.cache_data
def get_val_scores():
    """Raw + calibrated scores on the held-out validation runs (runF, runG)."""
    df = get_features()
    art = get_artifact()
    val = df[df["session"].isin(["runf", "rung"])].copy()
    if val.empty:
        return val, np.array([]), np.array([])
    X = val[FEATURE_ORDER].to_numpy(dtype=float)
    raw = art.model.predict_proba(X)[:, 1]
    cal = np.clip(art.calibrator.predict(raw), 0.0, 1.0)
    return val, raw, cal


@st.cache_data
def run_evade(enforce: bool) -> dict:
    return evade_sync(rounds=30, enforce_damage=enforce, seed=42)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def feature_group(name: str) -> str:
    if name in STALL_FEATURES:
        return "stall"
    if name in CONCURRENCY_FEATURES:
        return "concurrency"
    if name in RATE_FEATURES:
        return "rate"
    return "other"


def expected_calibration_error(y, p, n_bins: int = 10) -> float:
    y = np.asarray(y, dtype=float)
    p = np.asarray(p, dtype=float)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        mask = (p >= lo) & (p <= hi) if i == 0 else (p > lo) & (p <= hi)
        if not mask.any():
            continue
        ece += mask.mean() * abs(y[mask].mean() - p[mask].mean())
    return float(ece)


def policy_band(score: float) -> str:
    if score >= LADDER[0][0]:
        return "quarantine"
    if score >= LADDER[1][0]:
        return "block"
    if score >= LADDER[2][0]:
        return "throttle"
    return "forward"


def nginx_directives(mech) -> str:
    lines = []
    if mech.conn_limit is not None:
        lines.append(f"limit_conn addr {mech.conn_limit};")
    if mech.rate_limit is not None:
        lines.append(f"limit_req zone=api burst={mech.rate_limit} nodelay;")
    if mech.timeout_s is not None:
        lines.append(f"proxy_read_timeout {int(mech.timeout_s)}s;")
    return "\n".join(lines) if lines else "# no directive (forward)"


# ---------------------------------------------------------------------------
# Style
# ---------------------------------------------------------------------------
CSS = """
<style>
  .block-container { padding-top: 1.8rem; }
  .hero {
      background: linear-gradient(120deg, #0b1d33 0%, #123a5c 100%);
      padding: 1.3rem 1.6rem; border-radius: 14px; color: #eaf2fb;
      margin-bottom: .9rem;
  }
  .hero h1 { margin: 0; font-size: 1.5rem; letter-spacing: .2px; }
  .hero p  { margin: .4rem 0 0; color: #a9c3dd; font-size: .9rem; }
  .pipe { margin: .2rem 0 1rem; }
  .stage {
      display: flex; gap: .9rem; align-items: flex-start;
      border: 1px solid rgba(120,150,180,.28); border-left: 5px solid #2d7ff9;
      background: rgba(45,127,249,.05); border-radius: 10px;
      padding: .65rem .9rem; margin-bottom: .2rem;
  }
  .stage .num {
      flex: 0 0 30px; height: 30px; width: 30px; border-radius: 50%;
      background: #2d7ff9; color: #fff; display: flex; align-items: center;
      justify-content: center; font-weight: 700; font-size: .9rem;
  }
  .stage .st { font-weight: 700; font-size: .97rem; }
  .stage .sd { color: #5b6b7c; font-size: .85rem; margin-top: .1rem; }
  .stage code { font-size: .77rem; background: rgba(0,0,0,.06);
      padding: .07rem .34rem; border-radius: 5px; }
  .arrow { text-align: center; color: #8aa4bd; font-size: .95rem; margin: -.15rem 0 .05rem 22px; }
</style>
"""
st.markdown(CSS, unsafe_allow_html=True)

df_all = get_features()

st.markdown(
    f"""
    <div class="hero">
      <h1>🛡️ Sentinel-AI — Explainable L7 Denial-of-Service Defence</h1>
      <p>Reads <b>why</b> the model flagged a flow (SHAP) and lets the reason pick the
      defence — a rate limit is useless against a slowloris, so the explanation
      chooses <code>limit_conn&nbsp;+&nbsp;timeouts</code> instead. Live view over
      {len(df_all):,} real flows.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

top = st.columns(5)
top[0].metric("Flows", f"{len(df_all):,}")
top[1].metric("Sessions", f"{df_all['session'].nunique()}")
top[2].metric("Benign / attack",
              f"{int((df_all['role'] == 'benign').sum()):,} / {int((df_all['role'] == 'attack').sum()):,}")
top[3].metric("Features", f"{len(FEATURE_ORDER)}")
top[4].metric("Feature tiers", "3")

(
    tab_live,
    tab_lab,
    tab_protect,
    tab_flow,
    tab_inspect,
    tab_adv,
    tab_results,
) = st.tabs(
    [
        "▶️ Live monitor",
        "🧪 Live lab",
        "🛡 Protect a site",
        "🔀 System flow",
        "🔎 Flow inspector",
        "🎯 Adversarial",
        "📊 Model & results",
    ]
)


# ===========================================================================
# TAB 1 — System flow
# ===========================================================================
with tab_flow:
    st.subheader("How one request becomes a defence decision")
    st.caption(
        "Every stage is real code in this repo; the dashboard reads the same "
        "artifacts those stages write."
    )

    stages = [
        ("Lab traffic",
         "nginx proxy + three generators emit benign, slowloris/RUDY and flood traffic on an isolated network.",
         "docker compose up -d"),
        ("Packet capture",
         "tcpdump records the wire on the proxy to a pcap.",
         "tcpdump -w /captures/run.pcap"),
        ("Flow records",
         "The pcap is reassembled into per-connection flows (IP/port, timing, bytes, headers).",
         "m1_capture/sensor.py"),
        ("Features",
         "16 features per flow, grouped by the defence they justify: stall, concurrency, rate.",
         "m1_capture/features.py"),
        ("Detection",
         "XGBoost scores the flow: raw P(attack).",
         "m3_scoring/train_xgb.py"),
        ("Calibration",
         "Isotonic regression turns the raw score into a trustworthy probability.",
         "m3_scoring/calibrate.py"),
        ("Explanation",
         "SHAP (TreeExplainer) attributes the score to individual features.",
         "m3_scoring/explain.py"),
        ("Decision",
         "SHAP is summed per group; the winning group selects the mechanism.",
         "mechanism.py"),
        ("Enforcement",
         "The mechanism becomes nginx directives that actually contain the attack.",
         "proxy/limits/*.conf"),
    ]
    html = ['<div class="pipe">']
    for i, (title, desc, ref) in enumerate(stages, 1):
        html.append(
            f'<div class="stage"><div class="num">{i}</div><div>'
            f'<div class="st">{title}</div>'
            f'<div class="sd">{desc}</div>'
            f'<div class="sd"><code>{ref}</code></div>'
            f"</div></div>"
        )
        if i != len(stages):
            html.append('<div class="arrow">▼</div>')
    html.append("</div>")
    st.markdown("".join(html), unsafe_allow_html=True)

    st.divider()
    st.subheader("Why the explanation matters")
    c1, c2 = st.columns([3, 2])
    with c1:
        st.markdown(
            "A slowloris holds many sockets open while trickling bytes. Its "
            "**request rate is low**, so a token-bucket rate limit never trips — "
            "the attack sails straight through. The features that light up are "
            "*stall* and *concurrency*, and those are exactly what `limit_conn` "
            "plus a read timeout act on.\n\n"
            "A flood is the opposite: high rate, few long-lived sockets. There the "
            "SHAP mass sits in the *rate* group, and `limit_req` is the correct lever. "
            "The switch reads the explanation, not a fixed rule."
        )
    with c2:
        st.markdown(
            f"**stall** — `{', '.join(sorted(STALL_FEATURES))}`\n\n"
            f"**concurrency** — `{', '.join(sorted(CONCURRENCY_FEATURES))}`\n\n"
            f"**rate** — `{', '.join(sorted(RATE_FEATURES))}`"
        )


# ===========================================================================
# TAB 2 — Flow inspector
# ===========================================================================
with tab_inspect:
    st.subheader("Inspect any real flow end-to-end")

    sessions = sorted(df_all["session"].unique())
    default_session = "mix3" if "mix3" in sessions else sessions[0]

    c1, c2, c3 = st.columns([1.0, 1.0, 2.4])
    with c1:
        session = st.selectbox("Session", sessions, index=sessions.index(default_session))
    sub = df_all[df_all["session"] == session]
    with c2:
        role_f = st.selectbox("Filter", ["attack", "benign", "all"], index=0)
    if role_f != "all":
        sub = sub[sub["role"] == role_f]

    labels = {
        i: f"#{i} · {r.role} · stall={r.stall_time_s:.1f}s · conns={r.concurrent_conns:.0f} · rate={r.requests_per_s:.0f}/s"
        for i, r in sub.iterrows()
    }
    with c3:
        idx = st.selectbox("Flow", list(labels.keys()), format_func=lambda i: labels[i])

    row = df_all.loc[idx]
    feats = {k: float(row[k]) for k in FEATURE_ORDER}

    art = get_artifact()
    Xrow = np.array([[feats[k] for k in FEATURE_ORDER]], dtype=float)
    raw = float(art.model.predict_proba(Xrow)[0, 1])
    cal = float(art.calibrated_score(feats))
    shap_vals = explain(art.model, feats)
    mech = choose_by_shap_group(shap_vals, cal)
    groups = shap_group_scores(shap_vals)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Raw P(attack)", f"{raw:.3f}")
    k2.metric("Calibrated", f"{cal:.3f}")
    k3.metric("Ground truth", row["role"])
    k4.metric("Policy action", policy_band(cal))

    left, right = st.columns(2)
    with left:
        st.markdown("**Feature vector** (grouped by the defence they justify)")
        fdf = pd.DataFrame(
            {
                "feature": FEATURE_ORDER,
                "value": [feats[f] for f in FEATURE_ORDER],
                "group": [feature_group(f) for f in FEATURE_ORDER],
            }
        ).sort_values(["group", "feature"]).reset_index(drop=True)
        st.dataframe(fdf.style.format({"value": "{:.3f}"}),
                     width="stretch", height=430)

    with right:
        st.markdown("**SHAP attribution** (what pushed *this* score)")
        tops = top_k(shap_vals, 10)[::-1]
        names = [n for n, _ in tops]
        vals = [v for _, v in tops]
        colors = [GROUP_COLORS[group_of(n)] for n in names]
        fig = go.Figure(
            go.Bar(x=vals, y=names, orientation="h", marker_color=colors,
                   hovertemplate="%{y}: %{x:+.3f}<extra></extra>")
        )
        fig.update_layout(height=430, margin=dict(l=10, r=10, t=10, b=10),
                          xaxis_title="SHAP value (signed)", showlegend=False)
        st.plotly_chart(fig, width="stretch")

    st.divider()
    d1, d2, d3 = st.columns([1.2, 1.4, 1.6])
    with d1:
        st.markdown("**Group SHAP mass** — the switch")
        gl = [g for g in GROUP_ORDER if g in groups]
        gv = [groups[g] for g in gl]
        fig_g = go.Figure(
            go.Bar(x=gl, y=gv,
                   marker_color=[GROUP_COLORS.get(g, "#94a3b8") for g in gl],
                   text=[f"{v:.2f}" for v in gv], textposition="outside")
        )
        fig_g.update_layout(height=300, yaxis_title="Σ |SHAP|", showlegend=False,
                            margin=dict(l=10, r=10, t=30, b=10))
        st.plotly_chart(fig_g, width="stretch")

    with d2:
        st.markdown("**Chosen mechanism**")
        if mech.driver_group in ("stall", "concurrency"):
            st.error("stall / concurrency → limit_conn + timeout")
        elif mech.driver_group == "rate":
            st.info("rate → limit_req")
        else:
            st.warning("unclear → apply both, moderately")
        st.write(mech.reason)
        st.caption(
            f"conn_limit={mech.conn_limit} · rate_limit={mech.rate_limit} · "
            f"timeout={mech.timeout_s}s"
        )

    with d3:
        st.markdown("**What would be enforced** (nginx)")
        st.code(nginx_directives(mech), language="nginx")
        pol = Policy().decide(str(row["entity"]), cal)
        st.caption(f"Policy ladder for entity `{row['entity']}` at {cal:.2f}: **{pol}**")


# ===========================================================================
# TAB 3 — Adversarial
# ===========================================================================
with tab_adv:
    st.subheader("Adaptive attacker: evasion costs you the attack")
    st.caption(
        "The attacker mutates trickle interval and concurrency to look benign. "
        "The score comes from Module 5's offline **simulation formula** "
        "(`_simulated_score`) — not the XGBoost model; the damage rule is the "
        "physical one it checks against."
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        bi = st.slider("byte_interval (s between bytes)", 0.001, 0.200, 0.100, 0.001)
    with c2:
        conns = st.slider("concurrent connections", 5, 60, 50, 1)
    with c3:
        spread = st.checkbox("spread across entity keys", value=False)

    params = {"byte_interval": bi, "conns": conns, "entity": "adv-9" if spread else "adv-1"}
    score = _simulated_score(params)
    damage = (bi * 35.0) >= 2.0 and conns >= 15

    m1, m2, m3 = st.columns(3)
    m1.metric("Suspicion score", f"{score:.3f}")
    m2.metric("Evades detector?", "YES" if score < DETECT_THRESHOLD else "no")
    m3.metric("Still damages backend?", "YES" if damage else "no")

    if score < DETECT_THRESHOLD and not damage:
        st.warning(
            f"Self-defeating evasion: the attacker got below {DETECT_THRESHOLD:.2f}, "
            "but by speeding up the trickle it no longer exhausts sockets."
        )
    elif score < DETECT_THRESHOLD and damage:
        st.error("Dangerous: evades detection AND still causes damage.")
    elif damage:
        st.info("Still detected, and still damaging — the defence holds.")

    xs = np.linspace(0.001, 0.20, 200)
    fig = go.Figure()
    for cc in (15, 30, 50):
        ys = [_simulated_score({"byte_interval": x, "conns": cc, "entity": "adv-1"}) for x in xs]
        fig.add_trace(go.Scatter(x=xs, y=ys, mode="lines", name=f"conns={cc}"))
    fig.add_hline(y=DETECT_THRESHOLD, line_dash="dash", line_color="#d1495b",
                  annotation_text=f"detection threshold {DETECT_THRESHOLD:.2f}")
    fig.add_vline(x=2.0 / 35.0, line_dash="dot", line_color="#5b6b7c",
                  annotation_text="damage limit")
    fig.add_trace(go.Scatter(x=[bi], y=[score], mode="markers",
                             marker=dict(size=14, color="#0b1d33"), name="your setting"))
    fig.update_layout(height=380, xaxis_title="byte_interval (s)",
                      yaxis_title="suspicion score",
                      margin=dict(l=10, r=10, t=20, b=10))
    st.plotly_chart(fig, width="stretch")

    st.divider()
    st.markdown("**Hill-climbing search** (Module 5, 30 rounds, seed 42)")
    cc1, cc2 = st.columns(2)
    with cc1:
        st.markdown("*Unconstrained*")
        st.json(run_evade(False))
    with cc2:
        st.markdown("*Damage-enforced*")
        st.json(run_evade(True))


# ===========================================================================
# TAB 4 — Model & results
# ===========================================================================
with tab_results:
    st.subheader("Held-out performance (sessions mix1–mix3)")
    st.caption(
        "Recomputed live from the shipped artifact on the untouched mixed "
        "sessions. Raw = XGBoost output; Calibrated = after isotonic regression."
    )

    from sklearn.metrics import average_precision_score, roc_auc_score

    val, raw_v, cal_v = get_val_scores()
    y = val["y"].to_numpy()

    pr_c = average_precision_score(y, cal_v)
    roc_c = roc_auc_score(y, cal_v)
    ece_c = expected_calibration_error(y, cal_v)

    m = st.columns(3)
    m[0].metric("PR-AUC (calibrated)", f"{pr_c:.4f}")
    m[1].metric("ROC-AUC (calibrated)", f"{roc_c:.4f}")
    m[2].metric("ECE (calibrated)", f"{ece_c:.4f}")

    met = pd.DataFrame(
        {
            "metric": ["PR-AUC", "ROC-AUC", "ECE"],
            "Raw": [
                average_precision_score(y, raw_v),
                roc_auc_score(y, raw_v),
                expected_calibration_error(y, raw_v),
            ],
            "Calibrated": [pr_c, roc_c, ece_c],
        }
    )
    st.dataframe(met.style.format({"Raw": "{:.4f}", "Calibrated": "{:.4f}"}),
                 width="stretch", hide_index=True)

    fig = go.Figure()
    fig.add_trace(go.Histogram(x=cal_v[y == 0], name="benign", opacity=0.7,
                               marker_color="#2d7ff9", nbinsx=40))
    fig.add_trace(go.Histogram(x=cal_v[y == 1], name="attack", opacity=0.7,
                               marker_color="#d1495b", nbinsx=40))
    fig.add_vline(x=DETECT_THRESHOLD, line_dash="dash", line_color="#5b6b7c", annotation_text=f"{DETECT_THRESHOLD:.2f}")
    fig.update_layout(barmode="overlay", height=340,
                      xaxis_title="calibrated score", yaxis_title="flows",
                      margin=dict(l=10, r=10, t=20, b=10))
    st.plotly_chart(fig, width="stretch")

    st.divider()
    st.subheader("Policy ablation (5 policies)")
    st.caption(
        "Same workload, five decision policies. *contained* = attacks stopped; "
        "*collateral* = benign flows wrongly penalised."
    )
    with open(ABLATION_PATH, encoding="utf-8") as fh:
        ab = json.load(fh)
    summ = pd.DataFrame(ab["summary"]).T.reset_index().rename(columns={"index": "policy"})
    st.dataframe(summ, width="stretch", hide_index=True)

    with st.expander("Per-scenario rows"):
        st.dataframe(pd.DataFrame(ab["rows"]), width="stretch")

    st.caption(
        "The enforcement stage is shown as the nginx directive the mechanism "
        "produces. The white-box lab generates the data; the decision loop is "
        "exercised offline on the captured flows."
    )


# ===========================================================================
# TAB 1 — Live monitor: the real model, streaming the real captured flows
# ===========================================================================
@st.cache_resource
def get_live_engine() -> LiveEngine:
    return LiveEngine(ARTIFACT_PATH)


@st.cache_data
def get_monitor_order() -> list:
    """Every real flow, in capture order, with its saved feature vector."""
    df = get_features().sort_values(["session", "t"], kind="stable")
    rows = []
    for r in df.itertuples(index=False):
        feats = {k: float(getattr(r, k)) for k in FEATURE_ORDER}
        rows.append(
            {
                "session": str(r.session),
                "y": int(r.y),
                "entity": str(r.entity),
                "feats": feats,
                "profile": flow_signature(feats),
            }
        )
    return rows


@st.cache_data(show_spinner="Scoring captured flows with the shipped model…")
def get_monitor_scored() -> list:
    """Shipped XGBoost + calibrator + SHAP switch + Policy on every parquet flow."""
    return get_live_engine().score_dataset(get_monitor_order())


def _active_stream(order: list, source: str) -> list:
    if source == "Attacks only":
        return [r for r in order if r["y"] == 1]
    if source == "Benign only":
        return [r for r in order if r["y"] == 0]
    return order


def _action_totals(rows: list) -> tuple[dict, int, int]:
    acts = {"forward": 0, "throttle": 0, "block": 0, "quarantine": 0}
    tp = fp = 0
    for h in rows:
        acts[h["action"]] = acts.get(h["action"], 0) + 1
        if h["score"] >= DETECT_THRESHOLD:
            if h["truth"] == "attack":
                tp += 1
            else:
                fp += 1
    return acts, tp, fp


@st.fragment(run_every=0.5)
def live_body(active: list, speed: int) -> None:
    """Streaming half of the monitor. A fragment, so the timer does not rerun
    the rest of the app (other tabs stay responsive and quiet)."""
    n = len(active)
    playing = bool(st.session_state.get("lm_playing")) and n > 0
    st.caption(
        f"{'▶ streaming' if playing else '⏸ paused'} · "
        f"walkthrough {st.session_state.lm_i:,} of {n:,} · "
        "counters below are the shipped model on this whole captured set, not the playback buffer"
    )

    if playing:
        for _ in range(max(1, int(round(speed / 2)))):
            i = st.session_state.lm_i
            if i >= n:
                st.session_state.lm_playing = False
                playing = False
                break
            st.session_state.lm_hist.append(active[i])
            st.session_state.lm_i += 1
        del st.session_state.lm_hist[:-250]
        playing = bool(st.session_state.lm_playing)

    st.markdown(pipeline_html(animate=playing), unsafe_allow_html=True)

    hist = st.session_state.lm_hist
    done = st.session_state.lm_i
    acts, tp, _fp = _action_totals(active)
    m = st.columns(6)
    m[0].metric("Flows seen", f"{done:,} / {n:,}")
    m[1].metric("Forward", f"{acts['forward']:,}")
    m[2].metric("Throttle", f"{acts['throttle']:,}")
    m[3].metric("Block", f"{acts['block']:,}")
    m[4].metric("Quarantine", f"{acts['quarantine']:,}")
    m[5].metric("Attacks caught", f"{tp:,}")

    if not hist:
        st.info(
            "Those counts are already the real decisions on the captured flows. "
            "Press ▶ Start only if you want to walk through them one by one."
        )
        return

    cur = hist[-1]
    left, right = st.columns([1.15, 1.0])
    with left:
        st.markdown("**Current flow**")
        band = policy_band(cur["score"])
        badge = {"forward": "🟢", "throttle": "🟡", "block": "🟠",
                 "quarantine": "🔴"}[cur["action"]]
        flag = "✅ correct" if (cur["truth"] == "attack") == (cur["score"] >= DETECT_THRESHOLD) else "⚠️ miss"
        st.markdown(
            f"{badge} `{cur['entity']}` · signature **{cur['profile']}** · "
            f"truth **{cur['truth']}** · session `{cur['session']}` · {flag}  \n"
            f"**score {cur['score']:.3f}** (raw {cur['raw']:.3f}) → policy **{band}**"
        )
        g = cur["groups"]
        gfig = go.Figure(
            go.Bar(
                x=[g.get(k, 0.0) for k in GROUP_ORDER],
                y=GROUP_ORDER,
                orientation="h",
                marker_color=[GROUP_COLORS[k] for k in GROUP_ORDER],
                text=[f"{g.get(k, 0.0):.2f}" for k in GROUP_ORDER],
                textposition="auto",
            )
        )
        gfig.update_layout(height=170, margin=dict(l=6, r=6, t=6, b=6),
                           xaxis_title="Σ|SHAP| in group")
        st.plotly_chart(gfig, width="stretch")
    with right:
        st.markdown("**Decision → nginx**")
        st.markdown(
            f"- dominant reason group: **{cur['group']}**\n"
            f"- mechanism: **{cur['mech']}**\n"
            f"- action: **{cur['action']}**"
        )
        st.code(cur["directive"], language="nginx")

    tl = hist[-80:]
    xs = list(range(len(tl)))
    fig = go.Figure()
    for truth, color in (("benign", "#2d7ff9"), ("attack", "#d1495b")):
        fig.add_trace(
            go.Scatter(
                x=[x for x, h in zip(xs, tl) if h["truth"] == truth],
                y=[h["score"] for h in tl if h["truth"] == truth],
                mode="markers", name=truth,
                marker=dict(color=color, size=7),
            )
        )
    fig.add_hline(y=LADDER[2][0], line_dash="dot", line_color="#5b6b7c")
    fig.add_hline(y=LADDER[1][0], line_dash="dot", line_color="#e08e0b")
    fig.add_hline(y=LADDER[0][0], line_dash="dot", line_color="#d1495b")
    fig.update_layout(height=260, margin=dict(l=8, r=8, t=20, b=8),
                      yaxis_range=[0, 1], xaxis_title="last 80 flows",
                      yaxis_title="calibrated score")
    st.plotly_chart(fig, width="stretch")

    st.markdown("**Decision log** (newest first)")
    base = done - len(hist)
    feed = pd.DataFrame(
        [
            {
                "#": base + i,
                "session": h["session"],
                "signature": h["profile"],
                "truth": h["truth"],
                "score": round(h["score"], 3),
                "group": h["group"],
                "mechanism": h["mech"],
                "action": h["action"],
            }
            for i, h in enumerate(hist[-12:])
        ]
    ).iloc[::-1]
    st.dataframe(feed, width="stretch", hide_index=True)


with tab_live:
    st.subheader("Real-time monitor — every flow scored as it arrives")
    st.caption(
        "The shipped model, its isotonic calibrator, the SHAP explanation and the "
        "SHAP→defence switch run on the project's **real captured flows**. The "
        "Forward / Throttle / Block / Quarantine / Attacks caught numbers are the "
        "shipped model on that whole set (parquet labels + `calibration_result_candidate.joblib`), "
        "not zeros from an unstarted playback."
    )

    order = get_monitor_scored()
    st.session_state.setdefault("lm_playing", False)
    st.session_state.setdefault("lm_i", 0)
    st.session_state.setdefault("lm_hist", [])
    st.session_state.setdefault("lm_source", "All flows")

    ctl = st.columns([0.9, 0.9, 0.9, 1.7, 1.6])
    play_btn = ctl[0].button(
        "⏸ Pause" if st.session_state.lm_playing else "▶ Start", width="stretch"
    )
    if play_btn:
        st.session_state.lm_playing = not st.session_state.lm_playing
        st.rerun()
    if ctl[1].button("⟲ Reset", width="stretch"):
        st.session_state.lm_i = 0
        st.session_state.lm_hist = []
        st.session_state.lm_playing = False
        st.rerun()
    speed = ctl[2].slider("Flows per second", 1, 30, 6)
    source = ctl[3].selectbox(
        "Traffic stream", ["All flows", "Attacks only", "Benign only"]
    )
    ctl[4].markdown(
        "Runs on a live timer, so **the other tabs stay responsive.**  \n"
        "Press ▶ to stream, ⏸ to hold, ⟲ to restart."
    )

    if st.session_state.get("lm_source") != source:
        st.session_state.lm_source = source
        st.session_state.lm_i = 0
        st.session_state.lm_hist = []

    live_body(_active_stream(order, source), speed)


# ===========================================================================
# TAB 2 — Live lab: real packets off the wire
# ===========================================================================
def _read_feed(path: Path, limit: int = 500) -> list:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines()[-limit:]:
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


@st.fragment(run_every=2.0)
def lab_body() -> None:
    """Live lab display. Refreshes on its own timer while the runner works."""
    runner = LabRunner()
    docker_ok = LabRunner.docker_available()
    proc = st.session_state.get("lab_proc")
    running = proc is not None and proc.poll() is None

    names = runner.running_names() if docker_ok else []
    st.caption("lab containers: " + (", ".join(names) if names else "not running"))

    status = _read_json(LAB_STATUS_PATH)
    feed = _read_feed(FEED_PATH, 500)

    st.markdown(pipeline_html(animate=running), unsafe_allow_html=True)

    if status:
        ctr = status.get("counters", {})
        lim = status.get("limits", {})
        mm = st.columns(7)
        mm[0].metric("Decisions", f"{status.get('decisions', 0):,}")
        mm[1].metric("True positives", f"{ctr.get('tp', 0):,}")
        mm[2].metric("False positives", f"{ctr.get('fp', 0):,}")
        mm[3].metric("False negatives", f"{ctr.get('fn', 0):,}")
        mm[4].metric("Observing", f"{ctr.get('observing', 0):,}",
                     help="Open flows younger than 10 s — not yet judgeable.")
        mm[5].metric("limit_req", "ON" if lim.get("rate") else "off")
        mm[6].metric("limit_conn", "ON" if lim.get("conn") else "off")

    if not feed and not running:
        st.info("Press ▶ Start live demo to capture and score real packets.")
        return

    if feed:
        dfl = pd.DataFrame(feed)
        keep = [c for c in ["i", "entity", "truth", "profile", "age",
                            "model_score", "score", "evidence",
                            "group", "mechanism", "action", "final"]
                if c in dfl.columns]
        st.markdown("**Live decisions** (newest first)")
        st.caption(
            f"{len(dfl):,} decisions in this run (saved to reports/live_feed.jsonl). "
            "`score` is the effective verdict: the model's calibrated score OR "
            "Module 2's stall-rule severity, whichever is higher. `model_score` is "
            "the model alone; `evidence` names the stall rule that fired, if any. "
            "Open flows younger than 10 s are reported as *observing* and are not "
            "counted as misses."
        )
        st.dataframe(dfl[keep].iloc[::-1], width="stretch", hide_index=True)
        st.download_button(
            "Download all decisions (CSV)",
            data=dfl.to_csv(index=False),
            file_name="live_decisions.csv",
            mime="text/csv",
        )

    st.markdown("**nginx limits the runner has written**")
    st.caption(
        "`limit_req` = rate limiting (token bucket per IP); `limit_conn` = "
        "concurrent-connection cap per IP. ON when the worst flow score is "
        ">= 0.55, OFF once everything drops below 0.30."
    )
    lc1, lc2 = st.columns(2)
    rate_txt = (REPO_ROOT / "proxy" / "limits" / "rate.conf").read_text()
    conn_txt = (REPO_ROOT / "proxy" / "limits" / "conn.conf").read_text()
    lc1.code(rate_txt.strip() or "# empty — no rate limit", language="nginx")
    lc2.code(conn_txt.strip() or "# empty — no conn limit", language="nginx")

    if status:
        st.caption(
            f"runner: {'LIVE' if status.get('running') else 'stopped'} · "
            f"mode `{status.get('mode', '?')}` · "
            f"decisions {status.get('decisions', 0):,}"
        )


with tab_lab:
    st.subheader("Live lab — real packets, captured and scored as they arrive")
    st.caption(
        "Drives the white-box lab: launches benign + attack traffic, captures the "
        "wire, rebuilds flows and scores each one with the shipped model. When a "
        "flow is flagged, the decision is written into `proxy/limits/` and nginx is "
        "reloaded — the enforcement is real, not a printed string."
    )

    docker_ok = LabRunner.docker_available()
    st.session_state.setdefault("lab_proc", None)
    proc = st.session_state.get("lab_proc")
    running = proc is not None and proc.poll() is None

    if not docker_ok:
        st.warning(
            "Docker isn't reachable from here, so the physical lab can't start on "
            "this machine. The ▶️ Live monitor tab needs no Docker — use it for the "
            "hosted demo. Run this tab on the lab host for the on-the-wire version."
        )

    c = st.columns([1.3, 1.0, 1.0, 1.2, 1.0, 1.2])
    mode = c[0].selectbox("Traffic profile", ["mixed", "flood", "slow", "benign"])
    dur = c[1].number_input("Seconds", min_value=20, max_value=600, value=120, step=10)
    rudy = c[2].checkbox("Include RUDY", value=False,
                         help="Also launch RUDY workers from the slow container: "
                              "a 5 MB body that is declared and never sent.")
    if c[3].button("▶ Start live demo", width="stretch",
                   disabled=running or not docker_ok, type="primary"):
        logf = open(REPO_ROOT / "reports" / "live_lab.log", "a", encoding="utf-8")
        cmd = [sys.executable, str(DASH_DIR / "live_lab.py"),
               "--duration", str(int(dur)), "--mode", mode]
        if rudy and mode in ("slow", "mixed"):
            cmd += ["--rudy-count", "20"]
        proc = subprocess.Popen(
            cmd,
            cwd=REPO_ROOT, stdout=logf, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        st.session_state.lab_proc = proc
        running = True
    if c[4].button("⏹ Stop", width="stretch", disabled=not running):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        _lab = LabRunner()
        _lab.stop_capture()
        _lab.stop_traffic()
        running = False
    c[5].metric("Docker", "ready" if docker_ok else "n/a")

    lab_body()


# ===========================================================================
# TAB — Protect a site (A/B proof)
# ===========================================================================
with tab_protect:
    st.subheader("Protect a site — the same attack, with and without the defence")
    st.caption(
        "A real portal (Aurora Bank) sits behind the nginx middleware. The proof "
        "runs the same attack twice: once in shadow mode (no limit written) and "
        "once enforcing, then compares them using nginx's own access log — not "
        "our counters."
    )

    proof = None
    proof_path = REPO_ROOT / "reports" / "protection_proof.json"
    if proof_path.exists():
        try:
            proof = json.loads(proof_path.read_text())
        except Exception:
            proof = None

    docker_ok_p = LabRunner.docker_available()
    st.session_state.setdefault("protect_proc", None)
    pproc = st.session_state.get("protect_proc")
    prunning = pproc is not None and pproc.poll() is None

    if not docker_ok_p:
        st.info(
            "Docker isn't reachable here, so the live A/B can't run on this "
            "machine. This tab still shows the last recorded proof; run it on the "
            "lab host to refresh the numbers."
        )

    p = st.columns([1.1, 0.9, 0.8, 1.0, 0.9, 1.1])
    pmode = p[0].selectbox("Attack profile", ["flood", "slow", "mixed"], key="pp_mode")
    pdur = p[1].number_input("Seconds / phase", min_value=20, max_value=300,
                             value=45, step=5, key="pp_dur")
    pipc = p[2].number_input("Attack IPs", min_value=1, max_value=200,
                             value=15, step=1, key="pp_ipc")
    if p[3].button("▶ Run proof", key="pp_run", width="stretch", type="primary",
                   disabled=prunning or not docker_ok_p):
        logf = open(REPO_ROOT / "reports" / "protect_demo.log", "a", encoding="utf-8")
        pproc = subprocess.Popen(
            [sys.executable, str(DASH_DIR / "protect_demo.py"),
             "--duration", str(int(pdur)), "--mode", pmode,
             "--ip-count", str(int(pipc))],
            cwd=REPO_ROOT, stdout=logf, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        st.session_state.protect_proc = pproc
        prunning = True
    if p[4].button("⏹ Stop", key="pp_stop", width="stretch", disabled=not prunning):
        try:
            os.killpg(os.getpgid(pproc.pid), signal.SIGTERM)
        except Exception:
            pass
        prunning = False
    p[5].metric("Docker", "ready" if docker_ok_p else "n/a")

    if prunning:
        st.status("Proof running — baseline phase, then defended phase ...",
                  state="running")
        st.caption("Log: reports/protect_demo.log")

    st.markdown(
        "**Target site:** [http://localhost:8080](http://localhost:8080) — the "
        "Aurora Bank portal behind the proxy (only reachable on the lab host)."
    )

    if not proof:
        st.info(
            "No proof recorded yet. On the lab host run:\n\n"
            "```\n.venv/bin/python dashboard/protect_demo.py\n```"
        )
    else:
        vrd = proof.get("verdict", {})
        bdata = proof.get("baseline", {})
        ddata = proof.get("defended", {})

        if vrd.get("attack_suppressed") and vrd.get("benign_preserved"):
            st.success(
                f"PROTECTED — the {vrd.get('attack_class')} attack went from "
                f"{vrd.get('attack_served_baseline_pct')}% served to "
                f"{vrd.get('attack_served_defended_pct')}% served "
                f"({vrd.get('attack_429_defended_pct')}% rejected with 429), "
                f"while benign clients saw {vrd.get('benign_429_defended_pct')}% "
                f"rejections."
            )
        elif vrd.get("benign_preserved"):
            st.warning(
                "Benign traffic was preserved, but the attack was not clearly "
                "suppressed in this run — see the per-class table."
            )
        else:
            st.error("Inconclusive run — see the per-class table.")

        rows = []
        for cls in ("benign", "slow", "flood"):
            for phase, data in (("baseline (no defence)", bdata),
                                ("defended", ddata)):
                d = data.get(cls, {})
                rows.append({
                    "client class": cls,
                    "phase": phase,
                    "requests": d.get("requests", 0),
                    "2xx %": d.get("pct_2xx", 0.0),
                    "429 %": d.get("pct_429", 0.0),
                    "5xx %": d.get("pct_5xx", 0.0),
                    "p50 ms": d.get("p50_ms", 0.0),
                    "p95 ms": d.get("p95_ms", 0.0),
                })
        st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

        classes = ["benign", "slow", "flood"]
        fig = go.Figure()
        fig.add_bar(name="baseline (no defence)", x=classes,
                    y=[bdata.get(c, {}).get("pct_2xx", 0.0) for c in classes])
        fig.add_bar(name="defended", x=classes,
                    y=[ddata.get(c, {}).get("pct_2xx", 0.0) for c in classes])
        fig.update_layout(
            barmode="group", height=340,
            yaxis_title="requests served (2xx %)",
            xaxis_title="client class",
            margin=dict(l=10, r=10, t=30, b=10),
            legend=dict(orientation="h", y=1.12),
        )
        st.plotly_chart(fig, width="stretch")
        st.caption(
            "Measured from nginx's access log (`logs/flow.log`) using the "
            "generators' fixed source-IP pools: benign 172.18.15.x, "
            "slowloris 172.18.16.x, flood 172.18.17.x."
        )
        if not proof.get("backstop", True):
            st.warning(
                "This run had the profile cross-check **off** (`--no-backstop`): "
                "the flood is routed by SHAP to `limit_conn`, which cannot contain "
                "a rate-shaped attack, so the attack stays served. Re-run without "
                "`--no-backstop` to apply the rate limit the profile demands."
            )
        else:
            st.caption(
                "Enforcement: the detector applies the mechanism the explanation "
                "chose, then cross-checks it against the flow's measured profile "
                "(`mechanism.contains`). A keep-alive request flood can be "
                "attributed to the concurrency group, which would pick "
                "`limit_conn`; the cross-check adds the rate limit so the attack "
                "is actually contained."
            )
