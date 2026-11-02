#!/usr/bin/env python3
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
from sklearn.metrics import average_precision_score, roc_auc_score

DASH_DIR = Path(__file__).resolve().parent
REPO_ROOT = DASH_DIR.parent
for _p in (REPO_ROOT, REPO_ROOT / "m1_capture", REPO_ROOT / "m3_scoring"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from m1_capture.features import (
    CONCURRENCY_FEATURES,
    FEATURE_ORDER,
    RATE_FEATURES,
    STALL_FEATURES,
)
from m3_scoring.calibrate import CalibrationResult
from m3_scoring.explain import explain, top_k
from mechanism import (
    DETECT_THRESHOLD,
    LADDER,
    Policy,
    choose_by_shap_group,
    group_of,
    shap_group_scores,
)

if str(DASH_DIR) not in sys.path:
    sys.path.insert(0, str(DASH_DIR))
from live import (
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

# Loads the saved detection model and calibrator.
@st.cache_resource
def get_artifact() -> CalibrationResult:
    return CalibrationResult.load(str(ARTIFACT_PATH))

# Reads the labelled flow data from parquet.
@st.cache_data
def get_features() -> pd.DataFrame:
    return pd.read_parquet(DATA_PATH)

# Returns raw and calibrated scores for held-out runs.
@st.cache_data
def get_val_scores():
    df = get_features()
    art = get_artifact()
    val = df[df["session"].isin(["runf", "rung"])].copy()
    if val.empty:
        return val, np.array([]), np.array([])
    X = val[FEATURE_ORDER].to_numpy(dtype=float)
    raw = art.model.predict_proba(X)[:, 1]
    cal = np.clip(art.calibrator.predict(raw), 0.0, 1.0)
    return val, raw, cal

# Maps a feature name to its defence group (stall, concurrency, rate, or other).
def feature_group(name: str) -> str:
    if name in STALL_FEATURES:
        return "stall"
    if name in CONCURRENCY_FEATURES:
        return "concurrency"
    if name in RATE_FEATURES:
        return "rate"
    return "other"

# Computes calibration error across probability bins.
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

# Turns a score into a policy action like forward, throttle, block, or quarantine.
def policy_band(score: float) -> str:
    if score >= LADDER[0][0]:
        return "quarantine"
    if score >= LADDER[1][0]:
        return "block"
    if score >= LADDER[2][0]:
        return "throttle"
    return "forward"

# Builds nginx limit directives from a mechanism decision.
def nginx_directives(mech) -> str:
    lines = []
    if mech.conn_limit is not None:
        lines.append(f"limit_conn addr {mech.conn_limit};")
    if mech.rate_limit is not None:
        lines.append(f"limit_req zone=api burst={mech.rate_limit} nodelay;")
    if mech.timeout_s is not None:
        lines.append(f"proxy_read_timeout {int(mech.timeout_s)}s;")
    return "\n".join(lines) if lines else "# no directive (forward)"

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
    tab_flow,
    tab_results,
) = st.tabs(
    [
        "▶️ Live monitor",
        "🧪 Live lab",
        "🔀 System flow",
        "📊 Model & results",
    ]
)

with tab_flow:
    st.subheader("How one request becomes a defence decision")
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

with tab_results:
    st.subheader("Held-out performance (sessions mix1–mix3)")

    from sklearn.metrics import average_precision_score, roc_auc_score

    val, raw_v, cal_v = get_val_scores()
    y = val["y"].to_numpy()

    pr_c = average_precision_score(y, cal_v)
    roc_c = roc_auc_score(y, cal_v)
    ece_c = expected_calibration_error(y, cal_v)

    # Calculates true positives, true negatives, false positives, and false negatives.
    def _confusion(scores: np.ndarray) -> tuple[int, int, int, int]:
        pred = scores >= DETECT_THRESHOLD
        tp = int(((pred) & (y == 1)).sum())
        tn = int((~pred & (y == 0)).sum())
        fp = int((pred & (y == 0)).sum())
        fn = int((~pred & (y == 1)).sum())
        return tp, tn, fp, fn

    tp_r, tn_r, fp_r, fn_r = _confusion(raw_v)
    tp_c, tn_c, fp_c, fn_c = _confusion(cal_v)

    m = st.columns(3)
    m[0].metric("PR-AUC (calibrated)", f"{pr_c:.4f}")
    m[1].metric("ROC-AUC (calibrated)", f"{roc_c:.4f}")
    m[2].metric("ECE (calibrated)", f"{ece_c:.4f}")

    met = pd.DataFrame(
        {
            "metric": ["PR-AUC", "ROC-AUC", "ECE", "TP", "TN", "FP", "FN"],
            "Raw": [
                average_precision_score(y, raw_v),
                roc_auc_score(y, raw_v),
                expected_calibration_error(y, raw_v),
                tp_r,
                tn_r,
                fp_r,
                fn_r,
            ],
            "Calibrated": [pr_c, roc_c, ece_c, tp_c, tn_c, fp_c, fn_c],
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

# Creates a cached live scoring engine for captured flows.
@st.cache_resource
def get_live_engine() -> LiveEngine:
    return LiveEngine(ARTIFACT_PATH)

# Orders every captured flow by session and time with its features.
@st.cache_data
def get_monitor_order() -> list:
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

# Scores all captured flows using the shipped model and calibrator.
@st.cache_data(show_spinner="Scoring captured flows with the shipped model…")
def get_monitor_scored() -> list:
    return get_live_engine().score_dataset(get_monitor_order())

# Filters flows by traffic stream: all, attacks only, or benign only.
def _active_stream(order: list, source: str) -> list:
    if source == "Attacks only":
        return [r for r in order if r["y"] == 1]
    if source == "Benign only":
        return [r for r in order if r["y"] == 0]
    return order

# Counts defence actions and true/false positives across flows.
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

# Renders the live monitor fragment with scores, gauges, and charts.
@st.fragment(run_every=0.5)
def live_body(active: list, speed: int) -> None:
    n = len(active)
    playing = bool(st.session_state.get("lm_playing")) and n > 0

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

    if st.session_state.get("lm_source") != source:
        st.session_state.lm_source = source
        st.session_state.lm_i = 0
        st.session_state.lm_hist = []

    live_body(_active_stream(order, source), speed)

# Reads the most recent lines from the live decisions feed file.
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

# Safely reads a JSON file, returning an empty dict if missing or bad.
def _read_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}

# Refreshes the live lab display with container status and decisions.
@st.fragment(run_every=2.0)
def lab_body() -> None:
    runner = LabRunner()
    docker_ok = LabRunner.docker_available()
    proc = st.session_state.get("lab_proc")
    running = proc is not None and proc.poll() is None

    names = runner.running_names() if docker_ok else []

    status = _read_json(LAB_STATUS_PATH)
    feed = _read_feed(FEED_PATH, 500)

    st.markdown(pipeline_html(animate=running), unsafe_allow_html=True)

    if status:
        ctr = status.get("counters", {})
        lim = status.get("limits", {})
        # Compute ROC-AUC and PR-AUC from feed
        y_true, y_score = [], []
        for entry in feed:
            truth = entry.get("truth")
            score = entry.get("score")
            if truth in ("attack", "benign") and score is not None:
                y_true.append(1 if truth == "attack" else 0)
                y_score.append(float(score))
        roc_auc = roc_auc_score(y_true, y_score) if len(set(y_true)) == 2 else float("nan")
        pr_auc = average_precision_score(y_true, y_score) if len(set(y_true)) == 2 else float("nan")
        mm = st.columns(10)
        mm[0].metric("Decisions", f"{status.get('decisions', 0):,}")
        mm[1].metric("True positives", f"{ctr.get('tp', 0):,}")
        mm[2].metric("True negatives", f"{ctr.get('tn', 0):,}")
        mm[3].metric("False positives", f"{ctr.get('fp', 0):,}")
        mm[4].metric("False negatives", f"{ctr.get('fn', 0):,}")
        mm[5].metric("Observing", f"{ctr.get('observing', 0):,}",
                     help="Open flows younger than 10 s — not yet judgeable.")
        mm[6].metric("ROC-AUC", f"{roc_auc:.3f}" if roc_auc == roc_auc else "n/a",
                     help="Area under ROC curve (1.0 = perfect, 0.5 = random)")
        mm[7].metric("PR-AUC", f"{pr_auc:.3f}" if pr_auc == pr_auc else "n/a",
                     help="Area under Precision-Recall curve (1.0 = perfect)")
        mm[8].metric("limit_req", "ON" if lim.get("rate") else "off")
        mm[9].metric("limit_conn", "ON" if lim.get("conn") else "off")

    if not feed and not running:
        st.info("Press ▶ Start live demo to capture and score real packets.")
        return

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

    c = st.columns([1.3, 1.0, 1.2, 1.0, 1.2])
    mode = c[0].selectbox("Traffic profile", ["mixed", "flood", "slow", "benign"],
                          key="lab_mode_select")
    dur = c[1].number_input("Seconds", min_value=20, max_value=600, value=120, step=10,
                            key="lab_duration_input")
    if c[2].button("▶ Start live demo", width="stretch",
                   disabled=running or not docker_ok, type="primary",
                   key="lab_start_button"):
        logf = open(REPO_ROOT / "reports" / "live_lab.log", "a", encoding="utf-8")
        cmd = [sys.executable, str(DASH_DIR / "live_lab.py"),
               "--duration", str(int(dur)), "--mode", mode]
        proc = subprocess.Popen(
            cmd,
            cwd=REPO_ROOT, stdout=logf, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        st.session_state.lab_proc = proc
        running = True
    if c[3].button("⏹ Stop", width="stretch", disabled=not running,
                   key="lab_stop_button"):
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        _lab = LabRunner()
        _lab.stop_capture()
        _lab.stop_traffic()
        running = False
    c[4].metric("Docker", "ready" if docker_ok else "n/a")

    st.divider()
    st.markdown("**Live decisions** (newest first)")
    if feed:
        dfl = pd.DataFrame(feed)
        keep = [c for c in ["i", "entity", "truth", "profile", "age",
                            "model_score", "score", "evidence",
                            "group", "mechanism", "action", "final"]
                if c in dfl.columns]
        st.dataframe(dfl[keep].iloc[::-1], width="stretch", hide_index=True)
        st.download_button(
            "Download all decisions (CSV)",
            data=dfl.to_csv(index=False),
            file_name="live_decisions.csv",
            mime="text/csv",
            key="lab_download_csv",
        )

with tab_lab:
    st.subheader("Live lab — real packets, captured and scored as they arrive")
    lab_body()