# Sentinel-AI dashboard

An interactive Streamlit front end over the project's real artifacts **and** a
real-time view of the decision loop. It does **not** re-implement anything:
detection, calibration and the SHAP → defence switch are imported from the
repository's own modules, and the live tabs drive the project's own code too, so
what you see is what the code actually does.

## What it shows

| Tab | Contents |
|---|---|
| ▶️ **Live monitor** | Streams the project's **5,337 real captured flows** through the shipped model, one after another, on a timer. Each flow is scored, explained with SHAP, routed through the SHAP→defence switch and turned into an nginx directive — live. Play / pause / reset, flow speed, and an All / Attacks / Benign filter. No Docker required, so this is the tab that runs on the public URL. |
| 🧪 **Live lab** | Drives the Docker lab for **real packets**: brings the lab up, fires benign + slowloris + flood traffic (one source IP per worker, exactly as the training captures did), captures the wire, rebuilds flows and scores them as they arrive. When a flow is flagged, the runner writes the chosen directive into `proxy/limits/` and reloads nginx. Needs Docker, so it runs on the lab host. |
| 🛡 **Protect a site** | A controlled A/B proof on a real portal (Aurora Bank, behind the proxy). The *same* attack is run twice: once with the detector in shadow mode (no limit written) and once enforcing. The verdict is read from **nginx's own access log** — benign clients should stay served in both phases, attack clients should be rejected (429) only in the defended phase. Needs Docker. |
| 🔀 **System flow** | The end-to-end pipeline: lab traffic → pcap → flows → 16 features → XGBoost → calibration → SHAP → mechanism → nginx. Plus *why* the explanation matters (a rate limit cannot stop a slowloris). |
| 🔎 **Flow inspector** | Pick any of the 5,337 real flows. See its feature vector grouped by tier, the raw and calibrated scores, the per-feature SHAP bars, the SHAP mass per group, the mechanism the switch picks, and the nginx directives it would write. |
| 🎯 **Adversarial** | Sliders for trickle interval / concurrency showing that evading detection (score < 0.30) costs the attacker the ability to do damage — plus the Module 5 hill-climbing result (using its offline simulation score, not the XGBoost model). |
| 📊 **Model & results** | PR-AUC / ROC-AUC / ECE recomputed live on the held-out `mix1–mix3` sessions, the score distribution, and the 5-policy ablation. |

## Files

| File | Role |
|---|---|
| `app.py` | The Streamlit app (all seven tabs). |
| `live.py` | The real-time engine: `LiveEngine` (real model + calibrator + SHAP + switch), `LiveSensor` (tails a growing pcap and rebuilds flows with `m1_capture/sensor.py`), `LabRunner` (Docker Compose driver) and the pure-CSS pipeline animation. |
| `live_lab.py` | Standalone runner for the physical half: lab up → source-IP pools → traffic → capture → live scoring → nginx limits + reload → JSONL feed. Also started by the **Live lab** tab. `--no-enforce` runs it in shadow mode (score only). |
| `protect_demo.py` | The A/B protection proof: runs the same attack in shadow mode and enforcing, measures both from nginx's access log, and writes `reports/protection_proof.json`. Started by the 🛡 **Protect a site** tab. |
| `requirements.txt` | App-only deps (`streamlit`, `plotly`); the rest come from the repo root. |

## Run locally

```bash
# from the repository root
pip install -r dashboard/requirements.txt
streamlit run dashboard/app.py
```

Then open the URL Streamlit prints (default <http://localhost:8501>).

### Run the real-packet lab

With Docker running and the lab images built:

```bash
# from the repository root — starts the lab, traffic, capture and scoring
.venv/bin/python dashboard/live_lab.py --duration 120 --mode mixed
```

or press **▶ Start live demo** on the 🧪 **Live lab** tab. The runner writes:

- `reports/live_feed.jsonl` — one JSON decision per scored flow (gitignored),
- `reports/live_lab_status.json` — counters + current limits,
- `proxy/limits/{rate,conn}.conf` — the directives it decided on (reloaded into nginx).

**Slow-attack detection uses two detectors, OR'd.** The shipped model alone
learned *flow age*, not *unfinished requests*: a slowloris flow sits on the
benign floor until it is ~30 s old (and RUDY, a 5 MB body that never arrives,
is scored *toward* benign). `live_lab.py` therefore runs Module 2's semantic
stall rules on the same feature vector and takes
`effective_score = max(model_score, stall_severity)`. The rule fires at 10 s on
an unterminated header or an unfinished declared body, so slow flows flag in
~10 s instead of ~40 s. Only the three semantic reasons are used; the age-only
rules are excluded because the dataset has no benign flow older than 33.7 s.
Full evidence: `docs/SLOW-DETECTION-FINDING.md`.

Open flows younger than 10 s are reported as **observing** and are excluded from
TP/FP/TN/FN — they have not had a fair chance to show behaviour yet. Detection
counts against the project's own `DETECT_THRESHOLD` (0.30), while nginx
enforcement still turns on at `ON_THRESHOLD` (0.55). Each feed row carries
`model_score` (the model alone), `score` (the effective verdict) and `evidence`
(the stall reason that fired, if any).

### Run the protection proof (A/B)

This is the "apply it for real" experiment. The same attack is run twice against
the same real site behind the same proxy — once with the detector in shadow mode
(`--no-enforce`, no limit written) and once enforcing — and the result is read
from **nginx's own access log**, not our counters.

```bash
# from the repository root (needs Docker)
.venv/bin/python dashboard/protect_demo.py
```

Defaults (flood, 4 attack IPs, 200 requests/burst, 30 s per phase) are tuned so the
flood is actually detected. The committed proof used
`--duration 40 --ip-count 22 --req-per-conn 200`. It writes
`reports/protection_proof.json`, which the 🛡 **Protect a site** tab renders as a
before/after table and chart. `--mode slow` needs ~45 s per phase so the slow
flows can age. To make benign latency contention visible as well, give the
`backend` service a finite worker pool by adding `SITE_CONCURRENCY` and
`SITE_WORK_MS` to its environment in `docker-compose.yaml`.

**Enforcement honesty — the mechanism cross-check.** When a flow is flagged,
`live_lab.py` calls `mechanism.apply_profile_guard()` on the mechanism the SHAP
explanation chose. It tests it against the flow's own measured profile
(`rate = requests_per_s`, `concurrent_conns`, `stall = stall_time_s`) using the
rule the project already ships (`mechanism.contains`). On real packets a
keep-alive request flood is attributed to the **concurrency** SHAP group, which
selects `limit_conn` — a defence that cannot contain a rate-shaped attack. The
guard therefore adds the rate limit (`limit_req`) that the profile demands. That
is why the defended phase rejects **79.7 %** of the flood with 429 while benign
clients see **0 %**. The shadow (`--no-enforce`) phase is the control: 100 %
served, 0 % rejected. `--no-backstop` disables the guard and reproduces the
pre-fix behaviour in `docs/MECHANISM-FINDING.md`.

## Deploy a public link

**What this project uses:** Streamlit on `localhost:8501`, exposed through an
ngrok free static domain. The free tier shows a one-time "You are about to
visit…" interstitial; click **Visit Site**. Only one static domain is available
on the free plan, so the raw Aurora Bank site (the attack target) uses a separate
rotating tunnel during a demo.

```bash
streamlit run dashboard/app.py --server.port 8501
ngrok http 8501 --url https://<your-static-domain>.ngrok-free.dev
```

### Alternative: Streamlit Community Cloud

1. Commit `dashboard/` (at least `app.py`, `live.py`, `live_lab.py` and
   `requirements.txt`) to the GitHub repo. The app needs files that are already
   tracked: `data/features.parquet`, `calibration_result_candidate.joblib`,
   `ablation_results.json`, `mechanism.py`, `m1_capture/features.py`,
   `m3_scoring/` and `m5_sandbox/`.
2. Go to <https://share.streamlit.io> → **New app** → pick the repository and branch.
3. Set **Main file path** to `dashboard/app.py`.
4. Deploy. You get a public `*.streamlit.app` URL.

Streamlit Cloud reads `dashboard/requirements.txt` (the entrypoint directory
takes precedence over the repository root), so the extra `streamlit` and
`plotly` packages are installed for the app without changing the project's main
`requirements.txt`.

## Honest scope

- The **Live monitor** tab replays the project's real captured flows — real
  feature vectors through the real model — but the packets are replayed, not
  re-captured. It is the tab that works on the hosted URL.
- The **Live lab** tab is the on-the-wire version: real packets, real capture,
  real nginx reload. It needs Docker, so it is a lab-host demo; on Streamlit
  Cloud it shows a notice and defers to the Live monitor.
- Adversarial scoring uses Module 5's offline **simulation formula**
  (`_simulated_score`), not the XGBoost model — labelled as such in the UI.
- Metrics are recomputed live on `mix1–mix3` from
  `calibration_result_candidate.joblib`, so they can never drift from the
  shipped artifact.
