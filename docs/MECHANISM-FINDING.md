# Finding: the SHAP→mechanism switch misroutes real request floods

Status: **measured**, fixed at the enforcement layer. This note is evidence for the
report; it does not change the model or the ablation artefact.

## What we saw

Same attack twice against the real site behind nginx (Aurora Bank, `protect_demo.py`), **before the fix**:

| phase | flood served | flood 429 |
|---|---:|---:|
| baseline (shadow) | 100.0 % | 0.0 % |
| defended | 100.0 % | 0.0 % |

The defence did **nothing**, even though the model detected the flood
(calibrated score ≈ 0.76). The reason is the *which-defence?* switch, not detection.

## Root cause

`mechanism.shap_group_scores` sums `abs(SHAP)` per feature group and lets the
largest group pick the defence. For a fast flood on a keep-alive connection the
largest groups are **stall** or **concurrency**, never **rate**:

* `requests_per_conn_so_far` is enormous on a keep-alive flood (measured ≈ 71 800
  on one connection) and lives in the **concurrency** group → picks `limit_conn`.
* `bytes_declared` carries a large `|SHAP|` for both flood and slow flows and lives
  in the **stall** group → picks `limit_conn`/timeouts.

Both select a defence that structurally cannot contain a rate-shaped attack.

## Measured, not assumed

Group-winner distribution over **real captured flows** (dataset `features.parquet`:
40 flagged flood, 40 flagged slowloris/rudy; plus the live capture). `R0` = current
code, `R1`/`R2` = candidate re-groupings:

| grouping | slow → | flood (dataset) → | flood (live) → |
|---|---|---|---|
| R0 current | stall 100 % | **stall 97 %** | **concurrency 100 %** |
| R1 `requests_per_conn_so_far`→rate | stall 100 % | stall 60 % / rate 40 % | **rate 100 %** |
| R2 R1 + `body_drip_rate_bps`→rate | stall 100 % | stall 60 % / rate 40 % | rate 100 % |

So re-grouping is **not** the robust lever: it fixes live flood routing but only
40 % of the dataset floods, and moving `requests_per_conn_so_far` to `rate` would
also flip the **synthetic** slowloris scenario in `ablation.py` to `rate`
(0.74 vs 0.70) — a regression against the reported result.

## Why the ablation looked fine

`ablation.py` is explicit that its scenarios are synthetic: it feeds hand-set SHAP
values (flood `requests_per_conn_so_far = 0.11`, `concurrent_conns = 40`,
`stall = 0`) into the switch. With those numbers flood → **rate** → `limit_req`.
On real packets the same feature dominates instead. The ablation is an
*illustration of the intended design*, not a measurement on captured traffic.

## Chosen fix (enforcement-layer cross-check)

`live_lab.py` now calls `mechanism.apply_profile_guard()` on the mechanism the
explanation chose. It tests that mechanism against the flow's **own measured
profile** (`rate = requests_per_s`, `concurrent_conns`, `stall = stall_time_s`)
using the rule the project already ships — `mechanism.contains()` ("can this
mechanism contain this attack?"). A flow is rate-shaped when
`requests_per_s > 20`; connection-holding when `concurrent_conns > 1` or
`stall_time_s > 5`. If the chosen mechanism cannot contain the profile, the
missing limit is added (`limit_req` and/or `limit_conn`).

This keeps the model, `features.py` group membership and `ablation_results.json`
untouched, and guarantees the runtime consequence (the site is actually protected)
without relying on the fragile attribution.

Verified (`reports/protection_proof.json`, flood mode, 40 s per phase, 22 attack
IPs, 200 requests/connection): flood served **100.0 % → 20.3 %**, rejected
**79.7 %** (429); benign rejected **0.0 %** and served **86.2 % → 89.3 %**. The
shadow (`--no-enforce`) phase is the control: the same attack is 100.0 % served
with 0.0 % rejected. `--no-backstop` disables the cross-check and reproduces the
pre-fix behaviour shown in the first table.

## Recommendation

Keep the cross-check as the enforcement guarantee. Present the synthetic ablation
as an illustration of intent, and this note as the measured reality on real
packets. If the switch is to be fixed natively, do it against the captured
distributions above (not the hand-set scenario numbers) and re-run the ablation.
