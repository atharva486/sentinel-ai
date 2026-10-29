

\# Module 2 — Cheap Triggers



\## 1. Sliding-window rate counter



\*\*Implementation:\*\* `m2\_triggers/counters.py`



Each entity has a Redis sorted-set counter. A Lua script removes expired hits,

checks the current count, and records a new hit only if the limit has not

been reached. The script is atomic, preventing concurrent requests from

bypassing the limit.



The window and request limit are configurable. The default is a one-second

window with a limit of 100 requests.



\## 2. CUSUM change-point detector



\*\*Implementation:\*\* `m2\_triggers/cusum.py`



CUSUM accumulates evidence of sustained upward or downward changes from a

baseline. The implementation uses `mu`, `sigma`, `k`, and `h`, and resets

its accumulated scores after detecting a change.



The baseline and thresholds must be calibrated using benign traffic.

A legitimate traffic spike can also trigger an alert.



\## 3. Stall detector



\*\*Implementation:\*\* `m2\_triggers/stall.py`



The stall detector checks incomplete headers, incomplete request bodies,

slow body drips, long-idle connections, slow first-byte times, connections

with no requests, and excessive concurrent connections.



Current thresholds include:

\- Stall age: 10 seconds

\- Slow first byte: over 10 seconds

\- Soft concurrent-connection limit: 50

\- Slow body drip: below 100 bytes per second for declared bodies over 10,000 bytes



Legitimate slow clients and large uploads can resemble attacks. The false

positive rate must be measured on benign traffic.



\## 4. Fixed rules



\*\*Implementation:\*\* `m2\_triggers/rules.py`



The fixed rules emit rate alerts when `requests\_per\_s` exceeds the configured

rate threshold and connection alerts when `concurrent\_conns` exceeds the

configured connection threshold.



The default thresholds are 100 requests per second and 50 concurrent

connections. These values are provisional until evaluated on benign traffic.



## Evaluation and false-positive rate

A 20-minute benign evaluation was recorded (26.0 minutes of captured traffic,
282 flow records) in `reports/module2_benign_20min_20261012_180000/` and
re-verified in `reports/module2_benign_final_verification_20261012_195007/`.
CUSUM was calibrated on a separate capture (`captures/cusum_calibration_v3.pcap`,
296 samples) and then frozen for evaluation.

Measured on that benign capture:

| Trigger | Alerts | Rate |
|---|---:|---:|
| stall (`long_idle_connection`) | 36 | 83.07 alerts/hour |
| connections (`concurrent_conns > 50`) | 0 | 0 |
| rate (`requests_per_s > 100`) | 0 | 0 |
| CUSUM | 114 | 1,561 sampled intervals |
| combined (deduplicated by entity + 1 s bin) | 35 | 80.77 alert-bins/hour |

These are **benign-traffic false-positive measurements**, not attack-detection
FPR. The 36 stall alerts are legitimate slow benign uploads with
`conn_age_s > 60 s`; the fixed-rule thresholds were provisional and were verified
not to fire. Full caveats: `FINAL_VERIFICATION_RESPONSE.md` and
`reports/module2_benign_final_verification_20261012_195007/limitations.md`.
