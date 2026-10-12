

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



\## Evaluation and false-positive rate



No one-hour benign-traffic evaluation has been recorded yet. Therefore,

measured false-positive rates are \*\*pending\*\* and must not be reported as

zero or estimated.



The evaluation must use at least one hour of purely benign traffic. Record

the duration, number of benign observations, number of false alerts, and

false-positive rate for each trigger and the combined detector.



CUSUM thresholds must be calibrated on benign traffic and then frozen before

the final evaluation.

