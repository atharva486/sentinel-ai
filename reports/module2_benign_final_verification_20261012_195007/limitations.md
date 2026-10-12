# \# Sentinel AI Module 2 - Evaluation Limitations

#

# \## 1. CUSUM Calibration and Evaluation

#

# \- \*\*Assignment requirement:\*\* CUSUM calibration and evaluation must use separate data.

# \- A separate calibration capture is available: `captures/cusum\_calibration\_v3.pcap` (295 seconds, 296 samples).

# \- Calibration parameters: mean ≈ 0.22635 and standard deviation ≈ 0.23491.

# \- CUSUM evaluation was performed on the separate benign evaluation capture using the calibrated parameters.

# \- Input parameters: \\(k=0.5\\), \\(h=5.0\\).

# \- Internally scaled thresholds: \\(k\\approx0.113\\), \\(h\\approx1.175\\).

# \- The evaluation produced \*\*114 CUSUM alert events across 1,561 sampled intervals\*\*.

# \- The observed alert frequency is a benign-traffic alert rate, not a validated production false-positive rate.

#

# \## 2. Provisional Thresholds Not Optimized

#

# \- Rate threshold: 100 requests/second (provisional).

# \- Connection threshold: 50 concurrent connections (provisional).

# \- Stall `long\_idle\_connection` threshold: 60 seconds (provisional).

# \- CUSUM parameters: \\(k=0.5\\), \\(h=5.0\\) (provisional).

# \- These thresholds were verified during evaluation but have not been established as production-ready.

# \- Further calibration and testing across representative benign and attack traffic are required before production use.

#

# \## 3. Capture Duration

#

# \- Actual capture duration: 1,560.081 seconds (approximately 26 minutes).

# \- The capture meets the 20-minute evaluation requirement.

# \- It does not meet assignment variants requiring at least one hour of benign traffic.

# \- A longer capture would provide additional evidence about alert frequency over time.

#

# \## 4. Generator Exceptions and Incomplete Requests

#

# \- Requests attempted: 369.

# \- Requests completed: 354.

# \- Requests not completed: 15.

# \- Total recorded exceptions: 29, comprising 14 `ConnectionResetError` and 15 `response\_read\_timeout` exceptions.

# \- The exceptions were attributed to the 300-second timeout limits in the aiohttp backend infrastructure.

# \- Incomplete requests and exceptions are different measurements and should not be treated as interchangeable counts.

# \- These issues may affect flow completion statistics and observed alert rates.

#

# \## 5. Stall Alerts on Legitimate Traffic

#

# \- The benign evaluation produced 36 `long\_idle\_connection` alerts.

# \- All 36 alerts had `conn\_age\_s > 60` seconds.

# \- Observed stall alert frequency: approximately \*\*83.07 alerts/hour\*\*.

# \- These alerts occurred during a benign-only evaluation and therefore represent alerts on legitimate traffic.

# \- The 60-second threshold may need adjustment to reduce false positives, but any change must be validated against separate evaluation data.

#

# \## 6. Combined Detector Deduplication

#

# \- The combined detector produced 35 unique alert bins after deduplication.

# \- Observed combined alert-bin frequency: approximately \*\*80.77 alert-bins/hour\*\*.

# \- Deduplication grouped alerts by entity and one-second time bin.

# \- Multiple alerts from the same entity within the same one-second bin were counted once.

# \- Different deduplication methods may produce different reported rates.

# \- These figures describe the evaluation's alert frequency; they do not establish attack-detection accuracy.

#

# \## 7. Flow Completeness

#

# \- Total flow records: 282.

# \- Closed flows observed: 263.

# \- Flows still open at capture end: 19 (approximately 6.7%).

# \- Open flows may not provide all the information available after a connection closes.

# \- Some trigger conditions may therefore be underrepresented in the observed results.

#

# \## 8. Single Entity Evaluated

#

# \- All captured traffic came from the legitimate load generator at `172.18.0.5`, configured with five agents.

# \- The results may not generalize to different traffic patterns, think-time distributions, generator configurations, or multiple simultaneous entities.

# \- Additional benign evaluations are needed to assess how alert frequency changes under different workloads.

#

# \## 9. No Attack Traffic in Capture

#

# \- The capture filter restricted evaluation to benign generator traffic.

# \- No attack traffic was included in this evaluation.

# \- Consequently, \*\*attack-detection accuracy, attack recall, and the ability to distinguish attacks from benign traffic have not been established by this capture\*\*.

# \- Module 2 trigger behavior under attack traffic requires a separate, authorized lab evaluation.

#

# \## 10. Capture Timestamp Span vs. Generator Runtime

#

# \- Capture timestamp span: 1,560.081 seconds (approximately 26 minutes).

# \- Generator runtime: 1,200 seconds (20 minutes, four 300-second chunks).

# \- The capture ran continuously, while the generator ran in separate chunks.

# \- Startup, shutdown, and transitions between chunks may explain differences between the capture span and generator runtime.

#

# \## 11. Test Verification

#

# \- The final verification report records that all 28 Module 2 tests passed.

# \- The reported tests cover CUSUM, rules, stall detection, sampling, timed CUSUM, connection signals, and trigger integration.

# \- This test result reflects the recorded verification run; it should not be interpreted as proof of production readiness or attack-detection accuracy.

#

# \## Summary of Caveats

#

# \- CUSUM calibration and evaluation used separate captures, but the observed benign alert frequency is not a validated production false-positive rate.

# \- Thresholds remain provisional and require further validation.

# \- The 36 stall alerts correspond to approximately 83.07 alerts/hour on the benign capture.

# \- The combined detector produced 35 deduplicated alert bins, approximately 80.77 bins/hour.

# \- The generator recorded 369 attempted requests, 354 completed requests, 15 incomplete requests, and 29 exceptions.

# \- The capture lasted approximately 26 minutes, meeting the 20-minute requirement but not a one-hour requirement.

# \- Nineteen of 282 flows remained open at capture end.

# \- Results are specific to the tested five-agent benign workload.

# \- No attack-detection accuracy is claimed because the evaluation contained no attack traffic.

#

# \*\*Overall conclusion:\*\* Module 2's benign evaluation and verification evidence document the observed detector behavior under the tested conditions. Further testing with longer benign captures, additional workload configurations, and separate authorized attack captures is needed before making production-readiness or attack-detection performance claims.
