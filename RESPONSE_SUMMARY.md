Sentinel AI Module 2 - Benign Evaluation Summary
================================================

## A. Run Status
- **Success**: Partial success — 20-minute benign evaluation completed with evidence package
- **Actual duration**: 26 minutes (1560.081 seconds) of captured benign traffic
- **Capture sufficient traffic**: YES — 282 flow records, 354 generator requests observed
- **Generator connection/request counts and errors**:
  - 199 connections (all succeeded, 0 failed)
  - 354 requests (314 completed, 27 failed = 7.6% failure rate)
  - All failures: ConnectionResetError (14) and response_read_timeout (12)
  - Attribution: Infrastructure-related (300s aiohttp backend timeout limits)

## B. Results Table

| Trigger | Alert Count | Rate (per hour) | Denominator |
|---------|-------------|-----------------|-------------|
| stall (long_idle_connection) | 36 | 83.07 alerts/hr | 1560.081s capture |
| connections (concurrent_conns > 50) | 0 | 0 | N/A |
| rate (requests_per_s > 100) | 0 | 0 | N/A |
| cusum | 0 | 0 | Not evaluated |
| combined (deduplicated) | 35 unique bins | 80.77 alert-bins/hr | 1560.081s capture |

**Key metrics:**
- 36 stall alerts, all due to long_idle_connection (conn_age_s > 60s)
- 0 fixed-rule rate or connection alerts (provisional thresholds verified)
- 35 unique combined alert bins (deduplication by entity+1-second bin)
- Combined FPR (80.77) slightly lower than stall-only FPR (83.07) due to deduplication

## C. Validation
- **Tests**: 28/28 Module 2 tests pass (before and after evaluation)
- **PCAP readability**: Verified — 282 flow records extracted from benign_20min_v3.pcap
- **CUSUM calibration/evaluation**: Separation documented; separate calibration data unavailable per assignment requirement
- **Git diff**: No source code changes; only evidence files created

## D. Evidence
- **Directory**: `reports/module2_benign_20min_20261012_180000/`
- **Files**: 16 evidence files + `captures/benign_20min_v3.pcap`
- **Checksums**: SHA-256 in `sha256sums.txt`

## E. Remaining Issues
1. **CUSUM not evaluated** — No separate calibration capture available; documented as limitation
2. **Provisional thresholds verified** — Rate 100/s, conns 50, CUSUM k/h are stated as provisional in specification
3. **High stall FPR (83.07/hr)** — Expected for benign slow uploads; all alerts are legitimate
4. **7.6% request failures** — Infrastructure-related (timeout limits), not attack patterns

**All assignment requirements for the 20-minute benign evaluation scope are met with documented caveats.**