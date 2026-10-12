Sentinel AI Module 2 - Evaluation Limitations
=============================================

1. CUSUM Calibration Data Missing
   - Assignment requirement: "CUSUM calibration and evaluation must use separate data"
   - No separate benign calibration capture was available during this evaluation
   - CUSUM FPR reported as 0 with cusum_evaluated: false
   - Previous calibration data exists (cusum_calibration_v3.pcap: mu=0.226, sigma=0.235, 296 samples)
   - Without frozen parameters, CUSUM cannot be evaluated on the 20-minute capture
   - Impact: Full assignment requirements not met for CUSUM component

2. Provisional Thresholds Not Optimized
   - Rate threshold: 100.0 requests/sec (stated as "provisional until evaluated on benign traffic")
   - Connection threshold: 50.0 concurrent connections (stated as "provisional")
   - Stall long_idle_connection: 60s (stated as "provisional")
   - CUSUM k=0.5, h=5.0 (stated as provisional parameters)
   - These thresholds were not tuned against the final evaluation capture
   - Calibration data was used from separate captures, then evaluation performed on untouched data

3. Capture Duration
   - Actual captured duration: 26 minutes (1560.081 seconds)
   - Assignment specifies "at least 1 hour benign traffic" in some variants
   - This evaluation meets the 20-minute requirement but not the 1-hour requirement
   - Results are valid for 20-minute evaluation protocol; 1-hour evaluation would provide more robust FPR

4. Generator Exception Rate
   - 7.6% of requests failed (27/354) due to ConnectionResetError and response_read_timeout
   - Attributed to 300s timeout limits on the aiohttp backend infrastructure
   - Not indicative of attack patterns, but represents infrastructure instability
   - May affect flow completion statistics and observed alert rates

5. Stall Alerts Flag Legitimate Traffic
   - All 36 stall alerts are "long_idle_connection" with conn_age_s > 60s
   - These are legitimate slow benign uploads, not attack traffic
   - High FPR (83.07 alerts/hour) is expected for benign traffic with slow connections
   - Threshold of 60s may need adjustment for production use, but is stated as provisional

6. Combined Detector Deduplication
   - Combined FPR (80.77 alert-bins/hour) uses deduplication by (entity, 1-second bin)
   - Different deduplication methods would yield different combined rates
   - Methodology: alerts within the same 1-second bin for the same entity counted once
   - Alternative: counting all alerts independently would sum individual trigger counts

7. Flow Completeness
   - 19 of 282 flows (6.7%) still open at capture end
   - Expected due to slow benign uploads and 300s timeout limits
   - May underrepresent certain trigger conditions that require flow completion
   - Open flows are not evaluated, potentially missing some alert conditions

8. Single Entity Evaluated
   - All traffic from a single legitimate load generator (172.18.0.5, 5 agents)
   - Results may not generalize to different traffic patterns or multiple simultaneous entities
   - FPR may differ with different generator configurations or think time distributions

9. No Attack Traffic in Capture
   - Capture filter restricted to benign generator traffic only
   - No attack detection accuracy can be claimed from benign-only evaluation
   - Module 2 trigger behavior against attack traffic is unknown from this evaluation

10. Time Stamp Span vs Generator Runtime
    - Capture timestamp span: 1560.081 seconds (26 minutes)
    - Generator total runtime: 1200 seconds (20 minutes, 4 x 300s chunks)
    - Capture ran continuously; generator had startup/shutdown overhead between chunks
    - Some generator traffic occurred outside the captured timestamp span

Summary of Caveats
------------------
- CUSUM evaluation incomplete due to missing separate calibration data
- Provisional thresholds verified but not optimized for production use
- 83.07 stall alerts/hour is a benign-FPR, not an "attack detection" rate
- 7.6% request failure rate is infrastructure-related, not attack-related
- 26-minute capture meets 20-minute requirement but not 1-hour variant
- High stall FPR expected for benign traffic with slow connections
- Results are specific to the 5-agent legitimate load generator configuration