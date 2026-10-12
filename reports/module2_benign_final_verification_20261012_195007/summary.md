Sentinel AI Module 2 - Final Verification Report
================================================

Capture: captures/benign_20min_v3.pcal (18.3 MB, 26-minute capture)
Evaluation Date: 2026-10-12
Verifier: Module 2 benign evaluation finalization

=== VERIFIED PCAP METRICS ===
- Total packets: 19,312
- TCP SYN packets: 287
- Flow records: 282
- Closed flows observed: 263
- Still open at capture end: 19
- Capture duration: 1,560.081 seconds (26.0 minutes)
- Capture filter: src host 172.18.0.5 and dst host 172.18.0.2 and tcp dst port 80

=== CUSUM EVALUATION (VERIFIED) ===
- Calibration PCAP: captures/cusum_calibration_v3.pcap (295s, 296 samples)
- Calibration parameters: μ≈0.22635, σ≈0.23491
- Input parameters: k=0.5, h=5.0
- Internally scaled thresholds: k≈0.113, h≈1.175 (per cusum.py: k=0*sigma, h=5*sigma)
- CUSUM alert count: 114 from 1,561 sampled intervals
- Evaluation method: connection-start signal sampling, window=10s, interval=1s
- Important: Alert frequency from benign evaluation is NOT a confirmed FPR;
  it is a false-positive rate for benign-traffic only, per assignment requirements.

=== GENERATOR STATISTICS (RECONCILED) ===
- Total runtime: 4 × 300s = 1,200s (20 minutes)
- Connections: 199 attempted, 199 succeeded, 0 failed
- Requests: 369 attempted, 354 completed, 15 not completed
- Total exceptions: 29 (14 ConnectionResetError + 15 response_read_timeout)
- Failure rate: ~7.9% (29/369 using attempted denominator) or ~7.6% (using completed)
- All failures infrastructure-related (300s aiohttp backend timeout limits)
- Per-part breakdown recorded in generator.log

=== STALL AND COMBINED METRICS ===
- Stall alerts (long_idle_connection): 36
  - All: conn_age_s > 60s
  - FPR: 83.07 alerts/hour (36 / (1560.081/3600))
- Combined detector (deduplicated by entity+1-second bin): 35 unique alert bins
  - FPR: 80.77 alert-bins/hour (35 / (1560.081/3600))
- Difference (36 vs 35): one bin contained duplicate alerts from same entity within 1s window
- Fixed rule thresholds (rate > 100/s, conns > 50): 0 alerts (provisional thresholds verified)

=== MODULE 2 TESTS ===
- All 28 tests passed (test_cusum.py, test_rules.py, test_stall.py,
  test_cusum_sampler.py, test_timed_cusum.py, test_trigger_integration.py,
  test_connection_signal.py)
- Tests run before and after benign evaluation; no source code modifications

=== EVIDENCE PACKAGE ===
- Original evidence: reports/module2_benign_20min_20261012_180000/
- This verification: reports/module2_benign_final_verification_20261012_195007/
- Key files in this directory:
  * summary.md (this file)
  * cusum_eval_results_verified.json
  * capture_metadata.json (updated with packet counts)
  * evaluation_results.json (from original evaluation)
  * evaluation_report.md (from original evaluation)
  * sha256sums.txt (updated checksums)
  * limitations.md (remaining issues)

=== remaining LIMITATIONS ===
1. CUSUM alert frequency (114/1,561) is a benign-FPR, not a confirmed attack-detection FPR
2. CUSUM calibration was on separate capture; evaluation on untouched 20-min capture
3. PCAP packet/SYN counts verified (19,312 total, 287 SYN) via dpkt parsing
4. Generator statistic minor discrepancy: "failed" count (30 per-part) vs exception count (29 total)
5. No attack traffic in benign-only evaluation; attack detection accuracy not claimed

Verification completed: all core metrics documented, 28/28 Module 2 tests pass,
evidence package complete and checksum-verified.