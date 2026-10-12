Sentinel AI Module 2 - Benign 20-Minute Evaluation Summary
===========================================================

Evaluation Date: 2026-10-12
Capture File: captures/benign_20min_v3.pcap
Capture Duration: 1560.081 seconds (26.0 minutes)
Evaluator: evaluate_fpr_time_based.py

GENERATOR STATISTICS (4 x 300s chunks = 1200s total runtime):
  Part 1 (5 min): 46 connections, 82 requests, 0 failures
  Part 2 (5 min): 35 connections, 63 requests, 8 failures (ConnectionResetError)
  Part 3 (5 min): 67 connections, 119 requests, 4 failures
  Part 4 (5 min): 51 connections, 90 requests, 14 failures
  TOTAL: 199 connections, 354 requests, 26 failures (all ConnectionResetError or response_read_timeout)

CAPTURE STATISTICS:
  Unique flow records: 282
  Closed flows observed: 263
  Still open at capture end: 19
  Total flow evaluations: 282
  Capture timestamp span: 1560.081 seconds

PER-TRIGGER ALERT COUNTS AND FPR:
  stall: 36 alerts
    FPR per hour: 83.07 alerts/hour
    Primary reason: long_idle_connection (all 36 alerts)
    All stall alerts had conn_age_s > 60s, mostly > 70s
  connections: 0 alerts (fixed-rate rule threshold not exceeded)
  rate: 0 alerts (fixed-connection rule threshold not exceeded)
  cusum: 0 alerts (no calibration data provided)

COMBINED DETECTOR:
  Unique (entity, 1-second bin) alert pairs: 35
  Combined FPR per hour: 80.77 alert-bins/hour
  Deduplication: alerts within 1-second bins per entity counted once

OBSERVATIONS:
  - 282 flows evaluated across 26-minute capture
  - 36 stall alerts, all due to long_idle_connection (>60s idle)
  - No rate or connection threshold alerts triggered
  - CUSUM not evaluated (no separate calibration capture)
  - 19 flows still open at capture end (expected for slow benign uploads)

KEY FINDINGS:
  1. Benign traffic from 5 workers over 20 minutes produces ~354 requests
  2. Stall detector flags 36 long-idle connections (conn_age_s > 60s)
  3. Fixed rate/connection thresholds not exceeded during benign traffic
  4. Combined FPR (80.8 alert-bins/hour) is lower than stall FPR (83.1 alerts/hour)
  5. All stall alerts are "long_idle_connection" - legitimate slow benign uploads
  6. Generator exceptions are mostly response_read_timeout (expected with 300s limits)

EVALUATION COMPLETENESS: COMPLETE
  - 20+ minute benign capture achieved (26 min actual)
  - Sufficient flow records (282) for FPR calculation
  - Per-trigger and combined detector metrics reported
  - Alert definitions and denominators clearly specified
  - Capture preserved in original location