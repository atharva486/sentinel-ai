#!/usr/bin/env python3
"""Run CUSUM calibration and evaluation with separate data."""
import subprocess
import sys

result = subprocess.run(
    [sys.executable, 'evaluate_cusum.py',
     '--calibration', 'captures/cusum_calibration_v3.pcap',
     '--evaluation', 'captures/benign_20min_v3.pcap',
     '--k', '0.113',
     '--h', '1.175',
     '--output', 'cusum_eval_frozen.json'],
    capture_output=True, text=True, cwd=r'C:\Users\Ayush Lokare\Projects\AI_pro\sentinel-ai'
)

print("=== STDOUT ===")
print(result.stdout)
print("=== STDERR ===")
print(result.stderr)
print(f"\n=== RETURN CODE: {result.returncode} ===")

with open('cusum_eval_frozen_output.txt', 'w') as f:
    f.write(result.stdout)
    f.write(result.stderr)