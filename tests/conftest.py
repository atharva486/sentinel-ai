import os
import sys

# Add the repository root and all code package directories to sys.path so that
# tests in any subfolder can import from m1_capture, m2_triggers, m3_scoring,
# m5_sandbox, dashboard, and top-level modules regardless of where pytest is
# invoked from.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Code package directories
for _d in ("m1_capture", "m2_triggers", "m3_scoring", "m5_sandbox", "dashboard"):
    _p = os.path.join(ROOT, _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Test subdirectories (so tests can import each other, e.g. test_sensor)
for _d in ("m1_capture", "m2_triggers", "m3_scoring", "m5_sandbox", "mechanism", "dashboard", "root"):
    _p = os.path.join(ROOT, "tests", _d)
    if _p not in sys.path:
        sys.path.insert(0, _p)
