"""Re-export package over m1_capture (the canonical capture package).

The repo's working capture code lives in m1_capture/.  Tests and the project
docs refer to capture/.  This package re-exports m1_capture so both import
styles resolve to the same modules; there is only one source of truth.
"""
