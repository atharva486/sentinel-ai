"""m5_sandbox: Module 5 - Sandbox, Adversarial, Integration.

Components:
- replay.py: Quarantine and replay at original speed against sandbox-backend.
- feedback.py: Active learning feedback loop (did-damage as label -> retrain -> evaluate).
- adversarial/evade.py: Black-box adaptive attacker (hill-climbing on traffic parameters).
- bench.py: End-to-end benchmark and demonstration harness.
"""

__version__ = "0.1.0"
