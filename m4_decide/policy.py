#!/usr/bin/env python3
"""
m4_decide/policy.py — Score -> action, with HYSTERESIS.

Without a deadband, a score oscillating around 0.6 flips the action on every
request. You would have built an amplifier, not a defence.

There is no "challenge" rung. An API client cannot solve a CAPTCHA, so challenging
an API caller is a self-inflicted outage. The earlier draft had one; it is gone.
The ladder is strictly: forward -> throttle -> block -> quarantine.
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# The policy ladders. Four rungs, hysteresis deadbands, per-entity state.
#
# Ordered MOST SEVERE FIRST:
#   index 0: (enter 0.80, exit 0.70) -> "quarantine"
#   index 1: (enter 0.55, exit 0.46) -> "block"
#   index 2: (enter 0.30, exit 0.24) -> "throttle"
#   index 3: (enter 0.00, exit 0.00) -> "forward"
#
# A fresh entity starts at index 3 ("forward") and walks toward index 0 to escalate.
# De-escalation requires score falling strictly below the exit threshold.
# ---------------------------------------------------------------------------
LADDER = [
    (0.80, 0.70, "quarantine"),
    (0.55, 0.46, "block"),
    (0.30, 0.24, "throttle"),
    (0.00, 0.00, "forward"),
]


class Policy:
    """Score -> action, with hysteresis so the action cannot flap."""

    def __init__(self):
        self._state: dict[str, int] = {}

    def decide(self, entity: str, score: float) -> str:
        """Evaluate score against the ladder and return the selected action.

        Hysteresis Mechanism:
        - ESCALATION: An entity walks toward index 0 (more severe) whenever the
          score clears the NEXT rung's enter threshold:
            while current > 0 and score >= LADDER[current - 1][0]:
                current -= 1
        - DE-ESCALATION: An entity walks toward index len-1 (less severe) ONLY
          once the score drops strictly below the CURRENT rung's exit threshold:
            while current < len(LADDER) - 1 and score < LADDER[current][1]:
                current += 1

        Why the draft's range(current, len(LADDER)) was broken:
          LADDER is ordered most severe first (index 0 = quarantine, index 3 = forward).
          Looping range(current, len(LADDER)) walks toward index 3 (LESS severe).
          A fresh entity at index 3 tested LADDER[3][0] == 0.00, which every score passes,
          immediately returning 'forward' for every score including 0.99 and blocking
          all escalation. The corrected while loops enforce proper directional traversal.
        """
        current = self._state.get(entity, len(LADDER) - 1)

        # Escalate toward index 0 while score clears enter threshold of higher rung
        while current > 0 and score >= LADDER[current - 1][0]:
            current -= 1

        # De-escalate toward lower rungs only when score drops below exit threshold
        while current < len(LADDER) - 1 and score < LADDER[current][1]:
            current += 1

        self._state[entity] = current
        return LADDER[current][2]

    def state_of(self, entity: str) -> int:
        """Return the current ladder index for an entity (defaults to lowest rung)."""
        return self._state.get(entity, len(LADDER) - 1)

    def reset(self, entity: str | None = None) -> None:
        """Reset state for a specific entity or all entities."""
        if entity is None:
            self._state.clear()
        else:
            self._state.pop(entity, None)
