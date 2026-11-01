#!/usr/bin/env python3
"""
test_policy.py — verify the hysteresis policy ladder (Section 6.4).

Requirements verified:
  1. No "challenge" rung: strictly forward -> throttle -> block -> quarantine.
  2. Escalation works: fresh entity escalates properly on scores (0.05, 0.38, 0.60, 0.99).
  3. Continuous escalation: walks up the ladder without resets.
  4. Deadband hysteresis: holds action inside deadband and de-escalates only on exit.
  5. Flapping prevention: an oscillating score (0.57–0.62) changes action at most once.
  6. Per-entity state isolation.

Run:  python3 test_policy.py
"""
from __future__ import annotations

import sys
from m4_decide.policy import LADDER, Policy

FAIL = []


def check(label: str, cond: bool, detail: str = ""):
    if cond:
        print(f"  PASS  {label}")
    else:
        print(f"  FAIL  {label}   got: {detail}")
        FAIL.append(label)


def main() -> None:
    print("\n=== 1. NO CHALLENGE RUNG IN LADDER ===")
    rungs = [action for _, _, action in LADDER]
    print(f"        rungs in LADDER: {rungs}")
    check("no 'challenge' rung in LADDER", "challenge" not in rungs)
    check("ladder has exactly 4 rungs", len(LADDER) == 4, str(len(LADDER)))
    check("ladder actions match forward->throttle->block->quarantine",
          set(rungs) == {"forward", "throttle", "block", "quarantine"})

    print("\n=== 2. POLICY LADDER ESCALATION ON FRESH ENTITIES ===")
    p1 = Policy()
    a1 = p1.decide("e1", 0.05)
    check("score 0.05 on fresh entity forwards", a1 == "forward", a1)

    p2 = Policy()
    a2 = p2.decide("e2", 0.38)
    check("score 0.38 on fresh entity throttles (crosses 0.30)", a2 == "throttle", a2)

    p3 = Policy()
    a3 = p3.decide("e3", 0.60)
    check("score 0.60 on fresh entity blocks (crosses 0.55)", a3 == "block", a3)

    p4 = Policy()
    a4 = p4.decide("e4", 0.99)
    check("score 0.99 on fresh entity quarantines (crosses 0.80)", a4 == "quarantine", a4)

    print("\n=== 3. SEQUENTIAL ESCALATION WITHOUT RESET ===")
    ramp = Policy()
    walked = [ramp.decide("e-ramp", s) for s in (0.05, 0.40, 0.60, 0.90)]
    print(f"        scores [0.05, 0.40, 0.60, 0.90] -> {walked}")
    check("escalates cleanly across all four rungs",
          walked == ["forward", "throttle", "block", "quarantine"], str(walked))

    print("\n=== 4. DEADBAND HYSTERESIS & DE-ESCALATION ===")
    band = Policy()
    # Enter block at 0.60 (>= 0.55)
    act_enter = band.decide("e-band", 0.60)
    check("initial score 0.60 enters 'block'", act_enter == "block", act_enter)

    # Score drops to 0.50 (below 0.55 enter, but above 0.46 exit) -> must hold block
    act_hold = band.decide("e-band", 0.50)
    check("score 0.50 holds 'block' (inside 0.55/0.46 deadband)", act_hold == "block", act_hold)

    # Score drops to 0.44 (below 0.46 exit) -> de-escalates to throttle
    act_drop = band.decide("e-band", 0.44)
    check("score 0.44 de-escalates to 'throttle' (below 0.46)", act_drop == "throttle", act_drop)

    # Score drops to 0.28 (inside 0.30/0.24 deadband) -> must hold throttle
    act_hold_thr = band.decide("e-band", 0.28)
    check("score 0.28 holds 'throttle' (inside 0.30/0.24 deadband)", act_hold_thr == "throttle", act_hold_thr)

    # Score drops to 0.20 (below 0.24 exit) -> de-escalates to forward
    act_fwd = band.decide("e-band", 0.20)
    check("score 0.20 de-escalates to 'forward' (below 0.24)", act_fwd == "forward", act_fwd)

    print("\n=== 5. FLAPPING PREVENTION (0.57 - 0.62) ===")
    # Oscillating sequence around the 0.55 boundary
    seq = [0.58, 0.62, 0.59, 0.61, 0.57, 0.60, 0.58, 0.62]
    pol = Policy()
    actions = [pol.decide("e-flap", s) for s in seq]
    changes = sum(1 for a, b in zip(actions, actions[1:]) if a != b)
    print(f"        scores:  {seq}")
    print(f"        actions: {actions}")
    print(f"        flaps/changes: {changes}")

    check("fresh entity escalates out of 'forward' on call one", actions[0] != "forward", actions[0])
    check("action settles on 'block'", actions[0] == "block", actions[0])
    check("oscillating score 0.57-0.62 changes action at most once",
          changes <= 1, f"{changes} changes: {actions}")

    print("\n=== 6. ENTITY STATE ISOLATION ===")
    p_multi = Policy()
    p_multi.decide("attacker", 0.95)   # quarantine
    p_multi.decide("legit", 0.05)      # forward
    check("attacker is quarantined", p_multi.decide("attacker", 0.75) == "quarantine")
    check("legit entity remains forwarded", p_multi.decide("legit", 0.05) == "forward")

    print()
    if FAIL:
        print(f"FAILED ({len(FAIL)} checks): {FAIL}")
        sys.exit(1)
    print("ALL POLICY LADDER & HYSTERESIS CHECKS PASSED.")


if __name__ == "__main__":
    main()
