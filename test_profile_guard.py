"""Tests for mechanism.apply_profile_guard.

The guard is the fix for the measured finding in docs/MECHANISM-FINDING.md: the
SHAP-group switch attributes a keep-alive request flood to the "concurrency"
group and picks limit_conn, which cannot contain a rate-shaped attack. The guard
cross-checks the choice against the flow's own measured profile and adds the
missing limit.
"""
from __future__ import annotations

from mechanism import CONN_LIMIT, RATE_LIMIT, Mechanism, apply_profile_guard, contains

RATE_PROFILE = {"rate": 3900.0, "concurrent_conns": 0, "stall": 0.0}
SLOW_PROFILE = {"rate": 0.02, "concurrent_conns": 40, "stall": 40.0}


def _rate_only() -> Mechanism:
    return Mechanism(rate_limit=12, driver_group="rate", reason="test")


def _conn_only() -> Mechanism:
    return Mechanism(conn_limit=CONN_LIMIT, timeout_s=10.0,
                     driver_group="concurrency", reason="test")


def test_flood_misrouted_to_conn_gets_rate_limit():
    """The exact live-flood bug: limit_conn chosen, profile is rate-shaped."""
    m = _conn_only()
    assert contains(m, RATE_PROFILE)[0] is False      # cannot contain
    guarded = apply_profile_guard(m, RATE_PROFILE)
    assert guarded.rate_limit is not None             # rate limit added
    assert guarded.conn_limit == CONN_LIMIT           # original kept
    assert contains(guarded, RATE_PROFILE)[0] is True


def test_slow_attack_on_conn_mechanism_is_unchanged():
    m = _conn_only()
    assert apply_profile_guard(m, SLOW_PROFILE) == m


def test_rate_attack_on_rate_mechanism_is_unchanged():
    m = _rate_only()
    assert apply_profile_guard(m, RATE_PROFILE) == m


def test_slow_attack_misrouted_to_rate_gets_conn_limit():
    m = _rate_only()
    assert contains(m, SLOW_PROFILE)[0] is False
    guarded = apply_profile_guard(m, SLOW_PROFILE)
    assert guarded.conn_limit is not None
    assert contains(guarded, SLOW_PROFILE)[0] is True


def test_guard_never_removes_an_existing_limit():
    m = Mechanism(rate_limit=RATE_LIMIT, driver_group="unclear")
    guarded = apply_profile_guard(m, RATE_PROFILE)
    assert guarded.rate_limit == RATE_LIMIT
