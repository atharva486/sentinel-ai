"""Tests for the live-lab stall gate (model OR Module 2 rule).

The live lab used to score with the model alone. The model learned *flow age*,
not *unfinished requests*: in the training set every benign flow is <= 33.7 s
old while every slowloris flow is 55-80 s old, so a slowloris flow sits on the
benign floor until it is ~30 s old. Module 2's stall rules are semantic, so
they fire from STALL_THRESHOLD_S (10 s) on the same feature vector.

These tests pin the three behaviours that make the OR safe:
  * an unfinished header past the window fires;
  * a *finished* header past the window does not;
  * nothing fires before the window;
and they pin the deliberate exclusion of the age-only rules, which were never
validated against long-lived benign keep-alives.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "dashboard"))

import live_lab  # noqa: E402


def _feats(**over) -> dict:
    """A plain, harmless flow: complete header, no body, one request."""
    f = {
        "conn_age_s": 12.0,
        "header_complete": 1.0,
        "bytes_declared": 0.0,
        "body_frac_sent": 1.0,
        "body_drip_rate_bps": 0.0,
        "requests_per_conn_so_far": 1.0,
        "concurrent_conns": 1.0,
        "time_to_first_byte": 0.0,
    }
    f.update(over)
    return f


def test_incomplete_header_fires_after_window():
    got = live_lab.stall_evidence(
        _feats(conn_age_s=12.0, header_complete=0.0), "10.0.0.1", "f-slow", 100.0
    )
    assert got is not None
    event, reasons = got
    assert "header_incomplete" in reasons
    assert event.severity >= 0.85
    # Strong enough to clear both the detection and enforcement thresholds.
    assert event.severity >= live_lab.COUNT_THRESHOLD
    assert event.severity >= live_lab.ON_THRESHOLD


def test_complete_header_does_not_fire():
    """A normal 12 s keep-alive must not be flagged."""
    got = live_lab.stall_evidence(
        _feats(conn_age_s=12.0, header_complete=1.0), "10.0.0.2", "f-ok", 100.0
    )
    assert got is None


def test_nothing_fires_before_window():
    """An unfinished header younger than 10 s is still a legitimate in-flight
    request, not an attack."""
    got = live_lab.stall_evidence(
        _feats(conn_age_s=5.0, header_complete=0.0), "10.0.0.3", "f-young", 100.0
    )
    assert got is None


def test_rudy_body_drip_fires():
    """A 5 MB body declared with 0 % delivered and no progress: classic RUDY."""
    got = live_lab.stall_evidence(
        _feats(
            conn_age_s=12.0,
            bytes_declared=5_000_000.0,
            body_frac_sent=0.0,
            body_drip_rate_bps=0.0,
        ),
        "10.0.0.4",
        "f-rudy",
        100.0,
    )
    assert got is not None
    event, reasons = got
    assert "body_incomplete" in reasons
    assert event.severity >= live_lab.COUNT_THRESHOLD


def test_age_only_rules_are_deliberately_excluded():
    """`long_idle_connection` matches a completely normal 70 s keep-alive that
    has only made one request. Module 2 raises it, but the live gate must drop
    it: the dataset contains no benign flow older than 33.7 s, so this rule was
    never validated against real long-lived benign traffic."""
    got = live_lab.stall_evidence(
        _feats(conn_age_s=70.0, header_complete=1.0,
               requests_per_conn_so_far=1.0),
        "10.0.0.5",
        "f-keepalive",
        100.0,
    )
    assert got is None


def test_stall_mechanism_holds_sockets_and_sets_timeout():
    """Stall verdicts must be contained by a connection cap + timeout, never by
    rate limiting (a slowloris sends too few requests for rate limiting to see
    it)."""
    m = live_lab._stall_mechanism(["header_incomplete"])
    assert m.conn_limit == live_lab.CONN_LIMIT
    assert m.timeout_s == 10.0
    assert m.rate_limit is None
    assert m.driver_group == "stall"
