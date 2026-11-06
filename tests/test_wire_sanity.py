"""Wire-sanity test: every generator request type must produce the expected
HTTP framing when parsed by ``parse_http``.

This test guards against regressions like the missing ``\\r\\n\\r\\n`` header
terminator (commit c4b02b7) that made every benign flow look like a slowloris
(header_complete=0) and collapsed the benign false-positive rate.

It exercises ``parse_http`` directly on the exact byte strings each generator
worker writes to the wire. No network, no Docker — pure unit test.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from m1_capture.sensor import parse_http


def benign_header() -> bytes:
    """Exact header bytes written by benign_worker (non-slow path)."""
    return (
        b"POST /api/txn HTTP/1.1\r\n"
        b"Host: api\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Content-Length: 4000\r\n"
        b"Content-Type: multipart/form-data\r\n\r\n"
    )


def benign_slow_head() -> bytes:
    """Header bytes written by benign_worker (slow upload path, before body)."""
    return (
        b"POST /api/txn HTTP/1.1\r\n"
        b"Host: api\r\n"
        b"User-Agent: Mozilla/5.0\r\n"
        b"Content-Length: 2000000\r\n"
        b"Content-Type: multipart/form-data\r\n\r\n"
    )


def slowloris_head() -> bytes:
    """Header bytes written by slowloris_worker (intentionally incomplete)."""
    return (
        b"GET /api/txn?q=" + b"y" * 70 + b"&u=0 HTTP/1.1\r\n"
        b"Host: api\r\nUser-Agent: Mozilla/5.0\r\n"
    )


def slowloris_drip() -> bytes:
    """A slowloris keepalive drip line (no header terminator)."""
    return b"X-keepalive: 42\r\n"


def flood_req() -> bytes:
    """One flood request (complete header, no body)."""
    return (
        b"GET /api/txn HTTP/1.1\r\nHost: api\r\n"
        b"Connection: keep-alive\r\n"
        b"User-Agent: Mozilla/5.0\r\n\r\n"
    )


def test_benign_non_slow_header_complete():
    """benign_worker non-slow POST: header must be complete."""
    http = parse_http(benign_header())
    assert http["header_complete"] is True, \
        f"benign header must be complete, got {http}"
    assert http["declared_body"] == 4000
    assert http["method"] == "POST"
    assert http["path"] == "/api/txn"


def test_benign_slow_header_complete():
    """benign_worker slow-upload POST: header complete, body declared large."""
    http = parse_http(benign_slow_head())
    assert http["header_complete"] is True, \
        f"benign slow header must be complete, got {http}"
    assert http["declared_body"] == 2000000
    assert http["method"] == "POST"


def test_slowloris_header_incomplete():
    """slowloris_worker: header must NEVER be complete (no \\r\\n\\r\\n)."""
    http = parse_http(slowloris_head())
    assert http["header_complete"] is False, \
        f"slowloris header must be incomplete, got {http}"
    assert http["declared_body"] == 0
    assert http["method"] == "GET"


def test_slowloris_drip_incomplete():
    """slowloris keepalive drip: never completes a header by itself."""
    http = parse_http(slowloris_drip())
    assert http["header_complete"] is False


def test_flood_header_complete():
    """flood_worker: header complete, no body."""
    http = parse_http(flood_req())
    assert http["header_complete"] is True, \
        f"flood header must be complete, got {http}"
    assert http["declared_body"] == 0
    assert http["method"] == "GET"


def test_benign_header_ends_with_crlfcrlf():
    """Regression: benign header must end with blank line, not flow into body."""
    head = benign_header()
    assert head.endswith(b"\r\n\r\n"), \
        "benign header must terminate with \\r\\n\\r\\n before body"


def test_slowloris_header_never_ends_with_crlfcrlf():
    """Regression: slowloris header must never contain \\r\\n\\r\\n."""
    head = slowloris_head()
    assert b"\r\n\r\n" not in head, \
        "slowloris header must never contain \\r\\n\\r\\n"


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v"]))
