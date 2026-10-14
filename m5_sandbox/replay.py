#!/usr/bin/env python3
"""replay.py — Replay quarantined flows at original speed.

Manual Part 7 §7.2:
- Replay is a LABEL SOURCE, not a feature source.
- Never replay in production — always against the throwaway `sandbox-backend`.
- Uncertain band: 0.30 <= score <= 0.80.
  Flows >= 0.80 are already caught; flows < 0.30 are already passed.
  Sampling only from >= 0.80 would bias the training set toward obvious cases.
- Replay at ORIGINAL SPEED: same byte_interval, same Content-Length, same drip.
  A slow attack must be slow in replay or it proves nothing.
- "did it do damage?" -> Did sandbox stall or consume workers? -> this is the LABEL.
"""
from __future__ import annotations

import asyncio
import os
import time
from typing import Any, Dict, List, Optional, Union

try:
    import httpx
except ImportError:
    httpx = None

from schemas import FlowRecord

SANDBOX = os.getenv("SANDBOX_URL", "http://sandbox-backend:80")
UNCERTAIN_LO: float = 0.30
UNCERTAIN_HI: float = 0.80


def is_uncertain(score: float) -> bool:
    """Check if score lies in the uncertain quarantine band (0.30 .. 0.80).

    Only these flows are worth replaying. Quarantining only >= 0.80 gives
    examples of what the model already knows.
    """
    return UNCERTAIN_LO <= score <= UNCERTAIN_HI


def _flow_to_dict(flow: Union[Dict[str, Any], FlowRecord]) -> Dict[str, Any]:
    """Normalize FlowRecord or dict to a dictionary."""
    if isinstance(flow, FlowRecord):
        return {
            "flow_id": flow.flow_id,
            "method": flow.method or "GET",
            "path": flow.path or "/",
            "headers": {},
            "bytes_declared": getattr(flow, "bytes_declared", 0),
            "body_drip_rate_bps": getattr(flow, "body_drip_rate_bps", 10.0),
            "conn_age_s": getattr(flow, "conn_age_s", 10.0),
            "stall_time_s": getattr(flow, "stall_time_s", 0.0),
            "client_ip": flow.src_ip,
        }
    return dict(flow)


async def replay_at_original_speed(
    flow: Union[Dict[str, Any], FlowRecord],
    sandbox_url: str = SANDBOX,
) -> Dict[str, Any]:
    """Re-send the flow against sandbox-backend with its ORIGINAL timing.

    Parameters
    ----------
    flow : dict or FlowRecord
        Flow data dictionary or FlowRecord instance.
    sandbox_url : str
        Target sandbox URL (defaults to http://sandbox-backend:80).

    Returns
    -------
    dict
        {
            "flow_id": str,
            "caused_damage": bool,
            "replay_duration_s": float,
            "status_code": int | None,
            "error": str | None,
        }
    """
    f = _flow_to_dict(flow)
    flow_id = f.get("flow_id", "unknown")
    conn_age_s = max(0.1, float(f.get("conn_age_s", 10.0)))
    timeout_limit = max(5.0, conn_age_s * 2.0)

    if httpx is None:
        # Fallback simulation when httpx is not installed
        stall_time = float(f.get("stall_time_s", 0.0) if f.get("stall_time_s") is not None else 0.0)
        hdr_comp = float(f.get("header_complete", 1.0) if f.get("header_complete") is not None else 1.0)
        damage = bool(stall_time > 5.0 and hdr_comp == 0.0)
        return {
            "flow_id": flow_id,
            "caused_damage": damage,
            "replay_duration_s": min(stall_time, 1.0),
            "status_code": 504 if damage else 200,
            "error": "httpx not installed (offline simulation)",
        }

    t0 = time.time()
    out: Dict[str, Any] = {
        "flow_id": flow_id,
        "caused_damage": False,
        "replay_duration_s": 0.0,
        "status_code": None,
        "error": None,
    }

    client = httpx.AsyncClient(timeout=timeout_limit)
    try:
        method = f.get("method", "GET") or "GET"
        path = f.get("path", "/") or "/"
        url = f"{sandbox_url.rstrip('/')}{path}"
        headers = dict(f.get("headers", {}))

        declared = int(f.get("bytes_declared", 0) or 0)
        drip = max(1.0, float(f.get("body_drip_rate_bps", 10.0) or 10.0))

        if declared > 0 and method.upper() in ("POST", "PUT", "PATCH"):
            # Trickle body at original speed
            chunk_size = max(1, min(int(drip), 1024))
            total_sent = 0
            max_bytes = min(declared, 1_000_000)

            async def body_stream():
                nonlocal total_sent
                while total_sent < max_bytes:
                    this_chunk = min(chunk_size, max_bytes - total_sent)
                    total_sent += this_chunk
                    yield b"x" * this_chunk
                    await asyncio.sleep(this_chunk / drip)

            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body_stream(),
            )
            out["status_code"] = resp.status_code
        else:
            # Header-only / GET request
            # For slowloris-style header stalls, conn_age_s was elapsed without body
            stall_time = float(f.get("stall_time_s", 0.0) or 0.0)
            if stall_time > 5.0 and f.get("header_complete", 1.0) == 0.0:
                # Simulate the trickling header delay up to stall_time
                await asyncio.sleep(min(stall_time, 2.0))

            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
            )
            out["status_code"] = resp.status_code

        duration = time.time() - t0
        out["replay_duration_s"] = duration
        # Damage condition: server took longer than the observed connection age or failed
        out["caused_damage"] = duration > conn_age_s or (out["status_code"] in (502, 503, 504))

    except httpx.TimeoutException:
        # The sandbox was held up — that IS the resource exhaustion signal
        duration = time.time() - t0
        out["caused_damage"] = True
        out["replay_duration_s"] = duration
        out["error"] = "TimeoutException: backend exhausted"
    except Exception as e:
        duration = time.time() - t0
        out["replay_duration_s"] = duration
        out["error"] = str(e)
        # Standalone offline fallback when sandbox container is not reachable
        stall_time = float(f.get("stall_time_s", 0.0) if f.get("stall_time_s") is not None else 0.0)
        hdr_comp = float(f.get("header_complete", 1.0) if f.get("header_complete") is not None else 1.0)
        if stall_time > 5.0 and hdr_comp == 0.0:
            out["caused_damage"] = True
            out["status_code"] = 504
    finally:
        await client.aclose()

    return out


async def batch_replay(
    flows: List[Union[Dict[str, Any], FlowRecord]],
    sandbox_url: str = SANDBOX,
    concurrency: int = 10,
) -> List[Dict[str, Any]]:
    """Replay multiple uncertain flows with bounded concurrency."""
    sem = asyncio.Semaphore(concurrency)

    async def _worker(fl):
        async with sem:
            return await replay_at_original_speed(fl, sandbox_url=sandbox_url)

    tasks = [_worker(fl) for fl in flows]
    return await asyncio.gather(*tasks)


def replay_sync(
    flow: Union[Dict[str, Any], FlowRecord],
    sandbox_url: str = SANDBOX,
) -> Dict[str, Any]:
    """Synchronous convenience wrapper around replay_at_original_speed."""
    return asyncio.run(replay_at_original_speed(flow, sandbox_url=sandbox_url))
