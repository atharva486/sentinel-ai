"""Atomic sliding-window rate counters and open-connection tracking."""

import math
import time
import uuid


SLIDING_WINDOW_LUA = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]

redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
local count = redis.call('ZCARD', key)

if count >= limit then
    return {0, count}
end

redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, math.ceil(window))
return {1, count + 1}
"""


def hit(
    r,
    key: str,
    window: float = 1.0,
    limit: int = 100,
) -> tuple[bool, int]:
    """Atomically record a hit if under the limit.

    Returns (allowed, count_in_window). Rejected hits are not recorded.
    The caller supplies an initialized Redis client.
    """
    if not key:
        raise ValueError("key must not be empty")
    if not math.isfinite(window) or window <= 0:
        raise ValueError("window must be a positive finite number")
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")

    now = time.time()
    member = f"{now:.6f}:{uuid.uuid4().hex}"

    allowed, count = r.eval(
        SLIDING_WINDOW_LUA,
        1,
        key,
        now,
        window,
        limit,
        member,
    )
    return bool(allowed), int(count)


def track_open_connections(r, entity_key: str, conn_id: str) -> int:
    """Register an open connection and return the current tracked count.

    Call when a connection opens. Remove it on close with
    remove_open_connection().
    """
    if not entity_key:
        raise ValueError("entity_key must not be empty")
    if not conn_id:
        raise ValueError("conn_id must not be empty")

    key = f"conns:{entity_key}"
    r.zadd(key, {conn_id: time.time()})
    r.expire(key, 300)
    return int(r.zcard(key))


def remove_open_connection(r, entity_key: str, conn_id: str) -> int:
    """Remove a closed connection and return the remaining tracked count."""
    key = f"conns:{entity_key}"
    r.zrem(key, conn_id)
    return int(r.zcard(key))
