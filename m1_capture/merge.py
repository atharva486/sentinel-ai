from __future__ import annotations
import json
from pathlib import Path
from typing import Dict
import pandas as pd
from .features import WindowTracker, build_features
from .sensor import parse_http

# Label source of truth: the per-connection side log written by the traffic
# generator.  Ground truth must never travel inside the traffic itself, so the
# old X-Ground-Truth header and the IP-prefix fallback are both removed.
#
# The side log already carries the per-connection class in its ``role`` column
# ("benign" | "attack") and the specific attack type in ``attack_type``
# ("benign" | "slowloris" | "slow_post" | "flood").  No GT_ROLE translation is
# needed -- the role column IS the class.
VALID_ROLES = ("benign", "attack")


def load_side_log(side_log_path: str | Path) -> list[dict]:
    """Load per-connection side-log rows written by the generator.

    Each row: src_ip, src_port, start_ts, end_ts, role, attack_type, tool,
    parameters.
    """
    p = Path(side_log_path)
    rows: list[dict] = []
    if not p.exists():
        return rows
    with p.open() as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _side_log_index(rows: list[dict]) -> Dict[tuple, list[dict]]:
    """Index side-log rows by (src_ip, src_port) for fast join lookup."""
    idx: Dict[tuple, list[dict]] = {}
    for row in rows:
        key = (row.get("src_ip"), row.get("src_port"))
        idx.setdefault(key, []).append(row)
    return idx


def _match_side_log(idx: Dict[tuple, list[dict]], client_ip: str,
                    client_port: int, t_start: float, t_end: float) -> dict | None:
    """Find the side-log row for one flow.

    Match on (src_ip, src_port) plus time overlap.  A (ip, port) pair identifies
    a single connection at a time, so at most one row should overlap; if several
    do (rapid reconnects on the same port) we return the one with the largest
    overlap.
    """
    candidates = idx.get((client_ip, client_port), [])
    best: dict | None = None
    best_overlap = 0.0
    for row in candidates:
        rs = float(row.get("start_ts", 0.0))
        re_ = float(row.get("end_ts", rs))
        overlap_start = max(t_start, rs)
        overlap_end = min(t_end, re_)
        overlap = max(0.0, overlap_end - overlap_start)
        if overlap > 0 and overlap > best_overlap:
            best_overlap = overlap
            best = row
    return best


def label_generated(flow_jsonl: str | Path,
                    side_log_path: str | Path | None = None) -> pd.DataFrame:
    """Label flow records from the side log, not from the traffic or IP.

    Args:
        flow_jsonl: raw flow records JSONL (output of m1_capture/sensor.py).
        side_log_path: per-connection side log written by gen/generate.py.
                       When None, no flow can be labelled and all are excluded.

    Returns:
        DataFrame with one row per labelled flow snapshot, including the
        non-feature columns ``entity``, ``role``, ``attack_type``, ``t``,
        ``snapshot_t``, ``flow_id`` and the binary label ``y``.  Flows with no
        matching side-log row are excluded from the frame but reported via
        ``_unlabelled`` attribute on the returned DataFrame (list of flow_ids).
    """
    p = Path(flow_jsonl)
    recs: list[dict] = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))

    side_rows = load_side_log(side_log_path) if side_log_path else []
    idx = _side_log_index(side_rows)

    win = WindowTracker(window_s=10.0)

    parsed: list[tuple[dict, dict, str, str, str]] = []
    unlabelled: list[str] = []
    for r in recs:
        try:
            http = parse_http(bytes.fromhex(r["fwd_payload"]))
        except Exception:
            continue
        client_ip = r.get("client_ip")
        client_port = r.get("client_port")
        t_start = float(r["t_first"])
        if r.get("t_close") is not None:
            t_end = float(r["t_close"])
        else:
            t_end = float(r["t_last"])

        match = _match_side_log(idx, client_ip, client_port, t_start, t_end)
        if match is None:
            unlabelled.append(str(r.get("flow_id")))
            continue
        role = match.get("role")
        if role not in VALID_ROLES:
            # Unknown role: cannot safely label, exclude rather than guess.
            unlabelled.append(str(r.get("flow_id")))
            continue
        ent = client_ip
        parsed.append((r, http, role, match.get("attack_type", role), ent))
        win.on_connect(ent, t_start)
        if r.get("t_close") is not None:
            win.on_close(ent, t_end)

    BUCKET_S = 15.0
    rows: list[dict] = []
    for r, http, role, attack_type, ent in parsed:
        t_start = float(r["t_first"])
        if r.get("t_close") is not None:
            t_end = float(r["t_close"])
        else:
            t_end = float(r["t_last"])
        age_cap = min(t_end - t_start, 600.0)
        n_buckets = int(age_cap // BUCKET_S) + 1
        seen = set()
        for k in range(n_buckets):
            now = t_start + (k + 1) * BUCKET_S
            if now > t_end:
                now = t_end
            key = round(now, 3)
            if key in seen:
                continue
            seen.add(key)
            if now < t_start:
                continue
            fvec = build_features(r, http, win, ent, now)
            rows.append({**fvec, "entity": ent, "role": role,
                         "attack_type": attack_type,
                         "t": t_start, "snapshot_t": now,
                         "flow_id": r.get("flow_id")})
        if round(t_end, 3) not in seen:
            fvec = build_features(r, http, win, ent, t_end)
            rows.append({**fvec, "entity": ent, "role": role,
                         "attack_type": attack_type,
                         "t": t_start, "snapshot_t": t_end,
                         "flow_id": r.get("flow_id")})

    df = pd.DataFrame(rows)
    if not df.empty:
        df["y"] = (df["role"] == "attack").astype(int)
    df.attrs["unlabelled"] = unlabelled
    return df
