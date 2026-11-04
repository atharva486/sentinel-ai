import json
from pathlib import Path
from typing import Dict
import pandas as pd
from .features import WindowTracker, build_features
from .sensor import parse_http
CONTAINER_ROLE: Dict[str, str] = {
    "172.18.0.5": "benign",
    "172.18.0.6": "attack",
    "172.18.0.7": "attack",
}

BENIGN_IP_PREFIXES = (
    "172.18.15.", "172.18.25.", "172.18.35.", "172.18.45.",
)
ATTACK_IP_PREFIXES= (
    "172.18.16.", "172.18.26.", "172.18.36.", "172.18.46.",
    "172.18.17.", "172.18.27.", "172.18.37.", "172.18.47.",
)

GT_ROLE: Dict[str, str] = {
    "benign": "benign",
    "slow": "attack",
    "flood": "attack",
}

def role_for_ip(ip) -> str | None:
    if not ip:
        return None
    if ip in CONTAINER_ROLE:
        return CONTAINER_ROLE[ip]
    for p in BENIGN_IP_PREFIXES:
        if ip.startswith(p):
            return "benign"
    for p in ATTACK_IP_PREFIXES:
        if ip.startswith(p):
            return "attack"
    return None

def label_generated(flow_jsonl)->pd.DataFrame:
    p = Path(flow_jsonl)
    recs = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))
    win = WindowTracker(window_s=10.0)

    parsed = []
    for r in recs:
        try:
            http = parse_http(bytes.fromhex(r["fwd_payload"]))
        except Exception:
            continue
        gt = http.get("ground_truth")
        role = GT_ROLE.get(gt) if gt else None
        if role is None:
            role = role_for_ip(r.get("client_ip"))
        if role is None:
            continue
        ent = r["client_ip"]
        parsed.append((r, http, role, ent))
        win.on_connect(ent, r["t_first"])
        if r.get("t_close") is not None:
            win.on_close(ent, r["t_close"])

    BUCKET_S = 15.0
    rows = []
    for r, http, role, ent in parsed:
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
                         "t": t_start, "snapshot_t": now,
                         "flow_id": r.get("flow_id")})
        if round(t_end, 3) not in seen:
            fvec = build_features(r, http, win, ent, t_end)
            rows.append({**fvec, "entity": ent, "role": role,
                         "t": t_start, "snapshot_t": t_end,
                         "flow_id": r.get("flow_id")})

    df = pd.DataFrame(rows)
    if not df.empty:
        df["y"] = (df["role"] == "attack").astype(int)
    return df

if __name__ == "__main__":
    print("Data is ready to be merged.")