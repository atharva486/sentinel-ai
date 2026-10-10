from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import pandas as pd

from features import WindowTracker, build_features
from sensor import parse_http


# Source IP -> role. Primary container IPs are PINNED in docker-compose.yaml
# (lab subnet 172.18.0.0/16). When generators bind each worker to its own
# source IP (gen/generate.py --ip-base), those IPs fall in per-container pools
# labelled by PREFIX below. An IP matching nothing is dropped (role None ->
# unlabelled), so an unlisted pool silently loses data — keep these in sync.
CONTAINER_ROLE: Dict[str, str] = {
    "172.18.0.5": "benign",   # legit-loadgen (primary)
    "172.18.0.6": "attack",   # slow-gen  (slowloris / rudy)
    "172.18.0.7": "attack",   # flood-gen
}

# Per-container source-IP pools for multi-IP captures. One pool per session;
# third octet ends in 5 = benign, 6 = slow-gen, 7 = flood-gen, mirroring .5/.6/.7.
BENIGN_IP_PREFIXES: tuple[str, ...] = (
    "172.18.15.", "172.18.25.", "172.18.35.", "172.18.45.",
)
ATTACK_IP_PREFIXES: tuple[str, ...] = (
    "172.18.16.", "172.18.26.", "172.18.36.", "172.18.46.",   # slow-gen pools
    "172.18.17.", "172.18.27.", "172.18.37.", "172.18.47.",   # flood-gen pools
)

# Ground-truth header values -> binary role. The header is embedded by the
# generator (X-Ground-Truth: benign|slow|rudy|flood) so labeling works even
# when one IP does mixed roles. If absent, fall back to IP-based role_for_ip.
GT_ROLE: Dict[str, str] = {
    "benign": "benign",
    "slow": "attack",
    "rudy": "attack",
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


def label_generated(flow_jsonl: str | Path) -> pd.DataFrame:
    p = Path(flow_jsonl)
    recs = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))

    win = WindowTracker(window_s=10.0)

    # Pass 1: parse + label, and register every connection's [open, close]
    # interval BEFORE computing anything. window_features() only counts
    # intervals that CONTAIN the decision time, so this is order-independent
    # and leaks nothing: a connection that has not opened by `now` is never
    # counted, and one still open at `now` counts correctly.
    parsed: list[tuple[dict, dict, str, str]] = []
    for r in recs:
        try:
            http = parse_http(bytes.fromhex(r["fwd_payload"]))
        except Exception:
            continue
        # Prefer per-flow ground-truth header; fall back to IP-based labeling.
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

    # Pass 2: features at each flow's own decision time (t_last).
    rows = []
    for r, http, role, ent in parsed:
        fvec = build_features(r, http, win, ent, r["t_last"])
        rows.append({**fvec, "entity": ent, "role": role, "t": r["t_first"]})

    df = pd.DataFrame(rows)
    if not df.empty:
        df["y"] = (df["role"] == "attack").astype(int)
    return df


if __name__ == "__main__":
    print("merge.py ready. IPs are pinned in docker-compose.yaml; "
          "CONTAINER_ROLE must match them.")
