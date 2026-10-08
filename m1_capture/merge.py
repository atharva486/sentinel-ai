from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import pandas as pd

from features import WindowTracker, build_features
from sensor import parse_http


CONTAINER_ROLE: Dict[str, str] = {
    # Update after capturing with actual container IPs from docker compose
    "172.18.0.5": "benign",
    "172.18.0.6": "attack",
    "172.18.0.7": "attack",
}


def label_generated(flow_jsonl: str | Path) -> pd.DataFrame:
    p = Path(flow_jsonl)
    recs = []
    with p.open() as f:
        for line in f:
            line = line.strip()
            if line:
                recs.append(json.loads(line))

    win = WindowTracker(window_s=10.0)
    rows = []
    for r in recs:
        try:
            http = parse_http(bytes.fromhex(r["fwd_payload"]))
        except Exception:
            continue
        role = CONTAINER_ROLE.get(r.get("client_ip"))
        if role is None:
            continue
        ent = r["client_ip"]
        win.on_connect(ent, r["t_first"])
        if r.get("t_close") is not None:
            win.on_close(ent, r["t_close"])
        fvec = build_features(r, http, win, ent, r["t_last"])
        rows.append({**fvec, "entity": ent, "role": role, "t": r["t_first"]})

    df = pd.DataFrame(rows)
    if not df.empty:
        df["y"] = (df["role"] == "attack").astype(int)
    return df


if __name__ == "__main__":
    print("merge.py ready. Update CONTAINER_ROLE with actual IPs after docker run.")
