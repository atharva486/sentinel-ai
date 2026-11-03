#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import shutil
import socket
import struct
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np

DASH_DIR = Path(__file__).resolve().parent
REPO_ROOT = DASH_DIR.parent
for _p in (REPO_ROOT, REPO_ROOT / "m1_capture", REPO_ROOT / "m3_scoring"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import dpkt

from m1_capture import sensor
from m1_capture.features import (
    FEATURE_ORDER,
    WindowTracker,
    build_features,
)
from m1_capture.merge import (
    ATTACK_IP_PREFIXES,
    BENIGN_IP_PREFIXES,
    CONTAINER_ROLE,
    GT_ROLE,
    role_for_ip,
)
from m3_scoring.calibrate import CalibrationResult
from mechanism import (
    CONN_LIMIT,
    Policy,
    RATE_LIMIT,
    choose_by_shap_group,
    shap_group_scores,
)

ARTIFACT_PATH = REPO_ROOT / "models" / "calibration_result_current.joblib"
DATA_PATH = REPO_ROOT / "data" / "features.parquet"
FEED_PATH = REPO_ROOT / "reports" / "live_feed.jsonl"
LAB_STATUS_PATH = REPO_ROOT / "reports" / "live_lab_status.json"
LAB_LOG_PATH = REPO_ROOT / "reports" / "live_lab.log"

class LiveEngine:
    def __init__(self, artifact_path: Path | str = ARTIFACT_PATH):
        self.art = CalibrationResult.load(str(artifact_path))
        self.policy = Policy()
        self._explainer = None

    def _shap(self, feats: dict) -> dict:
        import shap

        if self._explainer is None:
            self._explainer = shap.TreeExplainer(self.art.model)
        row = np.array(
            [[float(feats.get(k, 0.0)) for k in FEATURE_ORDER]], dtype=np.float64
        )
        sv = self._explainer.shap_values(row)
        if isinstance(sv, list):
            values = sv[1] if len(sv) == 2 and isinstance(sv[1], np.ndarray) else sv[0]
        else:
            values = sv[0] if getattr(sv, "ndim", 1) == 2 else sv
        values = np.asarray(values, dtype=float).ravel()
        if values.size < len(FEATURE_ORDER):
            values = np.pad(values, (0, len(FEATURE_ORDER) - values.size))
        values = values[: len(FEATURE_ORDER)]
        return {name: float(values[i]) for i, name in enumerate(FEATURE_ORDER)}

    def score(self, feats: dict, entity: str = "flow") -> dict:
        X = np.array(
            [[float(feats.get(k, 0.0)) for k in FEATURE_ORDER]], dtype=np.float64
        )
        raw = float(self.art.model.predict_proba(X)[0, 1])
        cal = float(self.art.calibrated_score(feats))
        shap_values = self._shap(feats)
        groups = shap_group_scores(shap_values)
        mech = choose_by_shap_group(shap_values, cal)
        action = self.policy.decide(str(entity), cal)
        return {
            "raw": raw,
            "calibrated": cal,
            "groups": groups,
            "top_group": max(groups, key=groups.get) if groups else "n/a",
            "mechanism": mech,
            "action": action,
        }

    def score_dataset(self, rows: list[dict]) -> list[dict]:
        import shap

        if not rows:
            return []
        X = np.array(
            [
                [float(r["feats"].get(k, 0.0)) for k in FEATURE_ORDER]
                for r in rows
            ],
            dtype=np.float64,
        )
        raw = self.art.model.predict_proba(X)[:, 1]
        cal = np.clip(self.art.calibrator.predict(raw), 0.0, 1.0)
        if self._explainer is None:
            self._explainer = shap.TreeExplainer(self.art.model)
        sv = self._explainer.shap_values(X)
        if isinstance(sv, list):
            values = sv[1] if len(sv) == 2 and isinstance(sv[1], np.ndarray) else sv[0]
        else:
            values = sv
        values = np.asarray(values, dtype=float)
        if values.ndim == 1:
            values = values.reshape(1, -1)
        values = values[:, : len(FEATURE_ORDER)]

        policy = Policy()
        out: list[dict] = []
        for i, row in enumerate(rows):
            shap_values = {
                name: float(values[i, j]) for j, name in enumerate(FEATURE_ORDER)
            }
            groups = shap_group_scores(shap_values)
            score_i = float(cal[i])
            mech = choose_by_shap_group(shap_values, score_i)
            action = policy.decide(str(row["entity"]), score_i)
            y = int(row["y"])
            out.append(
                {
                    "session": row["session"],
                    "profile": row["profile"],
                    "truth": "attack" if y else "benign",
                    "y": y,
                    "entity": row["entity"],
                    "score": score_i,
                    "raw": float(raw[i]),
                    "group": max(groups, key=groups.get) if groups else "n/a",
                    "groups": dict(groups),
                    "mech": mechanism_kind(mech),
                    "action": action,
                    "directive": nginx_directives(mech),
                }
            )
        return out

def flow_signature(f: dict) -> str:
    if f.get("header_complete", 1.0) < 0.5 and f.get("conn_age_s", 0.0) >= 1.0:
        return "slowloris"
    if f.get("requests_per_s", 0.0) >= 20.0:
        return "flood"
    if f.get("concurrent_conns", 0.0) >= 20 and f.get("conn_age_s", 0.0) < 5.0:
        return "conn-burst"
    return "benign"

def nginx_directives(mech) -> str:
    lines = []
    if mech.conn_limit is not None:
        lines.append(f"limit_conn addr {mech.conn_limit};")
    if mech.rate_limit is not None:
        lines.append(f"limit_req zone=api burst={mech.rate_limit} nodelay;")
    if mech.timeout_s is not None:
        lines.append(f"proxy_read_timeout {int(mech.timeout_s)}s;")
    return "\n".join(lines) if lines else "# no directive (forward)"

def mechanism_kind(mech) -> str:
    has_conn = mech.conn_limit is not None
    has_rate = mech.rate_limit is not None
    if has_conn and has_rate:
        return "both"
    if has_conn:
        return "limit_conn"
    if has_rate:
        return "limit_req"
    return "none"


PIPELINE = [
    ("", "Traffic"),
    ("", "Capture"),
    ("", "Flows"),
    ("", "Features"),
    ("", "Detect"),
    ("", "Calibrate"),
    ("", "Explain"),
    ("", "Decide"),
    ("", "Enforce"),
]

_PIPE_CSS = """
<style>
.jp-wrap{position:relative;padding:24px 4px 4px;}
.jp-rail{position:absolute;top:15px;left:10px;right:10px;height:3px;
  background:linear-gradient(90deg,#dbe8f8,#2d7ff9,#dbe8f8);border-radius:2px;opacity:.55;}
.jp-pkt{position:absolute;top:7px;left:0;width:17px;height:17px;border-radius:50%;
  background:#2d7ff9;box-shadow:0 0 12px 2px rgba(45,127,249,.7);
  animation:jptravel 3.6s cubic-bezier(.45,.05,.55,.95) infinite;}
.jp-pkt.off{animation:none;left:47%;opacity:.3;box-shadow:none;}
@keyframes jptravel{0%{left:0%;}100%{left:95%;}}
.jp-stages{display:flex;gap:6px;}
.jp-stage{flex:1;border:1px solid rgba(120,150,180,.30);border-radius:9px;
  padding:9px 5px 7px;text-align:center;background:rgba(45,127,249,.05);}
.jp-stage .ic{font-size:1.05rem;line-height:1;}
.jp-stage b{display:block;font-size:.72rem;margin-top:3px;color:#e0e0e0;}
.jp-stage.active{background:rgba(45,127,249,.22);border-color:#2d7ff9;}
</style>
"""

def pipeline_html(active: int | None = None, animate: bool = True) -> str:
    parts = [_PIPE_CSS, '<div class="jp-wrap"><div class="jp-rail"></div>']
    parts.append(f'<span class="jp-pkt{"" if animate else " off"}"></span>')
    parts.append('<div class="jp-stages">')
    for i, (ic, name) in enumerate(PIPELINE):
        cls = "jp-stage active" if active == i else "jp-stage"
        parts.append(
            f'<div class="{cls}"><div class="ic">{ic}</div><b>{i + 1}. {name}</b></div>'
        )
    parts.append("</div></div>")
    return "".join(parts)

class PcapTail:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.offset = 0
        self.linktype = None

    def read_new(self) -> list[tuple[float, bytes]]:
        out: list[tuple[float, bytes]] = []
        if not self.path.exists():
            return out
        if self.offset == 0:
            with open(self.path, "rb") as fh:
                gh = fh.read(24)
            if len(gh) < 24:
                return out
            self.linktype = struct.unpack_from("<I", gh, 20)[0]
            self.offset = 24
        pos = self.offset
        with open(self.path, "rb") as fh:
            fh.seek(self.offset)
            while True:
                hdr = fh.read(16)
                if len(hdr) < 16:
                    break
                ts_s, ts_us, incl, _orig = struct.unpack("<IIII", hdr)
                data = fh.read(incl)
                if len(data) < incl:
                    break
                out.append((ts_s + ts_us / 1e6, data))
                pos = fh.tell()
        self.offset = pos
        return out

class LiveSensor:
    CLIENT_PREFIXES = tuple(
        list(BENIGN_IP_PREFIXES)
        + list(ATTACK_IP_PREFIXES)
        + list(CONTAINER_ROLE.keys())
    )

    def __init__(self, pcap_path: Path, client_prefixes: tuple[str, ...] | None = None,
                 flush_after_s: float = 5.0):
        self.tail = PcapTail(path=pcap_path)
        self.store = sensor.FlowTracker(flush_after_s=flush_after_s)
        self.latest_ts = 0.0
        self.packets = 0
        self.client_prefixes = (client_prefixes if client_prefixes is not None
                                else self.CLIENT_PREFIXES)

    def is_client(self, ip: str) -> bool:
        return ip.startswith(self.client_prefixes)

    def poll(self) -> list:
        for ts, buf in self.tail.read_new():
            ip = sensor._unwrap(buf, self.tail.linktype)
            if ip is None or not isinstance(ip.data, dpkt.tcp.TCP):
                continue
            tcp = ip.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            if not (self.is_client(src) or self.is_client(dst)):
                continue
            self.store.ingest(
                ts, src, tcp.sport, dst, tcp.dport, bytes(tcp.data), tcp.flags
            )
            self.packets += 1
            self.latest_ts = max(self.latest_ts, ts)
        return [fs for fs in self.store.flows.values()
                if fs.client_ip.startswith(self.client_prefixes)]

class LabRunner:
    SERVICES = ["proxy", "backend", "legit-loadgen", "slow-gen", "flood-gen"]

    def __init__(self, repo: Path = REPO_ROOT):
        self.repo = Path(repo)

    @staticmethod
    def docker_available() -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            r = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=10,
            )
            return r.returncode == 0 and bool(r.stdout.strip())
        except Exception:
            return False

    def compose(self, args: list[str], timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "compose", *args], cwd=self.repo,
            capture_output=True, text=True, timeout=timeout,
        )

    def up(self) -> subprocess.CompletedProcess:
        return self.compose(["up", "-d", *self.SERVICES], timeout=300)

    def down(self) -> subprocess.CompletedProcess:
        return self.compose(["down"], timeout=120)

    def ps(self) -> list[dict]:
        r = self.compose(["ps", "--format", "json"], timeout=60)
        rows = []
        for line in r.stdout.splitlines():
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
        return rows

    def running_names(self) -> list[str]:
        names = []
        for row in self.ps():
            state = (row.get("State") or row.get("Status") or "").lower()
            if "run" in state or "up" in state:
                names.append(row.get("Service") or row.get("Name") or "?")
        return names

    def add_ip_pool(self, service: str, base: str, count: int) -> None:
        script = "; ".join(
            f"ip addr add {base}.{i}/16 dev eth0 2>/dev/null" for i in range(1, count + 1)
        )
        self.compose(["exec", "-T", service, "sh", "-c", script], timeout=120)

    def start_capture(self, name: str = "live.pcap") -> subprocess.CompletedProcess:
        return self.compose(
            ["exec", "-d", "proxy", "tcpdump", "-i", "eth0", "-s", "0",
             "-w", f"/captures/{name}", "tcp port 80"],
            timeout=60,
        )

    def stop_capture(self) -> subprocess.CompletedProcess:
        return self.compose(["exec", "-T", "proxy", "pkill", "-f", "tcpdump"], timeout=30)

    def launch(self, service: str, mode: str, duration: int = 180,
               label: str = "live", ip_base: str | None = None,
               ip_count: int = 0, extra: list[str] | None = None) -> subprocess.CompletedProcess:
        cmd = ["exec", "-d", service, "python", "generate.py",
               "--mode", mode, "--duration", str(duration), "--label", label]
        if ip_base and ip_count > 0:
            cmd += ["--ip-base", ip_base, "--ip-count", str(ip_count)]
        if extra:
            cmd += extra
        return self.compose(cmd, timeout=60)

    def stop_traffic(self) -> None:
        for s in ("legit-loadgen", "slow-gen", "flood-gen"):
            self.compose(["exec", "-T", s, "pkill", "-f", "generate.py"], timeout=30)

    def write_limits(self, rate_conf: str, conn_conf: str) -> None:
        (self.repo / "proxy" / "limits" / "rate.conf").write_text(rate_conf)
        (self.repo / "proxy" / "limits" / "conn.conf").write_text(conn_conf)

    def reload_nginx(self) -> subprocess.CompletedProcess:
        return self.compose(
            ["exec", "-T", "proxy", "sh", "-c", "nginx -t && nginx -s reload"],
            timeout=30,
        )

RATE_CONF_ON = (
    "# written live by dashboard/live_lab.py — rate-class mechanism\n"
    "limit_req_zone $binary_remote_addr zone=api:10m rate=50r/s;\n"
    "limit_req_status 429;\n"
    f"limit_req zone=api burst={RATE_LIMIT} nodelay;\n"
)
CONN_CONF_ON = (
    "# written live by dashboard/live_lab.py — stall/concurrency-class mechanism\n"
    "limit_conn_zone $binary_remote_addr zone=addr:10m;\n"
    "limit_conn_status 429;\n"
    f"limit_conn addr {CONN_LIMIT};\n"
)

def append_feed(record: dict) -> None:
    FEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(FEED_PATH, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")

def read_feed(limit: int = 400) -> list[dict]:
    if not FEED_PATH.exists():
        return []
    with open(FEED_PATH, "r", encoding="utf-8") as fh:
        lines = fh.readlines()[-limit:]
    out = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out

def clear_feed() -> None:
    if FEED_PATH.exists():
        FEED_PATH.unlink()

def truth_for(rec: dict, http: dict) -> str:
    gt = http.get("ground_truth")
    role = GT_ROLE.get(gt) if gt else None
    if role is None:
        role = role_for_ip(rec.get("client_ip"))
    return role or "unknown"
