from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class FlowRecord:
    """One connection's worth of observed behaviour, mid-flight or complete."""
    flow_id: str
    entity_key: str
    # hash(ip, ja3, session) — NOT ip alone
    ts_start: float
    ts_end: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str = "tcp"
    method: str = ""
    path: str = ""
    status_code: Optional[int] = None
    bytes_in: int = 0
    bytes_out: int = 0
    req_count: int = 0
    conn_id: str = ""
    ja3: Optional[str] = None
    ja4: Optional[str] = None
    # ---- the 20 derived features (Module 1's contract with the model) ----
    bytes_in_per_s: float = 0.0
    bytes_out_per_s: float = 0.0
    requests_per_s: float = 0.0
    packets_per_s: float = 0.0
    interarrival_mean: float = 0.0
    interarrival_std: float = 0.0
    interarrival_max: float = 0.0
    concurrent_conns: float = 0.0
    conns_per_second_opened: float = 0.0
    requests_per_conn_so_far: float = 0.0
    conn_age_s: float = 0.0
    stall_time_s: float = 0.0
    body_frac_sent: float = 1.0
    bytes_declared: float = 0.0
    body_drip_rate_bps: float = 0.0
    time_to_first_byte: float = 0.0
    header_complete: float = 1.0
    syn_retries: float = 0.0
    bytes_in_ratio: float = 0.0
    is_open: float = 1.0

@dataclass(frozen=True)
class TriggerEvent:
    """Module 2 raises these. Cheap, no ML."""
    ts: float
    entity_key: str
    trigger: str
    # "rate" | "cusum" | "connections" | "stall" | "entropy"
    severity: float
    detail: dict = field(default_factory=dict)

@dataclass(frozen=True)
class ScoreObject:
    """Module 3 produces these."""
    flow_id: str
    ts: float
    score: float
    # calibrated P(attack), 0..1
    model_version: str
    shap_values: dict
    # feature -> SHAP value, ALL of them
    shap_top_k: list
    # ranked, for display
    tcn_score: Optional[float] = None
    trigger_context: Optional[TriggerEvent] = None


@dataclass(frozen=True)
class ActionObject:
    """Module 4 produces these. This is what actually gets enforced."""
    flow_id: str
    entity_key: str
    action: str
    # "forward"|"throttle"|"block"|"quarantine"
    rate_limit: Optional[int] = None
    conn_limit: Optional[int] = None
    timeout_s: Optional[float] = None
    mechanism_reason: str = ""
    driver_group: str = ""
    # ★ which group caused this: stall|concurrency|rate
    expires_at: float = 0.0