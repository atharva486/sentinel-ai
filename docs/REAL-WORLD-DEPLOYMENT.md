# Putting Sentinel-AI in front of a real site

This document answers one question: **if a real production site wanted this L7
DoS defence, how would you actually wire it in?** It lists every realistic
option, where each one breaks down, and the phased plan I would propose.

The lab demo is the simple end of this list (nginx + tcpdump + a config reload).
Everything below is the same system placed at different points in a real stack.

---

## 0. The problem splits into two jobs

| Job | What it does | Examples |
|---|---|---|
| **Detect** | observe L7 client behaviour, decide "this looks like slowloris / RUDY / flood" | our model |
| **Enforce** | act on that decision near the traffic | nginx `limit_req`, a WAF, an eBPF map |

They are separate. You can swap either one. The thing that connects them is a
**control plane** (how the decision reaches the enforcer). Most real deployments
fail on the control plane, not the model.

There is also a hard constraint that eliminates half the options:
**slowloris and RUDY can only be seen while the request is still incomplete.**
Any observation point that only gives you finished requests (access logs,
NetFlow, most cloud analytics) **cannot** detect them, by construction. That
single fact drives most of the choices below.

---

## 1. Where the detector can get its data (observation points)

| # | Point | Sees partial headers/body? | Cost | Notes |
|---|---|---|---|---|
| a | **Packet capture at the reverse proxy / LB** (`tcpdump`, mirror port) | yes | low | what the lab does; CPU per packet; needs privileges |
| b | **eBPF / XDP at the kernel** (`tc`, `xdp`) | yes | medium | production-grade, per-connection, near-zero copy; needs kernel work |
| c | **Reverse-proxy access logs** (nginx/Envoy/Haproxy) | **no** | trivial | misses slowloris/RUDY entirely — good for flood only |
| d | **NetFlow / IPFIX / sFlow** | **no** (L3/L4 only) | low | no L7 at all; can only do volumetric |
| e | **In-process / app middleware** (middleware in the app) | yes | low | sees headers/body directly, but not the network shape; no partial-header timing unless the app exposes it |
| f | **Service-mesh sidecar** (Envoy/Istio) | partial | medium | rich L7 telemetry, can enforce too |

**Rule of thumb:** if you want slowloris/RUDY, you must be at (a), (b), (e) or a
sidecar — *not* (c)/(d). The lab uses (a) because it is the simplest thing that
still sees partial requests.

---

## 2. Where enforcement can happen (the "middleware")

| # | Enforcer | Acts on | Granularity | How it gets the decision |
|---|---|---|---|---|
| a | **Reverse proxy / ADC** — nginx, HAProxy, Envoy, Traefik | per-client-IP rate + concurrency + timeouts | per-IP, per-route | config reload, shared map, or its admin/xDS API |
| b | **Edge CDN / cloud WAF** — Cloudflare, AWS WAF+Shield, GCP Cloud Armor, Azure Front Door | per-IP/geo/ASN rate rules | per-IP | provider API or rules engine |
| c | **eBPF / XDP rate limiter** (Cilium, custom) | per-source packet/connection rate at the NIC | per-IP, line-rate | eBPF map update |
| d | **API gateway** (Kong, Apigee) | per-key/per-IP rate limits | per-IP/key | admin API |
| e | **Service mesh sidecar** | per-connection L7 policy | per-IP/workload | xDS |
| f | **Host firewall** (nftables/ipset) | hard IP ban | per-IP | set update |
| g | **Application code** | business-level rejection | per-session | in-process |

The lab uses **(a) with per-IP keying** (`limit_req_zone $binary_remote_addr`,
`limit_conn_zone $binary_remote_addr`). Keying on the client IP is the single
most important safety property: it means the mitigation lands on the attacker
and **not** on everyone else.

---

## 3. How the decision reaches the enforcer (control plane)

| Mechanism | Latency to apply | Blast radius | Used by |
|---|---|---|---|
| **Config write + `nginx -s reload`** | ~10–100 ms | that node | **the lab** |
| Shared map / include file polled by the proxy | ~poll interval | that node | nginx `map`/`geo`, HAProxy maps |
| Enforcer admin API / xDS | ~ms | one or many nodes | Envoy, Kong, Cloudflare |
| **eBPF map update** | ~µs | one node | kernel enforcers |
| In-process call (model embedded in middleware) | 0 | that process | app middleware |
| Message bus (Redis/Kafka) to a fleet | ~10–100 ms | whole edge | large multi-node |

The lab deliberately uses the **simplest** one (write file, reload). It is easy
to audit: you can `cat proxy/limits/*.conf` and see exactly what was decided.

---

## 4. Scoping and safety (the part that decides whether it is usable)

- **Per-client, never global.** A global rule during an attack throttles good
  users too — that is a self-inflicted outage. Every rule is keyed by
  `$binary_remote_addr`.
- **Hysteresis.** Turn a rule on at a high score, off at a low one (lab:
  ON ≥ 0.55, OFF < 0.30). Without this the system flaps every poll.
- **TTL on blocks.** A block should expire; a NAT'd user may share an IP with
  an attacker (see §7).
- **Shadow mode first.** Run detection with enforcement *off*, compare against
  labels, and only then turn enforcement on.
- **Fail-open vs fail-closed.** If the detector dies, does traffic pass or
  stop? For availability, fail-open + alert is the usual choice.

---

## 5. Recommended production blueprint (phased)

```
            ┌─────────────── control plane ───────────────┐
            │ metrics / alerting        policy store       │
            └───────▲───────────────────────────┬──────────┘
                    │ decisions                 │ rules
   clients ──► [ reverse proxy / LB ] ──► [ app pool ]
                    │  ▲                       
             mirror │  │ enforce (per-IP)
                    ▼  │
              [ detector: eBPF / pcap ]  → model → SHAP → mechanism
```

1. **Phase 1 — observability only.** Mirror traffic (or read eBPF) at the LB;
   run the detector in **shadow mode**; ship scores + SHAP to the dashboard.
   No enforcement. Measure precision on real traffic.
2. **Phase 2 — per-IP enforcement at the LB.** Turn on `limit_req`/`limit_conn`
   keyed by client IP, with hysteresis and a TTL. This is the lab demo, at
   production scale.
3. **Phase 3 — edge mitigation.** For volumetric floods, push confirmed
   attackers to the CDN/cloud WAF by API so junk is dropped before it reaches
   your origin.
4. **Phase 4 — kernel line-rate.** For the biggest floods, move the rate limit
   into eBPF/XDP so the box survives its own volume.

---

## 6. How the lab maps onto this

| Real production | Lab equivalent |
|---|---|
| mirror port / eBPF observation | `tcpdump` in the `proxy` container |
| reverse proxy / LB | nginx in the `proxy` container |
| per-IP rate + concurrency rules | `proxy/limits/rate.conf`, `conn.conf` |
| config push to the fleet | `nginx -s reload` inside the container |
| shadow mode | `dashboard/live_lab.py --no-enforce` |
| A/B proof | `dashboard/protect_demo.py` (no-defence vs defence) |

---

## 7. What a real site still needs (honest gaps)

- **TLS/HTTP2.** Once TLS terminates at the edge, you either detect at the
  terminator (where plaintext exists) or you are limited to flow metadata.
- **Scale and state.** Per-IP state has to survive millions of IPs and be
  evicted; this is a systems problem, not a model problem.
- **CGNAT/NAT.** Many users share one public IP; a per-IP block can hit
  innocents. Mitigation: combine IP with other signals, or use shorter/TTL'd
  limits rather than hard blocks.
- **IPv6.** Address space is huge; per-IP keying still works but cardinality
  explodes; consider /64 prefixes.
- **Adversarial drift.** Attackers adapt; the model needs periodic retraining
  and the A/B harness has to be re-run to keep the claims true.
- **Encrypted body attacks.** RUDY-style slow-body needs plaintext or the
  terminator's cooperation.

---

## 8. One-line answers (interview-ready)

- "Detection and enforcement are separate; most deployments fail on the
  control plane, so we keep it auditable — a file the proxy reloads."
- "Slow and slow-body attacks can only be seen mid-request, so we observe at
  the proxy/eBPF, not from access logs."
- "Every rule is per-client-IP with hysteresis and a TTL, so mitigation never
  becomes collateral damage."
- "We prove it with an A/B run: same attack, defence off vs on, measured from
  the proxy's own log."
