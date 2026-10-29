#!/usr/bin/env python3
"""Aurora Bank — the small site the reverse proxy protects.

This used to be a two-line stub that answered "ok" to everything. A stub is a
weak demo target: a reviewer cannot tell whether the reverse proxy is protecting
a *site* or just a function. So the backend now serves a small but real portal
(a landing page, a health endpoint and an account API) which you can open at
http://localhost:8080 while traffic runs.

Two things are deliberate:

  * The `/api/*` endpoints used by the traffic generators (`/api/form/*`,
    `/api/search`, `/api/upload`, `/api/items`) still return exactly "ok".
    The model's features are request-side only (see m1_capture/features.py's
    "no leakage" rule), so leaving them byte-identical keeps live captures
    comparable to the training captures.

  * The portal routes are additive. They do not shadow any generator path.

Optional env (used by the protection proof to make the target finite, like a
real server with a bounded worker pool):

    SITE_CONCURRENCY   max in-flight requests handled at once (0 = unlimited)
    SITE_WORK_MS       simulated per-request work in milliseconds (0 = none)
"""

import asyncio
import os
import time

from aiohttp import web

SITE_CONCURRENCY = int(os.environ.get("SITE_CONCURRENCY", "0") or "0")
SITE_WORK_MS = float(os.environ.get("SITE_WORK_MS", "0") or "0")
_sem: asyncio.Semaphore | None = None


def _get_sem() -> asyncio.Semaphore | None:
    global _sem
    if SITE_CONCURRENCY <= 0:
        return None
    if _sem is None:
        _sem = asyncio.Semaphore(SITE_CONCURRENCY)
    return _sem


INDEX = """<!doctype html><html><head><meta charset="utf-8">
<title>Aurora Bank — Portal</title>
<style>
 body{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1720;color:#e8eef5}
 header{padding:18px 28px;background:#16212e;border-bottom:1px solid #24313f}
 h1{margin:0;font-size:20px} .tag{color:#7fb2ff;font-size:12px}
 main{padding:28px;max-width:820px}
 .card{background:#16212e;border:1px solid #24313f;border-radius:10px;padding:18px;margin:14px 0}
 .ok{color:#5ad18a} .pill{display:inline-block;padding:2px 10px;border-radius:999px;background:#1d2c3d;color:#9fc4ff;font-size:12px}
 code{color:#ffd479}
</style></head><body>
<header><h1>Aurora Bank <span class="tag">online banking</span></h1></header>
<main>
 <div class="card"><span class="pill">protected</span>
   <p>This portal sits behind the Sentinel-AI reverse proxy. Requests from a
   client that the model flags are rate-limited or connection-limited at the
   proxy before they reach this page.</p>
   <p class="ok">If you can read this while an attack is running, the defence held.</p>
 </div>
 <div class="card"><h3>Endpoints</h3>
   <p><code>GET /health</code> — service health (JSON)</p>
   <p><code>GET /api/account</code> — sample account (JSON)</p>
   <p><code>POST /api/form/&lt;id&gt;</code> — form submit (used by load generators)</p>
 </div>
</main></body></html>"""


async def _work():
    if SITE_WORK_MS > 0:
        await asyncio.sleep(SITE_WORK_MS / 1000.0)


async def index(request: web.Request) -> web.Response:
    return web.Response(text=INDEX, content_type="text/html")


async def health(request: web.Request) -> web.Response:
    return web.json_response(
        {"status": "ok", "service": "aurora-bank", "ts": round(time.time(), 3)}
    )


async def account(request: web.Request) -> web.Response:
    sem = _get_sem()
    if sem is None:
        await _work()
    else:
        async with sem:
            await _work()
    return web.json_response(
        {
            "user": "demo",
            "balance": 4210.55,
            "currency": "USD",
            "transactions": [
                {"id": 1, "amount": -12.0, "desc": "coffee"},
                {"id": 2, "amount": 900.0, "desc": "salary"},
            ],
        }
    )


async def handle(request: web.Request) -> web.Response:
    # Generator / API path: read and discard the body, then answer exactly as
    # the training captures saw. Keep this branch boring on purpose.
    sem = _get_sem()
    if sem is None:
        await request.read()
        await _work()
    else:
        async with sem:
            await request.read()
            await _work()
    return web.Response(text="ok")


app = web.Application()
app.router.add_get("/", index)
app.router.add_get("/health", health)
app.router.add_get("/api/account", account)
app.router.add_route("*", "/{path:.*}", handle)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=80)
