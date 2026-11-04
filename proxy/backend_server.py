#!/usr/bin/env python3
import asyncio
from aiohttp import web

async def index(request):
    return web.json_response({"service": "aurora-bank", "status": "ok"})

async def account(request):
    return web.json_response({
        "user": "demo",
        "balance": 4210.55,
        "currency": "USD"
    })

async def handle(request):
    await request.read()
    return web.Response(text="ok")

app = web.Application()
app.router.add_get("/", index)
app.router.add_get("/api/account", account)
app.router.add_route("*", "/{path:.*}", handle)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=80)
