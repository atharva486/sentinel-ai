#!/usr/bin/env python3
"""Simple HTTP backend that reads request body and responds."""

import asyncio
from aiohttp import web


async def handle(request):
    # Read and discard the request body
    await request.read()
    return web.Response(text="ok")


app = web.Application()
app.router.add_route("*", "/{path:.*}", handle)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=80)