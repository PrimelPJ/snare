"""Live threat map server.

Serves a single page (Leaflet map + side panel) and pushes every event
to connected browsers over a WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
from pathlib import Path
from typing import Any

from aiohttp import WSMsgType, web

from .events import Event
from .stats import Stats

log = logging.getLogger(__name__)

STATIC = Path(__file__).parent / "static"
MAX_CLIENTS = 200


class Dashboard:
    def __init__(self, stats: Stats, home: tuple[float, float], name: str, token: str | None = None) -> None:
        self.stats = stats
        self.home = home
        self.name = name
        self.token = token
        self.clients: set[web.WebSocketResponse] = set()

    async def on_event(self, event: Event) -> None:
        self.stats.add(event)
        if not self.clients:
            return
        msg = json.dumps({"type": "event", "event": event.to_dict(), "stats": self._light_stats()})
        dead = []
        for ws in self.clients:
            try:
                await asyncio.wait_for(ws.send_str(msg), 2)
            except (ConnectionError, asyncio.TimeoutError, RuntimeError):
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    def _light_stats(self) -> dict[str, Any]:
        s = self.stats
        return {"total": s.total, "unique_ips": len(s.ips)}

    def _authorized(self, request: web.Request) -> bool:
        if not self.token:
            return True
        given = request.query.get("token") or request.cookies.get("snare_token") or ""
        return secrets.compare_digest(given, self.token)

    async def index(self, request: web.Request) -> web.StreamResponse:
        if not self._authorized(request):
            return web.Response(status=401, text="token required")
        resp = web.FileResponse(STATIC / "index.html")
        if self.token:
            resp.set_cookie("snare_token", self.token, httponly=True, samesite="Strict")
        return resp

    async def api_stats(self, request: web.Request) -> web.Response:
        if not self._authorized(request):
            return web.Response(status=401)
        return web.json_response(self.stats.snapshot())

    async def ws(self, request: web.Request) -> web.WebSocketResponse:
        if not self._authorized(request) or len(self.clients) >= MAX_CLIENTS:
            raise web.HTTPForbidden()
        ws = web.WebSocketResponse(heartbeat=30)
        await ws.prepare(request)
        await ws.send_str(
            json.dumps(
                {
                    "type": "hello",
                    "home": {"lat": self.home[0], "lon": self.home[1], "name": self.name},
                    "recent": list(self.stats.recent),
                    "stats": self.stats.snapshot(),
                }
            )
        )
        self.clients.add(ws)
        try:
            async for msg in ws:  # the page never sends anything we need
                if msg.type == WSMsgType.ERROR:
                    break
        finally:
            self.clients.discard(ws)
        return ws

    async def stats_pusher(self) -> None:
        """Send the full panel numbers every few seconds (cheaper than per event)."""
        while True:
            await asyncio.sleep(3)
            if not self.clients:
                continue
            msg = json.dumps({"type": "stats", "stats": self.stats.snapshot()})
            for ws in list(self.clients):
                try:
                    await ws.send_str(msg)
                except (ConnectionError, RuntimeError):
                    self.clients.discard(ws)

    def app(self) -> web.Application:
        app = web.Application()
        app.router.add_get("/", self.index)
        app.router.add_get("/ws", self.ws)
        app.router.add_get("/api/stats", self.api_stats)
        async def healthz(_: web.Request) -> web.Response:
            return web.Response(text="ok")

        app.router.add_get("/healthz", healthz)
        app.router.add_static("/static", STATIC)

        @web.middleware
        async def headers(request, handler):
            resp = await handler(request)
            resp.headers["X-Content-Type-Options"] = "nosniff"
            resp.headers["Referrer-Policy"] = "no-referrer"
            resp.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self'; "
                "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                "font-src https://fonts.gstatic.com; img-src 'self' data:; "
                "connect-src 'self' ws: wss:; frame-ancestors 'none'"
            )
            return resp

        app.middlewares.append(headers)
        return app


async def start_dashboard(dash: Dashboard, host: str, port: int) -> web.AppRunner:
    runner = web.AppRunner(dash.app(), access_log=None)
    await runner.setup()
    await web.TCPSite(runner, host, port).start()
    log.info("live map on http://%s:%s", host, port)
    return runner
