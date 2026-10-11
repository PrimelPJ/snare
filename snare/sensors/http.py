"""Fake web admin login.

Serves a plain router style login page. Every request is logged, and
form posts or HTTP Basic auth attempts are logged as login attempts.
No login ever succeeds.
"""

from __future__ import annotations

import base64
import logging

from aiohttp import web

from ..events import HTTP_REQUEST, LOGIN_ATTEMPT, Event, EventBus

log = logging.getLogger(__name__)

LOGIN_PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Admin Login</title>
<style>body{font-family:sans-serif;background:#eef1f4;display:flex;height:100vh;
align-items:center;justify-content:center}form{background:#fff;padding:32px;
border-radius:6px;box-shadow:0 2px 8px #0002;width:260px}input{width:100%;
margin:6px 0 14px;padding:8px;box-sizing:border-box}button{width:100%;padding:9px}
.err{color:#b00;font-size:13px}</style></head>
<body><form method="post" action="/login">
<h3>Device Administration</h3>{error}
<label>Username</label><input name="username" autocomplete="off">
<label>Password</label><input name="password" type="password">
<button type="submit">Sign in</button></form></body></html>"""

MAX_BODY = 16 * 1024


def _ip(request: web.Request) -> tuple[str, int]:
    peer = request.transport.get_extra_info("peername") if request.transport else None
    if not peer:
        return "0.0.0.0", 0
    return str(peer[0]), int(peer[1])


def _basic_auth(header: str | None) -> tuple[str, str] | None:
    if not header or not header.lower().startswith("basic "):
        return None
    try:
        raw = base64.b64decode(header[6:].strip(), validate=True).decode("utf-8", "replace")
    except (ValueError, UnicodeDecodeError):
        return None
    user, _, password = raw.partition(":")
    return user, password


def build_app(bus: EventBus, port: int) -> web.Application:
    async def handler(request: web.Request) -> web.Response:
        ip, src_port = _ip(request)
        ua = request.headers.get("User-Agent")
        common = dict(client=ua, method=request.method, path=request.path_qs)

        bus.publish(Event("http", HTTP_REQUEST, ip, src_port, port, **common))

        creds = _basic_auth(request.headers.get("Authorization"))
        if creds:
            bus.publish(Event("http", LOGIN_ATTEMPT, ip, src_port, port, username=creds[0], password=creds[1], **common))

        if request.method == "POST":
            form = await request.post() if request.can_read_body else {}
            user = form.get("username") or form.get("user") or form.get("login")
            password = form.get("password") or form.get("pass") or form.get("pwd")
            if user is not None or password is not None:
                bus.publish(
                    Event("http", LOGIN_ATTEMPT, ip, src_port, port, username=str(user or ""), password=str(password or ""), **common)
                )
                return _page('<p class="err">Invalid username or password.</p>', status=401)

        return _page("")

    app = web.Application(client_max_size=MAX_BODY)
    app.router.add_route("*", "/{tail:.*}", handler)
    return app


def _page(error: str, status: int = 200) -> web.Response:
    return web.Response(
        text=LOGIN_PAGE.replace("{error}", error),
        content_type="text/html",
        status=status,
        headers={"Server": "lighttpd/1.4.59"},
    )


async def start_http(bus: EventBus, host: str, port: int) -> web.AppRunner:
    runner = web.AppRunner(build_app(bus, port), access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    log.info("http sensor listening on %s:%s", host, port)
    return runner
