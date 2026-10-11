"""End to end: start each sensor on a free port, attack it, check what was logged."""

import asyncio
import base64
import json

import aiohttp
import asyncssh
from aiohttp.test_utils import TestClient, TestServer

from snare.dashboard import Dashboard
from snare.events import LOGIN_ATTEMPT, EventBus
from snare.sensors.common import ConnectionLimiter
from snare.sensors.http import build_app
from snare.sensors.ssh import start_ssh
from snare.sensors.telnet import start_telnet, strip_telnet
from snare.simulate import simulate
from snare.stats import Stats


def logins(bus):
    out = []
    while not bus._queue.empty():
        e = bus._queue.get_nowait()
        if e.kind == LOGIN_ATTEMPT:
            out.append(e)
    return out


async def test_ssh_logs_password_and_never_lets_in(tmp_path):
    bus = EventBus()
    acceptor = await start_ssh(bus, "127.0.0.1", 0, tmp_path / "key", ConnectionLimiter())
    port = acceptor.sockets[0].getsockname()[1]
    try:
        await asyncssh.connect("127.0.0.1", port, username="root", password="hunter2",
                               known_hosts=None, preferred_auth="password")
        raise AssertionError("login should never succeed")
    except asyncssh.PermissionDenied:
        pass
    finally:
        acceptor.close()
    got = logins(bus)
    assert [(e.username, e.password) for e in got] == [("root", "hunter2")]
    assert got[0].client.startswith("SSH-2.0-")


async def test_ssh_host_key_is_reused(tmp_path):
    bus = EventBus()
    a = await start_ssh(bus, "127.0.0.1", 0, tmp_path / "key", ConnectionLimiter())
    first = (tmp_path / "key").read_bytes()
    a.close()
    b = await start_ssh(bus, "127.0.0.1", 0, tmp_path / "key", ConnectionLimiter())
    b.close()
    assert (tmp_path / "key").read_bytes() == first


def test_strip_telnet_negotiation():
    raw = bytes([255, 251, 1, 255, 253, 3]) + b"root" + bytes([255, 250, 24, 0, 255, 240]) + b"\r"
    assert strip_telnet(raw) == b"root\r"


async def test_telnet_logs_credentials():
    bus = EventBus()
    server = await start_telnet(bus, "127.0.0.1", 0, ConnectionLimiter())
    port = server.sockets[0].getsockname()[1]
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(b"root\r\nxc3511\r\nadmin\r\nadmin\r\n")
    await writer.drain()
    out = b""
    try:
        while out.count(b"Login incorrect") < 2:
            chunk = await asyncio.wait_for(reader.read(1024), 5)
            if not chunk:
                break
            out += chunk
    finally:
        writer.close()
        server.close()
    assert [(e.username, e.password) for e in logins(bus)] == [("root", "xc3511"), ("admin", "admin")]


async def test_http_form_and_basic_auth():
    bus = EventBus()
    async with TestClient(TestServer(build_app(bus, 80))) as client:
        r = await client.post("/login", data={"username": "admin", "password": "pw1"})
        assert r.status == 401
        auth = base64.b64encode(b"bob:pw2").decode()
        r = await client.get("/.env", headers={"Authorization": f"Basic {auth}"})
        assert r.status == 200 and r.headers["Server"].startswith("lighttpd")
    assert [(e.username, e.password) for e in logins(bus)] == [("admin", "pw1"), ("bob", "pw2")]


def test_connection_limiter():
    lim = ConnectionLimiter(per_ip=2, total=3)
    assert lim.acquire("a") and lim.acquire("a") and not lim.acquire("a")
    assert lim.acquire("b") and not lim.acquire("c")  # total cap
    lim.release("a")
    assert lim.acquire("c") and lim.open_total == 3


async def test_dashboard_streams_events_over_websocket():
    bus = EventBus()
    dash = Dashboard(Stats(), (51.0, -114.0), "test", token="s3cret")
    bus.subscribe(dash.on_event)
    bus_task = asyncio.create_task(bus.run())
    async with TestClient(TestServer(dash.app())) as client:
        assert (await client.get("/")).status == 401
        assert (await client.get("/?token=s3cret")).status == 200
        ws = await client.ws_connect("/ws?token=s3cret")
        hello = json.loads((await ws.receive()).data)
        assert hello["type"] == "hello" and hello["home"]["name"] == "test"
        await simulate(bus, rate=1000, seed=1, limit=5)
        await bus.drain()
        msgs = [json.loads((await ws.receive(timeout=2)).data) for _ in range(5)]
        assert all(m["type"] == "event" and m["event"]["lat"] is not None for m in msgs)
        await ws.close()
    bus_task.cancel()
