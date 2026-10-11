import asyncio
import json

import pytest

from snare.events import CONNECT, HTTP_REQUEST, LOGIN_ATTEMPT, MAX_FIELD, Event, EventBus
from snare.geo import GeoEnricher, GeoInfo, TTLCache, is_public
from snare.sinks import BatchingSink, JsonlSink
from snare.stats import Stats


def ev(**kw):
    base = dict(sensor="ssh", kind=LOGIN_ATTEMPT, src_ip="8.8.8.8", src_port=1, dst_port=22)
    base.update(kw)
    return Event(**base)


# ---------- events ----------

def test_event_rejects_unknown_kind():
    with pytest.raises(ValueError):
        ev(kind="nope")


def test_event_clips_and_strips_nulls():
    e = ev(username="a\x00b" + "x" * 1000)
    assert "\x00" not in e.username
    assert len(e.username) == MAX_FIELD


def test_azure_shape_has_table_columns():
    row = ev(username="root", password="toor").to_azure()
    for col in ["TimeGenerated", "SrcIp", "Username", "Password", "Latitude", "Longitude", "Kind", "Sensor"]:
        assert col in row
    assert row["TimeGenerated"].endswith("Z")


async def test_bus_fans_out_and_enriches():
    bus = EventBus()
    got_a, got_b = [], []

    async def enrich(e):
        e.country = "Testland"

    async def a(e):
        got_a.append(e)

    async def b(e):
        got_b.append(e.country)

    bus.add_enricher(enrich)
    bus.subscribe(a)
    bus.subscribe(b)
    task = asyncio.create_task(bus.run())
    bus.publish(ev())
    await bus.drain()
    task.cancel()
    assert len(got_a) == 1 and got_b == ["Testland"]


async def test_bus_survives_bad_handler():
    bus = EventBus()
    ok = []

    async def boom(e):
        raise RuntimeError("bad sink")

    async def good(e):
        ok.append(e)

    bus.subscribe(boom)
    bus.subscribe(good)
    task = asyncio.create_task(bus.run())
    bus.publish(ev())
    await bus.drain()
    task.cancel()
    assert len(ok) == 1


def test_bus_drops_when_full():
    bus = EventBus(queue_size=2)
    for _ in range(5):
        bus.publish(ev())
    assert bus.published == 2 and bus.dropped == 3


# ---------- geo ----------

def test_is_public():
    assert is_public("8.8.8.8")
    for ip in ["10.0.0.1", "192.168.1.1", "127.0.0.1", "203.0.113.5", "garbage"]:
        assert not is_public(ip)


async def test_geo_caches_lookups():
    calls = []

    class Fake:
        async def lookup(self, ip):
            calls.append(ip)
            return GeoInfo(country="Canada", country_code="CA", lat=51.0, lon=-114.0)

    g = GeoEnricher(Fake())
    e1, e2 = ev(), ev()
    await g(e1)
    await g(e2)
    assert calls == ["8.8.8.8"]
    assert e2.country_code == "CA" and e2.lat == 51.0


async def test_geo_skips_private_ips():
    class Fail:
        async def lookup(self, ip):
            raise AssertionError("should not be called")

    e = ev(src_ip="10.1.2.3")
    await GeoEnricher(Fail())(e)
    assert e.lat is None


def test_ttl_cache_evicts_oldest():
    c = TTLCache(size=2)
    c.put("a", GeoInfo())
    c.put("b", GeoInfo())
    c.put("c", GeoInfo())
    assert c.get("a") is None and len(c) == 2


# ---------- stats ----------

def test_stats_counts_and_timeline():
    s = Stats()
    now = 1_700_000_000.0
    s.add(ev(username="root", password="123", country_code="CN", country="China"), now)
    s.add(ev(username="root", password="admin", country_code="CN", country="China"), now)
    s.add(ev(kind=HTTP_REQUEST, sensor="http", path="/.env", src_ip="1.1.1.1"), now + 120)
    s.add(ev(kind=CONNECT), now + 120)
    snap = s.snapshot()
    assert snap["total"] == 4 and snap["logins"] == 2 and snap["unique_ips"] == 2
    assert snap["usernames"][0] == ["root", 2]
    assert snap["countries"][0] == ["CN", "China", 2]
    assert snap["paths"][0] == ["/.env", 1]
    tl = s.timeline(now + 120)
    assert len(tl) == 60 and tl[-1] == 2 and tl[-3] == 2 and tl[-2] == 0


# ---------- sinks ----------

async def test_jsonl_sink_writes_lines(tmp_path):
    sink = JsonlSink(tmp_path)
    await sink(ev(username="root"))
    await sink(ev(username="admin"))
    sink.close()
    lines = next(tmp_path.glob("events-*.jsonl")).read_text().splitlines()
    assert [json.loads(l)["username"] for l in lines] == ["root", "admin"]


async def test_batching_sink_retries_without_losing_order():
    sent, fail = [], {"n": 1}

    async def upload(batch):
        if fail["n"]:
            fail["n"] -= 1
            raise IOError("network down")
        sent.extend(r["Username"] for r in batch)

    sink = BatchingSink(upload, batch_size=2)
    for u in "abc":
        await sink(ev(username=u))
    assert not await sink.flush_once()  # first upload fails, events go back
    assert await sink.flush_once()
    assert await sink.flush_once()
    assert sent == ["a", "b", "c"] and sink.failures == 1 and not sink.buffer
