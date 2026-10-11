"""Turn attacker IPs into countries and map coordinates.

Two backends:
  * MaxMind GeoLite2 City (+ optional ASN) database on disk. Fast, offline,
    no rate limits. Recommended for the cloud deploy.
  * ip-api.com free endpoint. Needs no setup, but is limited to 45
    lookups a minute and is for non-commercial use only.

Results are cached, so one noisy IP costs one lookup.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import aiohttp

from .events import Event

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class GeoInfo:
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: str | None = None


EMPTY = GeoInfo()


class Backend(Protocol):
    async def lookup(self, ip: str) -> GeoInfo | None: ...


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global


class TTLCache:
    def __init__(self, size: int = 50_000, ttl: float = 24 * 3600) -> None:
        self.size = size
        self.ttl = ttl
        self._data: OrderedDict[str, tuple[float, GeoInfo]] = OrderedDict()

    def get(self, key: str) -> GeoInfo | None:
        item = self._data.get(key)
        if item is None:
            return None
        stamp, value = item
        if time.monotonic() - stamp > self.ttl:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return value

    def put(self, key: str, value: GeoInfo) -> None:
        self._data[key] = (time.monotonic(), value)
        self._data.move_to_end(key)
        while len(self._data) > self.size:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


class MaxMindBackend:
    def __init__(self, city_db: Path, asn_db: Path | None = None) -> None:
        import maxminddb  # optional dependency

        self._city = maxminddb.open_database(str(city_db))
        self._asn = maxminddb.open_database(str(asn_db)) if asn_db and asn_db.exists() else None

    async def lookup(self, ip: str) -> GeoInfo | None:
        rec = self._city.get(ip) or {}
        loc = rec.get("location", {})
        country = rec.get("country", {})
        asn = None
        if self._asn:
            a = self._asn.get(ip) or {}
            if a:
                asn = f"AS{a.get('autonomous_system_number')} {a.get('autonomous_system_organization', '')}".strip()
        return GeoInfo(
            country=country.get("names", {}).get("en"),
            country_code=country.get("iso_code"),
            city=rec.get("city", {}).get("names", {}).get("en"),
            lat=loc.get("latitude"),
            lon=loc.get("longitude"),
            asn=asn,
        )


class IpApiBackend:
    URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon,as"

    def __init__(self, per_minute: int = 40) -> None:
        self.per_minute = per_minute
        self._stamps: list[float] = []
        self._session: aiohttp.ClientSession | None = None

    def _allowed(self) -> bool:
        now = time.monotonic()
        self._stamps = [t for t in self._stamps if now - t < 60]
        if len(self._stamps) >= self.per_minute:
            return False
        self._stamps.append(now)
        return True

    async def lookup(self, ip: str) -> GeoInfo | None:
        if not self._allowed():
            return None  # over budget, try again on a later event
        if self._session is None:
            self._session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5))
        try:
            async with self._session.get(self.URL.format(ip=ip)) as resp:
                data = await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None
        if data.get("status") != "success":
            return EMPTY
        return GeoInfo(
            country=data.get("country"),
            country_code=data.get("countryCode"),
            city=data.get("city"),
            lat=data.get("lat"),
            lon=data.get("lon"),
            asn=data.get("as"),
        )

    async def close(self) -> None:
        if self._session:
            await self._session.close()


class GeoEnricher:
    def __init__(self, backend: Backend | None, cache: TTLCache | None = None) -> None:
        self.backend = backend
        self.cache = cache or TTLCache()

    async def __call__(self, event: Event) -> None:
        if event.lat is not None:  # already enriched (simulator does this)
            return
        info = await self.resolve(event.src_ip)
        if info:
            event.country = info.country
            event.country_code = info.country_code
            event.city = info.city
            event.lat = info.lat
            event.lon = info.lon
            event.asn = info.asn

    async def resolve(self, ip: str) -> GeoInfo | None:
        if not is_public(ip):
            return None
        hit = self.cache.get(ip)
        if hit is not None:
            return hit
        if self.backend is None:
            return None
        info = await self.backend.lookup(ip)
        if info is not None:
            self.cache.put(ip, info)
        return info


def make_backend(city_db: str | None, asn_db: str | None, allow_online: bool) -> Backend | None:
    if city_db and Path(city_db).exists():
        log.info("geo: using MaxMind database %s", city_db)
        return MaxMindBackend(Path(city_db), Path(asn_db) if asn_db else None)
    if allow_online:
        log.info("geo: using ip-api.com (rate limited)")
        return IpApiBackend()
    log.warning("geo: no backend, events will have no location")
    return None
