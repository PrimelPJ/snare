"""Event model and an in-process pub/sub bus.

Every sensor turns what it sees into an Event and publishes it. Sinks
(file, Azure, live map) subscribe and handle it in their own way.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

log = logging.getLogger(__name__)

# What a sensor can report.
CONNECT = "connect"
LOGIN_ATTEMPT = "login_attempt"
HTTP_REQUEST = "http_request"
KINDS = {CONNECT, LOGIN_ATTEMPT, HTTP_REQUEST}

MAX_FIELD = 256  # attackers send junk; cap every string we store

DEFAULT_PORTS = {"ssh": 22, "telnet": 23, "http": 80}


def _clip(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.replace("\x00", "")
    return value[:MAX_FIELD]


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Event:
    sensor: str  # ssh | telnet | http
    kind: str
    src_ip: str
    src_port: int
    dst_port: int
    username: str | None = None
    password: str | None = None
    client: str | None = None  # SSH client version or HTTP user agent
    method: str | None = None
    path: str | None = None
    # Filled in by the geo enricher.
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: str | None = None
    # Filled in when the event is created.
    time: str = field(default_factory=utcnow)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    honeypot: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in KINDS:
            raise ValueError(f"unknown event kind: {self.kind}")
        for name in ("username", "password", "client", "method", "path"):
            setattr(self, name, _clip(getattr(self, name)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_azure(self) -> dict[str, Any]:
        """Shape the event to match the HoneypotEvents_CL table columns."""
        d = self.to_dict()
        return {
            "TimeGenerated": d.pop("time"),
            "EventId": d.pop("id"),
            "Sensor": d.pop("sensor"),
            "Kind": d.pop("kind"),
            "SrcIp": d.pop("src_ip"),
            "SrcPort": d.pop("src_port"),
            "DstPort": d.pop("dst_port"),
            "Username": d.pop("username"),
            "Password": d.pop("password"),
            "Client": d.pop("client"),
            "Method": d.pop("method"),
            "Path": d.pop("path"),
            "Country": d.pop("country"),
            "CountryCode": d.pop("country_code"),
            "City": d.pop("city"),
            "Latitude": d.pop("lat"),
            "Longitude": d.pop("lon"),
            "Asn": d.pop("asn"),
            "Honeypot": d.pop("honeypot"),
        }


Handler = Callable[[Event], Awaitable[None]]


class EventBus:
    """Fan events out to every subscriber without letting one slow sink block sensors."""

    def __init__(self, queue_size: int = 10_000) -> None:
        self._queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=queue_size)
        self._handlers: list[Handler] = []
        self._enrichers: list[Callable[[Event], Awaitable[None]]] = []
        self.dropped = 0
        self.published = 0

    def subscribe(self, handler: Handler) -> None:
        self._handlers.append(handler)

    def add_enricher(self, enricher: Callable[[Event], Awaitable[None]]) -> None:
        self._enrichers.append(enricher)

    def publish(self, event: Event) -> None:
        try:
            self._queue.put_nowait(event)
            self.published += 1
        except asyncio.QueueFull:
            # Under a flood we drop rather than run out of memory.
            self.dropped += 1

    async def run(self) -> None:
        while True:
            event = await self._queue.get()
            for enrich in self._enrichers:
                try:
                    await enrich(event)
                except Exception:  # enrichment is best effort
                    log.exception("enricher failed")
            for handler in self._handlers:
                try:
                    await handler(event)
                except Exception:
                    log.exception("handler failed")
            self._queue.task_done()

    async def drain(self) -> None:
        await self._queue.join()
