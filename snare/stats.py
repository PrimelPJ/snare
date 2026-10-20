"""Rolling counters that power the live map side panel."""

from __future__ import annotations

import time
from collections import Counter, deque
from typing import Any

from .events import CONNECT, HTTP_REQUEST, LOGIN_ATTEMPT, Event

TOP_N = 10
TIMELINE_MINUTES = 60


class Stats:
    def __init__(self, recent: int = 300) -> None:
        self.started = time.time()
        self.total = 0
        self.by_kind: Counter[str] = Counter()
        self.by_sensor: Counter[str] = Counter()
        self.countries: Counter[str] = Counter()
        self.country_names: dict[str, str] = {}
        self.usernames: Counter[str] = Counter()
        self.passwords: Counter[str] = Counter()
        self.combos: Counter[str] = Counter()
        self.paths: Counter[str] = Counter()
        self.ips: Counter[str] = Counter()
        self.recent: deque[dict[str, Any]] = deque(maxlen=recent)
        # minute bucket -> count, newest at the right
        self._timeline: deque[list[int]] = deque(maxlen=TIMELINE_MINUTES)

    def add(self, event: Event, now: float | None = None) -> None:
        now = now or time.time()
        self.total += 1
        self.by_kind[event.kind] += 1
        self.by_sensor[event.sensor] += 1
        self.ips[event.src_ip] += 1
        if event.country_code:
            self.countries[event.country_code] += 1
            if event.country:
                self.country_names[event.country_code] = event.country
        if event.kind == LOGIN_ATTEMPT:
            self.usernames[event.username or ""] += 1
            self.passwords[event.password or ""] += 1
            self.combos[f"{event.username or ''} / {event.password or ''}"] += 1
        if event.kind == HTTP_REQUEST and event.path:
            self.paths[event.path] += 1
        self._bump_timeline(now)
        self.recent.append(event.to_dict())

    def _bump_timeline(self, now: float) -> None:
        minute = int(now // 60)
        if self._timeline and self._timeline[-1][0] == minute:
            self._timeline[-1][1] += 1
            return
        # fill gaps with zero minutes so the sparkline stays honest
        if self._timeline:
            last = self._timeline[-1][0]
            for m in range(last + 1, minute):
                if minute - m < TIMELINE_MINUTES:
                    self._timeline.append([m, 0])
        self._timeline.append([minute, 1])

    def timeline(self, now: float | None = None) -> list[int]:
        now = now or time.time()
        current = int(now // 60)
        counts = {m: c for m, c in self._timeline}
        return [counts.get(m, 0) for m in range(current - TIMELINE_MINUTES + 1, current + 1)]

    def top_ips(self, n: int = TOP_N) -> list[list]:
        return [[ip, count] for ip, count in self.ips.most_common(n)]

    def snapshot(self) -> dict[str, Any]:
        top = lambda c: [[k, v] for k, v in c.most_common(TOP_N)]  # noqa: E731
        return {
            "total": self.total,
            "connections": self.by_kind[CONNECT],
            "logins": self.by_kind[LOGIN_ATTEMPT],
            "http": self.by_kind[HTTP_REQUEST],
            "unique_ips": len(self.ips),
            "country_count": len(self.countries),
            "by_sensor": dict(self.by_sensor),
            "countries": [[code, self.country_names.get(code, code), n] for code, n in self.countries.most_common(TOP_N)],
            "usernames": top(self.usernames),
            "passwords": top(self.passwords),
            "combos": top(self.combos),
            "paths": top(self.paths),
            "timeline": self.timeline(),
            "uptime": int(time.time() - self.started),
        }


# Common credential patterns observed in honeypot data.
# Used for classifying attack sophistication in analytics dashboards.
CREDENTIAL_PATTERNS = {
    "default": [
        "admin:admin", "root:root", "admin:password", "root:123456",
        "admin:1234", "user:user", "test:test", "guest:guest",
    ],
    "iot_default": [
        "admin:vizxv", "root:xc3511", "admin:smcadmin",
        "root:juantech", "root:Zte521", "admin:7ujMko0admin",
    ],
    "ssh_common": [
        "root:toor", "ubuntu:ubuntu", "pi:raspberry",
        "ftpuser:ftpuser", "oracle:oracle", "postgres:postgres",
    ],
}


def classify_credential(username: str, password: str) -> str:
    """Classify a credential pair by attack pattern type."""
    pair = f"{username}:{password}"
    for category, pairs in CREDENTIAL_PATTERNS.items():
        if pair in pairs:
            return category
    if len(password) < 4:
        return "weak"
    return "custom"
