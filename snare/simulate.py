"""Fake attack traffic for demos and local development.

Uses IPs from the documentation ranges (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) so nothing here points at a real host. Locations are
picked from a weighted list of cities that commonly show up in real
honeypot data.
"""

from __future__ import annotations

import asyncio
import random

from .events import CONNECT, HTTP_REQUEST, LOGIN_ATTEMPT, Event, EventBus

# (country, code, city, lat, lon, weight)
ORIGINS = [
    ("China", "CN", "Beijing", 39.90, 116.40, 14),
    ("China", "CN", "Shanghai", 31.23, 121.47, 10),
    ("United States", "US", "Ashburn", 39.04, -77.49, 12),
    ("United States", "US", "San Jose", 37.34, -121.89, 6),
    ("Russia", "RU", "Moscow", 55.75, 37.62, 9),
    ("Netherlands", "NL", "Amsterdam", 52.37, 4.90, 7),
    ("Germany", "DE", "Frankfurt", 50.11, 8.68, 6),
    ("Brazil", "BR", "Sao Paulo", -23.55, -46.63, 6),
    ("India", "IN", "Mumbai", 19.08, 72.88, 6),
    ("Vietnam", "VN", "Hanoi", 21.03, 105.85, 5),
    ("South Korea", "KR", "Seoul", 37.57, 126.98, 5),
    ("Singapore", "SG", "Singapore", 1.35, 103.82, 4),
    ("Indonesia", "ID", "Jakarta", -6.21, 106.85, 4),
    ("Iran", "IR", "Tehran", 35.69, 51.39, 3),
    ("Bulgaria", "BG", "Sofia", 42.70, 23.32, 3),
    ("Hong Kong", "HK", "Hong Kong", 22.32, 114.17, 3),
    ("United Kingdom", "GB", "London", 51.51, -0.13, 3),
    ("France", "FR", "Paris", 48.86, 2.35, 2),
    ("Taiwan", "TW", "Taipei", 25.03, 121.57, 2),
    ("Argentina", "AR", "Buenos Aires", -34.60, -58.38, 2),
    ("Nigeria", "NG", "Lagos", 6.52, 3.38, 1),
    ("Ukraine", "UA", "Kyiv", 50.45, 30.52, 2),
    ("Turkey", "TR", "Istanbul", 41.01, 28.98, 2),
    ("Australia", "AU", "Sydney", -33.87, 151.21, 1),
]

USERS = ["root"] * 12 + ["admin"] * 8 + ["ubuntu", "user", "test", "oracle", "postgres", "pi", "support", "guest", "ftpuser", "git", "deploy", "solana", "sol", "mysql", "www-data", "nagios"]
PASSWORDS = ["123456"] * 6 + ["admin"] * 4 + ["password", "root", "12345678", "1234", "qwerty", "123", "P@ssw0rd", "admin123", "toor", "raspberry", "ubuntu", "1qaz2wsx", "abc123", ""]
TELNET_CREDS = [("root", "xc3511"), ("root", "vizxv"), ("admin", "admin"), ("root", "default"), ("support", "support"), ("root", "7ujMko0admin"), ("guest", "12345")]
PATHS = ["/", "/.env", "/wp-login.php", "/admin", "/phpmyadmin/", "/boaform/admin/formLogin", "/cgi-bin/luci", "/.git/config", "/HNAP1/", "/login", "/actuator/env", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]
AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/7.88.1", "python-requests/2.31.0", "Go-http-client/1.1", "zgrab/0.x", "Mozilla/5.0 (compatible; CensysInspect/1.1)"]
SSH_CLIENTS = ["SSH-2.0-Go", "SSH-2.0-libssh2_1.10.0", "SSH-2.0-PuTTY_Release_0.78", "SSH-2.0-paramiko_3.1.0", "SSH-2.0-OpenSSH_7.4"]

DOC_NETS = ["192.0.2.", "198.51.100.", "203.0.113."]


class Attacker:
    def __init__(self, rng: random.Random) -> None:
        o = rng.choices(ORIGINS, weights=[x[5] for x in ORIGINS])[0]
        self.country, self.code, self.city, lat, lon, _ = o
        self.lat = round(lat + rng.uniform(-1.5, 1.5), 3)
        self.lon = round(lon + rng.uniform(-1.5, 1.5), 3)
        self.ip = rng.choice(DOC_NETS) + str(rng.randint(1, 254))
        self.sensor = rng.choices(["ssh", "telnet", "http"], weights=[6, 2, 2])[0]

    def event(self, kind: str, rng: random.Random, **kw) -> Event:
        port = {"ssh": 22, "telnet": 23, "http": 80}[self.sensor]
        return Event(
            self.sensor, kind, self.ip, rng.randint(30000, 65000), port,
            country=self.country, country_code=self.code, city=self.city,
            lat=self.lat, lon=self.lon, asn="AS64500 Example Net", **kw,
        )


async def simulate(bus: EventBus, rate: float = 2.0, seed: int | None = None, limit: int | None = None) -> None:
    """Publish fake events at roughly `rate` per second. Stops after `limit` events if set."""
    rng = random.Random(seed)
    pool = [Attacker(rng) for _ in range(120)]
    sent = 0
    while limit is None or sent < limit:
        a = rng.choice(pool)
        if a.sensor == "http":
            path = rng.choice(PATHS)
            ev = a.event(HTTP_REQUEST, rng, method=rng.choice(["GET", "GET", "POST"]), path=path, client=rng.choice(AGENTS))
        elif rng.random() < 0.15:
            ev = a.event(CONNECT, rng)
        elif a.sensor == "telnet":
            u, p = rng.choice(TELNET_CREDS)
            ev = a.event(LOGIN_ATTEMPT, rng, username=u, password=p)
        else:
            ev = a.event(LOGIN_ATTEMPT, rng, username=rng.choice(USERS), password=rng.choice(PASSWORDS), client=rng.choice(SSH_CLIENTS))
        bus.publish(ev)
        sent += 1
        # bursty: brute force tools fire several tries back to back
        await asyncio.sleep(rng.expovariate(rate) if rng.random() > 0.3 else 0.05)
