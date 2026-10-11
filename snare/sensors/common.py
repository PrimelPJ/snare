"""Small helpers shared by the sensors."""

from __future__ import annotations

import time
from collections import defaultdict


class ConnectionLimiter:
    """Cap open connections per IP and overall so a flood cannot exhaust the VM."""

    def __init__(self, per_ip: int = 20, total: int = 500) -> None:
        self.per_ip = per_ip
        self.total = total
        self._open: dict[str, int] = defaultdict(int)
        self._total = 0

    def acquire(self, ip: str) -> bool:
        if self._total >= self.total or self._open[ip] >= self.per_ip:
            return False
        self._open[ip] += 1
        self._total += 1
        return True

    def release(self, ip: str) -> None:
        if self._open.get(ip, 0) > 0:
            self._open[ip] -= 1
            self._total -= 1
            if self._open[ip] == 0:
                del self._open[ip]

    @property
    def open_total(self) -> int:
        return self._total


class Throttle:
    """Delay helper: slows down repeat guessers a little, like a real server would."""

    def __init__(self, base_delay: float = 0.5) -> None:
        self.base_delay = base_delay
        self._last: dict[str, float] = {}

    def delay_for(self, ip: str) -> float:
        now = time.monotonic()
        last = self._last.get(ip)
        self._last[ip] = now
        if last is not None and now - last < 1.0:
            return self.base_delay * 2
        return self.base_delay


def peer(transport_or_writer) -> tuple[str, int]:
    info = transport_or_writer.get_extra_info("peername") or ("0.0.0.0", 0)
    return str(info[0]), int(info[1])
