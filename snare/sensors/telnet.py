"""Fake Telnet login prompt.

Mirai style IoT bots still hammer port 23 with default router and camera
passwords. We show a login prompt, record what they type, and always
answer "Login incorrect".
"""

from __future__ import annotations

import asyncio
import logging

from ..events import CONNECT, LOGIN_ATTEMPT, Event, EventBus
from .common import ConnectionLimiter, peer

log = logging.getLogger(__name__)

IAC = 255
BANNER = b"\r\nUbuntu 22.04.4 LTS\r\n"
MAX_TRIES = 3
READ_TIMEOUT = 30
MAX_LINE = 512


def strip_telnet(data: bytes) -> bytes:
    """Remove Telnet option negotiation (IAC sequences) from raw input."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == IAC and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd == IAC:  # escaped 0xFF
                out.append(IAC)
                i += 2
            elif cmd == 250:  # SB ... IAC SE
                end = data.find(bytes([IAC, 240]), i + 2)
                i = len(data) if end == -1 else end + 2
            elif 251 <= cmd <= 254:  # WILL WONT DO DONT + option
                i += 3
            else:
                i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


async def read_line(reader: asyncio.StreamReader) -> str | None:
    buf = bytearray()
    while len(buf) < MAX_LINE:
        chunk = await asyncio.wait_for(reader.read(1), READ_TIMEOUT)
        if not chunk:
            return None if not buf else buf.decode("utf-8", "replace")
        if not buf and chunk in (b"\n", b"\x00"):
            continue  # tail of the previous CR LF / CR NUL
        buf += chunk
        if chunk in (b"\n", b"\r"):
            break
    text = strip_telnet(bytes(buf)).decode("utf-8", "replace")
    return text.strip("\r\n\x00 ")


class TelnetSensor:
    def __init__(self, bus: EventBus, port: int, limiter: ConnectionLimiter) -> None:
        self.bus = bus
        self.port = port
        self.limiter = limiter

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        ip, src_port = peer(writer)
        if not self.limiter.acquire(ip):
            writer.close()
            return
        try:
            self.bus.publish(Event("telnet", CONNECT, ip, src_port, self.port))
            # Ask the client to let us echo, like a real telnetd.
            writer.write(bytes([IAC, 251, 1, IAC, 251, 3]) + BANNER)
            for _ in range(MAX_TRIES):
                writer.write(b"\r\nlogin: ")
                await writer.drain()
                user = await read_line(reader)
                while user == "":  # skip blank lines and leftover CR/LF
                    user = await read_line(reader)
                if user is None:
                    return
                writer.write(b"Password: ")
                await writer.drain()
                password = await read_line(reader)
                if password is None:
                    return
                self.bus.publish(
                    Event("telnet", LOGIN_ATTEMPT, ip, src_port, self.port, username=user, password=password)
                )
                await asyncio.sleep(1.0)
                writer.write(b"\r\nLogin incorrect\r\n")
            await writer.drain()
        except (asyncio.TimeoutError, ConnectionError):
            pass
        finally:
            self.limiter.release(ip)
            writer.close()


async def start_telnet(bus: EventBus, host: str, port: int, limiter: ConnectionLimiter) -> asyncio.Server:
    sensor = TelnetSensor(bus, port, limiter)
    server = await asyncio.start_server(sensor.handle, host, port)
    log.info("telnet sensor listening on %s:%s", host, port)
    return server
