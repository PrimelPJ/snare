"""Fake SSH server.

Speaks real SSH (via asyncssh) so scanners and brute force bots behave
normally, records every username and password they try, and never lets
anyone in. There is no shell behind it.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import asyncssh

from ..events import CONNECT, LOGIN_ATTEMPT, Event, EventBus
from .common import ConnectionLimiter

log = logging.getLogger(__name__)

# Looks like a stock Ubuntu 22.04 box.
SERVER_VERSION = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
MAX_AUTH_ATTEMPTS = 6
LOGIN_TIMEOUT = 30
AUTH_FAILURE_DELAY = 0.5


def load_host_key(path: Path) -> asyncssh.SSHKey:
    """Reuse one host key across restarts so the fingerprint stays stable."""
    if path.exists():
        return asyncssh.read_private_key(str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key.write_private_key(str(path))
    path.chmod(0o600)
    return key


class _Server(asyncssh.SSHServer):
    def __init__(self, bus: EventBus, port: int, limiter: ConnectionLimiter) -> None:
        self.bus = bus
        self.port = port
        self.limiter = limiter
        self.conn: asyncssh.SSHServerConnection | None = None
        self.ip = "0.0.0.0"
        self.src_port = 0
        self.accepted = False
        self.attempts = 0

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        ip, port = conn.get_extra_info("peername")[:2]
        self.ip, self.src_port = str(ip), int(port)
        if not self.limiter.acquire(self.ip):
            conn.close()
            return
        self.accepted = True
        self.bus.publish(Event("ssh", CONNECT, self.ip, self.src_port, self.port))

    def connection_lost(self, exc: Exception | None) -> None:
        if self.accepted:
            self.limiter.release(self.ip)

    def begin_auth(self, username: str) -> bool:
        return True  # always require auth

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return False

    def kbdint_auth_supported(self) -> bool:
        return False

    async def validate_password(self, username: str, password: str) -> bool:
        client = None
        if self.conn is not None:
            client = self.conn.get_extra_info("client_version")
        self.bus.publish(
            Event(
                "ssh",
                LOGIN_ATTEMPT,
                self.ip,
                self.src_port,
                self.port,
                username=username,
                password=password,
                client=client,
            )
        )
        self.attempts += 1
        await asyncio.sleep(AUTH_FAILURE_DELAY)  # real sshd pauses on failure
        if self.attempts >= MAX_AUTH_ATTEMPTS and self.conn is not None:
            self.conn.close()  # same limit as OpenSSH's MaxAuthTries
        return False


async def start_ssh(
    bus: EventBus,
    host: str,
    port: int,
    key_path: Path,
    limiter: ConnectionLimiter,
) -> asyncssh.SSHAcceptor:
    key = load_host_key(key_path)
    acceptor = await asyncssh.create_server(
        lambda: _Server(bus, port, limiter),
        host,
        port,
        server_host_keys=[key],
        server_version=SERVER_VERSION,
        login_timeout=LOGIN_TIMEOUT,
        allow_scp=False,
        keepalive_interval=0,
    )
    log.info("ssh sensor listening on %s:%s", host, port)
    return acceptor
