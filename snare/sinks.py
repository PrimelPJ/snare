"""Where events go after enrichment.

JsonlSink   writes one JSON line per event to a daily file on disk.
AzureSink   batches events and sends them to a Log Analytics custom table
            through the Azure Monitor Logs Ingestion API.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from .events import Event

log = logging.getLogger(__name__)


class JsonlSink:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.directory.mkdir(parents=True, exist_ok=True)
        self._day: str | None = None
        self._fh = None

    def _file(self):
        day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        if day != self._day:
            if self._fh:
                self._fh.close()
            self._fh = open(self.directory / f"events-{day}.jsonl", "a", encoding="utf-8")
            self._day = day
        return self._fh

    async def __call__(self, event: Event) -> None:
        fh = self._file()
        fh.write(json.dumps(event.to_dict(), separators=(",", ":")) + "\n")
        fh.flush()

    def close(self) -> None:
        if self._fh:
            self._fh.close()


Uploader = Callable[[list[dict[str, Any]]], Awaitable[None]]


class BatchingSink:
    """Collect events and hand them to an uploader in batches, with retry.

    Kept separate from the Azure client so it can be tested without a
    cloud account.
    """

    def __init__(
        self,
        upload: Uploader,
        batch_size: int = 500,
        flush_seconds: float = 10.0,
        max_buffer: int = 50_000,
        max_backoff: float = 300.0,
    ) -> None:
        self.upload = upload
        self.batch_size = batch_size
        self.flush_seconds = flush_seconds
        self.max_backoff = max_backoff
        self.buffer: deque[dict[str, Any]] = deque(maxlen=max_buffer)
        self.sent = 0
        self.failures = 0
        self._wake = asyncio.Event()

    async def __call__(self, event: Event) -> None:
        self.buffer.append(event.to_azure())
        if len(self.buffer) >= self.batch_size:
            self._wake.set()

    async def flush_once(self) -> bool:
        """Send up to one batch. Returns False if the upload failed."""
        if not self.buffer:
            return True
        batch = [self.buffer.popleft() for _ in range(min(self.batch_size, len(self.buffer)))]
        try:
            await self.upload(batch)
        except Exception as exc:
            self.failures += 1
            log.warning("upload of %d events failed: %s", len(batch), exc)
            self.buffer.extendleft(reversed(batch))  # put them back in order
            return False
        self.sent += len(batch)
        return True

    async def run(self) -> None:
        backoff = 1.0
        while True:
            try:
                await asyncio.wait_for(self._wake.wait(), self.flush_seconds)
            except asyncio.TimeoutError:
                pass
            self._wake.clear()
            while self.buffer:
                if await self.flush_once():
                    backoff = 1.0
                else:
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, self.max_backoff)
                    break


def azure_uploader(endpoint: str, rule_id: str, stream: str) -> tuple[Uploader, Callable[[], Awaitable[None]]]:
    """Build an uploader that uses the VM's managed identity (or az login locally)."""
    from azure.identity.aio import DefaultAzureCredential
    from azure.monitor.ingestion.aio import LogsIngestionClient

    credential = DefaultAzureCredential()
    client = LogsIngestionClient(endpoint=endpoint, credential=credential)

    async def upload(batch: list[dict[str, Any]]) -> None:
        await client.upload(rule_id=rule_id, stream_name=stream, logs=batch)

    async def close() -> None:
        await client.close()
        await credential.close()

    return upload, close
