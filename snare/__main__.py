"""Command line entry point.

    python -m snare run        start the sensors, the live map, and the sinks
    python -m snare simulate   start only the live map, fed by fake traffic

Every flag can also be set with an environment variable (SNARE_*), which
is how the systemd unit on the VM configures it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import signal
from pathlib import Path

from .dashboard import Dashboard, start_dashboard
from .events import Event, EventBus
from .geo import GeoEnricher, make_backend
from .sensors import start_http, start_ssh, start_telnet
from .sensors.common import ConnectionLimiter
from .simulate import simulate
from .sinks import BatchingSink, JsonlSink, azure_uploader
from .stats import Stats

log = logging.getLogger("snare")


def env(name: str, default=None):
    return os.environ.get(f"SNARE_{name}", default)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="snare", description="Cloud honeypot with a live threat map.")
    p.add_argument("mode", choices=["run", "simulate"])
    p.add_argument("--bind", default=env("BIND", "0.0.0.0"), help="address the sensors listen on")
    p.add_argument("--ssh-port", type=int, default=int(env("SSH_PORT", 2222)))
    p.add_argument("--telnet-port", type=int, default=int(env("TELNET_PORT", 2323)))
    p.add_argument("--http-port", type=int, default=int(env("HTTP_PORT", 8000)))
    p.add_argument("--map-bind", default=env("MAP_BIND", "127.0.0.1"))
    p.add_argument("--map-port", type=int, default=int(env("MAP_PORT", 8080)))
    p.add_argument("--map-token", default=env("MAP_TOKEN"), help="require ?token=... to view the map")
    p.add_argument("--home-lat", type=float, default=float(env("HOME_LAT", 43.65)))
    p.add_argument("--home-lon", type=float, default=float(env("HOME_LON", -79.38)))
    p.add_argument("--name", default=env("NAME", "canadacentral"), help="label shown on the map")
    p.add_argument("--data-dir", default=env("DATA_DIR", "./data"))
    p.add_argument("--geoip-city", default=env("GEOIP_CITY"), help="path to GeoLite2-City.mmdb")
    p.add_argument("--geoip-asn", default=env("GEOIP_ASN"), help="path to GeoLite2-ASN.mmdb")
    p.add_argument("--no-online-geo", action="store_true", default=env("NO_ONLINE_GEO") == "1")
    p.add_argument("--dce-endpoint", default=env("DCE_ENDPOINT"), help="Azure data collection endpoint URL")
    p.add_argument("--dcr-id", default=env("DCR_ID"), help="immutable id of the data collection rule")
    p.add_argument("--stream", default=env("STREAM", "Custom-HoneypotEvents_CL"))
    p.add_argument("--rate", type=float, default=2.0, help="simulate: events per second")
    p.add_argument("--log-level", default=env("LOG_LEVEL", "INFO"))
    return p.parse_args(argv)


def load_history(stats: Stats, data_dir: Path, limit: int = 20_000) -> int:
    """Warm the map from recent JSONL files so a restart does not wipe the panel."""
    files = sorted(data_dir.glob("events-*.jsonl"))[-2:]
    lines: list[str] = []
    for f in files:
        lines.extend(f.read_text(encoding="utf-8", errors="replace").splitlines())
    loaded = 0
    for line in lines[-limit:]:
        try:
            stats.add(Event(**json.loads(line)))
            loaded += 1
        except (ValueError, TypeError):
            continue
    return loaded


async def main(args: argparse.Namespace) -> None:
    bus = EventBus()
    stats = Stats()
    dash = Dashboard(stats, (args.home_lat, args.home_lon), args.name, args.map_token)
    tasks: list[asyncio.Task] = []
    closers = []

    if args.mode == "run":
        data_dir = Path(args.data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        log.info("loaded %d past events", load_history(stats, data_dir))

        backend = make_backend(args.geoip_city, args.geoip_asn, not args.no_online_geo)
        bus.add_enricher(GeoEnricher(backend))

        jsonl = JsonlSink(data_dir)
        bus.subscribe(jsonl)
        closers.append(jsonl.close)

        if args.dce_endpoint and args.dcr_id:
            upload, close = azure_uploader(args.dce_endpoint, args.dcr_id, args.stream)
            azure = BatchingSink(upload)
            bus.subscribe(azure)
            tasks.append(asyncio.create_task(azure.run()))
            closers.append(close)
            log.info("shipping events to Azure Log Analytics")
        else:
            log.info("no DCE/DCR set, events stay on disk only")

        limiter = ConnectionLimiter()
        servers = [
            await start_ssh(bus, args.bind, args.ssh_port, data_dir / "ssh_host_key", limiter),
            await start_telnet(bus, args.bind, args.telnet_port, limiter),
        ]
        http_runner = await start_http(bus, args.bind, args.http_port)
    else:
        servers, http_runner = [], None
        tasks.append(asyncio.create_task(simulate(bus, rate=args.rate)))

    bus.subscribe(dash.on_event)
    map_runner = await start_dashboard(dash, args.map_bind, args.map_port)
    tasks += [asyncio.create_task(bus.run()), asyncio.create_task(dash.stats_pusher())]

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()

    log.info("shutting down")
    for s in servers:
        s.close()
    if http_runner:
        await http_runner.cleanup()
    await map_runner.cleanup()
    for t in tasks:
        t.cancel()
    for close in closers:
        result = close()
        if asyncio.iscoroutine(result):
            await result


def cli() -> None:
    args = parse_args()
    logging.basicConfig(level=args.log_level.upper(), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    asyncio.run(main(args))


if __name__ == "__main__":
    cli()
