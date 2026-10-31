#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hosted disposable TCP-only relay to the isolated REALITY fixture."""
import asyncio
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

if os.environ.get("GITHUB_ACTIONS") != "true" or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
    raise SystemExit("hosted CI only")
if len(sys.argv) != 3:
    raise SystemExit("fixture arguments required")
fixture = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
ports = []
for field in ("uri", "xhttpURI"):
    parsed = urlsplit(fixture[field])
    if parsed.scheme != "vless" or parsed.hostname != "10.0.2.2" or parsed.port is None or not 1024 <= parsed.port <= 65535:
        raise SystemExit("invalid synthetic relay target")
    ports.append(parsed.port)
if len(set(ports)) != 2:
    raise SystemExit("synthetic ports must differ")

async def transfer(reader, writer):
    try:
        while True:
            data = await asyncio.wait_for(reader.read(16384), timeout=120)
            if not data:
                if writer.can_write_eof():
                    writer.write_eof()
                    await writer.drain()
                return
            writer.write(data)
            await writer.drain()
    except (OSError, ConnectionError, asyncio.TimeoutError):
        return

async def main():
    limit = asyncio.Semaphore(128)
    async def forward(reader, writer, port):
        async with limit:
            other = None
            try:
                remote, other = await asyncio.wait_for(asyncio.open_connection("10.254.197.2", port), timeout=5)
                await asyncio.gather(transfer(reader, other), transfer(remote, writer))
            except (OSError, ConnectionError, asyncio.TimeoutError):
                pass
            finally:
                if other is not None:
                    other.close()
                writer.close()
    servers = []
    for port in ports:
        async def handle(reader, writer, bound=port):
            await forward(reader, writer, bound)
        servers.append(await asyncio.start_server(handle, host="127.0.0.1", port=port, limit=65536))
    Path(sys.argv[2]).write_text("ready\n", encoding="ascii")
    try:
        await asyncio.gather(*(server.serve_forever() for server in servers))
    finally:
        for server in servers:
            server.close()
            await server.wait_closed()

asyncio.run(main())
