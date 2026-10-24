"""`warden mcp stdio`: a stdio ↔ Streamable HTTP bridge for MCP clients that only speak stdio.

It runs on the client's machine and forwards every message, unchanged, to Warden's `/mcp` with the client's
bearer token. It holds no Warden state and no keys; the server checks everything as for any HTTP client.
"""

from __future__ import annotations

from typing import Any

import anyio
import httpx2
from mcp.client.streamable_http import streamable_http_client
from mcp.server.stdio import stdio_server


async def _pump(src: Any, dst: Any) -> None:
    async with src, dst:
        async for msg in src:
            if isinstance(msg, Exception):
                continue  # a malformed frame on one side is dropped, never forwarded as something else
            await dst.send(msg)


async def run_bridge(url: str, token: str) -> None:
    if (
        not url.startswith("https://")
        and not url.startswith("http://127.0.0.1")
        and not url.startswith("http://localhost")
    ):
        raise SystemExit("refusing to send the token over plain http to a remote host; use https://")
    headers = {"Authorization": f"Bearer {token}"}
    async with (
        httpx2.AsyncClient(headers=headers, timeout=httpx2.Timeout(30, read=600)) as http,
        streamable_http_client(url, http_client=http) as streams,
        stdio_server() as (local_read, local_write),
        anyio.create_task_group() as tg,
    ):
        tg.start_soon(_pump, local_read, streams[1])
        tg.start_soon(_pump, streams[0], local_write)
