"""The dashboard API app and the single ASGI entry point `warden serve` runs (README 14: NPM routes `/api`,
`/ws` and `/mcp` to one port).

Credentials never cross: `/mcp` takes only MCP bearer tokens (`RequireClientToken`), `/api` and `/ws` take
only the human session cookie and refuse any Authorization header.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from warden.api import routes
from warden.api.auth import ws_session
from warden.api.context import ApiContext
from warden.api.events import EventBus, Subscriber
from warden.errors import WardenError

Scope = MutableMapping[str, Any]
ASGI = Callable[[Scope, Any, Any], Awaitable[None]]

STATUS = {
    "not_found": 404,
    "decided_elsewhere": 409,
    "not_human": 403,
    "passkey_required": 403,
    "unknown_passkey": 403,
    "signed_out": 401,
}


def create_api(ctx: ApiContext, bus: EventBus) -> FastAPI:
    app = FastAPI(
        title="Warden dashboard API",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.ctx = ctx
    app.state.bus = bus

    @app.exception_handler(WardenError)
    async def _warden_error(_: Request, exc: WardenError) -> JSONResponse:
        return JSONResponse(
            {"detail": {"code": exc.code, "message": exc.message}}, status_code=STATUS.get(exc.code, 400)
        )

    for router in routes.ROUTERS:
        app.include_router(router, prefix="/api")

    @app.websocket("/ws")
    async def events(ws: WebSocket) -> None:
        if ws_session(ws) is None:
            await ws.close(4401, "sign in")
            return
        await ws.accept()
        sub = Subscriber()
        bus.subscribers.add(sub)

        async def reader() -> None:
            while True:
                msg = json.loads(await ws.receive_text())
                if isinstance(msg, dict) and isinstance(msg.get("watch"), str) and len(sub.plans) < 20:
                    sub.plans.add(msg["watch"][:40])
                if isinstance(msg, dict) and isinstance(msg.get("unwatch"), str):
                    sub.plans.discard(msg["unwatch"])

        task = asyncio.get_running_loop().create_task(reader())
        try:
            await ws.send_json({"type": "hello"})
            while not task.done():
                try:
                    event = await asyncio.wait_for(sub.queue.get(), 15)
                except TimeoutError:
                    event = {"type": "ping"}
                if ws_session(ws) is None:  # session revoked or expired while connected
                    await ws.close(4401, "session ended")
                    break
                await ws.send_json(event)
        except (WebSocketDisconnect, RuntimeError):
            pass
        finally:
            bus.subscribers.discard(sub)
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    return app


class Root:
    """Routes by path prefix. Lifespan events go to the MCP app (its session manager needs them)."""

    def __init__(self, api: ASGI, mcp: ASGI) -> None:
        self.api = api
        self.mcp = mcp

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] == "lifespan":
            await self.mcp(scope, receive, send)
            return
        path = scope.get("path", "")
        if path == "/mcp" or path.startswith("/mcp/"):
            await self.mcp(scope, receive, send)
        elif path.startswith("/api/") or path == "/ws":
            await self.api(scope, receive, send)
        elif path == "/healthz" and scope["type"] == "http":
            await send(
                {"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]}
            )
            await send({"type": "http.response.body", "body": b"ok"})
        elif scope["type"] == "http":
            await send({"type": "http.response.start", "status": 404, "headers": []})
            await send({"type": "http.response.body", "body": b""})
