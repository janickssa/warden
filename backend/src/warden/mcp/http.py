"""The MCP endpoint over Streamable HTTP, served by `warden serve` (README 3, 14).

Requests to `/mcp` need `Authorization: Bearer wdn_mcp_…` for an active client (`warden mcp add`). Anything
else gets 401 before the MCP layer runs. The SDK's DNS-rebinding protection only accepts the Host of
`server.public_url` (what NPM forwards) and the listen address itself.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any
from urllib.parse import urlsplit

from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from sqlalchemy import Engine
from starlette.applications import Starlette

from warden.config import Settings
from warden.mcp import clients

log = logging.getLogger("warden.mcp")

Scope = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[MutableMapping[str, Any]]]
Send = Callable[[MutableMapping[str, Any]], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]
MAX_BODY = 1024 * 1024


def bearer(headers: Any) -> str | None:
    """The token from an Authorization header mapping (Starlette headers or an ASGI header list)."""
    value: str | None = None
    if isinstance(headers, list):
        for k, v in headers:
            if k.lower() == b"authorization":
                value = v.decode("latin-1")
    elif headers is not None:
        value = headers.get("authorization")
    if not value or not value.startswith("Bearer "):
        return None
    return value[len("Bearer ") :].strip()


def identify_from_headers(engine: Engine) -> Callable[[Context], str | None]:
    def identify(ctx: Context) -> str | None:
        token = bearer(ctx.headers)
        return None if token is None else clients.authenticate(engine, token)

    return identify


class RequireClientToken:
    """ASGI middleware: refuse any HTTP request without a valid client token."""

    def __init__(self, app: ASGIApp, engine: Engine) -> None:
        self.app = app
        self.engine = engine

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        token = bearer(scope.get("headers", []))
        if token is None or clients.authenticate(self.engine, token) is None:
            client = scope.get("client")
            log.warning("MCP request refused from %s: missing or invalid token", client[0] if client else "?")
            body = json.dumps(
                {"error": "unauthorized", "message": "a valid Warden MCP client token is required"}
            )
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"application/json"), (b"www-authenticate", b"Bearer")],
                }
            )
            await send({"type": "http.response.body", "body": body.encode()})
            return
        await self.app(scope, receive, send)


def allowed_hosts(settings: Settings) -> list[str]:
    public = urlsplit(settings.server.public_url).netloc
    listen = f"{settings.mcp.listen_host}:{settings.mcp.listen_port}"
    hosts = {public, listen, f"127.0.0.1:{settings.mcp.listen_port}", f"localhost:{settings.mcp.listen_port}"}
    return sorted(h for h in hosts if h)


def build_app(server: MCPServer, engine: Engine, settings: Settings) -> ASGIApp:
    starlette: Starlette = server.streamable_http_app(
        streamable_http_path="/mcp",
        max_request_body_size=MAX_BODY,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True, allowed_hosts=allowed_hosts(settings), allowed_origins=[]
        ),
        host=settings.mcp.listen_host,
    )
    return RequireClientToken(starlette, engine)
