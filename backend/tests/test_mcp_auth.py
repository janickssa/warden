"""MCP client tokens and the HTTP auth gate (PLAN M4)."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from factories import T0
from sqlalchemy import Engine
from sqlmodel import Session, select

from warden import audit
from warden.actors import ClaudeActor, HumanActor
from warden.config import Settings
from warden.mcp import clients
from warden.mcp.http import RequireClientToken, allowed_hosts, bearer

ALICE = HumanActor("cli", "alice")


def test_add_authenticate_revoke(engine: Engine) -> None:
    token = clients.add(engine, "claude-code", actor=ALICE, now=T0)
    assert token.startswith("wdn_mcp_")
    assert clients.authenticate(engine, token) == "claude-code"
    assert clients.authenticate(engine, token + "x") is None
    assert clients.authenticate(engine, "wdn_mcp_guess") is None
    assert clients.authenticate(engine, "Bearer " + token) is None
    with Session(engine) as s:
        row = s.exec(select(clients.McpClientRow)).one()
        assert token not in row.token_hash  # only the hash is stored
    with pytest.raises(clients.ClientRefused):
        clients.add(engine, "claude-code", actor=ALICE, now=T0)
    clients.revoke(engine, "claude-code", actor=ALICE, now=T0)
    assert clients.authenticate(engine, token) is None
    new = clients.add(engine, "claude-code", actor=ALICE, now=T0)
    assert clients.authenticate(engine, new) == "claude-code"
    assert clients.authenticate(engine, token) is None
    with Session(engine) as s:
        assert [e.action for e in audit.entries(s)] == [
            "mcp_client_added",
            "mcp_client_revoked",
            "mcp_client_added",
        ]


@pytest.mark.parametrize("name", ["cli:alice", "Claude", "", "a" * 33, "dash board", "-x"])
def test_client_names_cant_look_like_humans(engine: Engine, name: str) -> None:
    with pytest.raises(clients.ClientRefused):
        clients.add(engine, name, actor=ALICE, now=T0)


def test_only_humans_manage_tokens(engine: Engine) -> None:
    with pytest.raises(clients.ClientRefused):
        clients.add(engine, "x", actor=ClaudeActor("claude-code"), now=T0)  # type: ignore[arg-type]


def test_bearer_parsing() -> None:
    assert bearer({"authorization": "Bearer abc"}) == "abc"
    assert bearer({"authorization": "Basic abc"}) is None
    assert bearer([(b"authorization", b"Bearer xyz")]) == "xyz"
    assert bearer(None) is None


def _call(app: Any, headers: list[tuple[bytes, bytes]], path: str = "/mcp") -> int:
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg: dict[str, Any]) -> None:
        sent.append(msg)

    asyncio.run(
        app({"type": "http", "path": path, "headers": headers, "client": ("10.0.0.9", 1)}, receive, send)
    )
    return int(sent[0]["status"])


def test_gate_refuses_before_mcp(engine: Engine) -> None:
    reached: list[str] = []

    async def inner(scope: Any, receive: Any, send: Any) -> None:
        reached.append(scope["path"])
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    token = clients.add(engine, "claude-code", actor=ALICE, now=T0)
    app = RequireClientToken(inner, engine)
    assert _call(app, []) == 401
    assert _call(app, [(b"authorization", b"Bearer wdn_mcp_wrong")]) == 401
    assert reached == []
    assert _call(app, [(b"authorization", f"Bearer {token}".encode())]) == 200
    assert _call(app, [], path="/healthz") == 200
    clients.revoke(engine, "claude-code", actor=ALICE, now=T0)
    assert _call(app, [(b"authorization", f"Bearer {token}".encode())]) == 401


def test_allowed_hosts() -> None:
    s = Settings.model_validate(
        {"server": {"public_url": "https://warden.example.dk"}, "http": {"listen_port": 8700}}
    )
    assert "warden.example.dk" in allowed_hosts(s)
    assert "127.0.0.1:8700" in allowed_hosts(s)
    assert "evil.example.com" not in allowed_hosts(s)
