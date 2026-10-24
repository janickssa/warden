"""MCP client tokens (PLAN M4): one bearer token per client, separate from every human login.

A human creates them with `warden mcp add <name>` on the warden guest. Only a SHA-256 hash is stored. The
client name becomes the `ClaudeActor` for everything that client does, so it can't contain `:` and can't
look like a human channel label (`cli:…`, `dashboard:…`).
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from datetime import datetime

from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, col, select

from warden import audit
from warden.actors import HumanActor
from warden.errors import WardenError

TOKEN_PREFIX = "wdn_mcp_"  # noqa: S105 - a prefix, not a secret
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")


class ClientRefused(WardenError):
    code = "mcp_client_refused"


class McpClientRow(SQLModel, table=True):
    __tablename__ = "mcp_clients"

    name: str = Field(primary_key=True)
    token_hash: str = Field(index=True)
    status: str  # active | revoked
    created_at: str
    created_by: str
    revoked_at: str | None = None


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def add(engine: Engine, name: str, *, actor: HumanActor, now: datetime) -> str:
    if not isinstance(actor, HumanActor):
        raise ClientRefused("only a human can create MCP client tokens")
    if not NAME.match(name):
        raise ClientRefused("client names are 1–32 lowercase letters, digits and dashes, e.g. claude-code")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    with Session(engine) as s, s.begin():
        row = s.get(McpClientRow, name)
        if row is not None and row.status == "active":
            raise ClientRefused(f"{name} already has an active token; revoke it first")
        if row is not None:
            s.delete(row)
            s.flush()
        s.add(
            McpClientRow(
                name=name,
                token_hash=_hash(token),
                status="active",
                created_at=now.isoformat(),
                created_by=actor.label,
            )
        )
        audit.append(s, ts=now, actor=actor.label, action="mcp_client_added", subject=name, detail={})
    return token


def revoke(engine: Engine, name: str, *, actor: HumanActor, now: datetime) -> None:
    if not isinstance(actor, HumanActor):
        raise ClientRefused("only a human can revoke MCP client tokens")
    with Session(engine) as s, s.begin():
        row = s.get(McpClientRow, name)
        if row is None or row.status != "active":
            raise ClientRefused(f"{name} has no active token")
        row.status, row.revoked_at = "revoked", now.isoformat()
        s.add(row)
        audit.append(s, ts=now, actor=actor.label, action="mcp_client_revoked", subject=name, detail={})


def list_clients(engine: Engine) -> list[McpClientRow]:
    with Session(engine) as s:
        return list(s.exec(select(McpClientRow).order_by(col(McpClientRow.name))))


def authenticate(engine: Engine, token: str) -> str | None:
    """The client name for a valid, active token; otherwise None."""
    if not token.startswith(TOKEN_PREFIX) or len(token) > 200:
        return None
    digest = _hash(token)
    with Session(engine) as s:
        row = s.exec(select(McpClientRow).where(col(McpClientRow.token_hash) == digest)).first()
    if row is None or row.status != "active" or not hmac.compare_digest(row.token_hash, digest):
        return None
    return row.name
