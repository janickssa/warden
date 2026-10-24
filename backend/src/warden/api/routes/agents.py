"""Agents (README 17.3 Agents): status, add (one-time token), confirm by fingerprint, revoke."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter

from warden.agents import TOKEN_TTL
from warden.api import schemas as sc
from warden.api import views
from warden.api.auth import Ctx, Human
from warden.errors import WardenError

router = APIRouter(tags=["agents"])
STATE = "/var/lib/warden-agent"


@router.get("/agents")
def list_agents(c: Ctx, _: Human) -> sc.AgentList:
    facts = views.Facts(c)
    names = [t.name for t in facts.cfg.targets.targets]
    extra = sorted({a.name for a in c.registry.list()} - set(names))
    rows = [facts.agent_view(n) for n in names + extra]
    rows.sort(key=lambda a: (a.status == "revoked", a.name))
    return sc.AgentList(agents=rows, latest_version=max(facts.latest.values(), default=0))


@router.post("/agents")
def add_agent(body: sc.AddAgentIn, c: Ctx, human: Human) -> sc.AgentToken:
    token = c.registry.create_token(body.name, human)
    s = c.config().settings.agents
    server = f"wss://{s.server_names[0]}:{s.listen_port}"
    return sc.AgentToken(
        name=body.name,
        token=token,
        command=f"sudo -u warden warden-agent enroll --state {STATE} --server {server} --token {token}",
        expires_at=(c.now() + TOKEN_TTL).isoformat(),
    )


@router.get("/agents/{name}/enrollment")
def enrollment(name: str, c: Ctx, _: Human) -> sc.EnrollmentView:
    row = c.registry.enrollment_for(name)
    if row is None:
        raise WardenError(f"no enrollment for {name}", code="not_found")
    status = row.status
    if status in ("open", "submitted") and datetime.fromisoformat(row.expires_at) <= c.now():
        status = "expired"
    return sc.EnrollmentView(
        name=name,
        status=status,
        fingerprint=row.fingerprint,
        source_ip=row.source_ip,
        agent_version=row.agent_version,
        expires_at=row.expires_at,
    )


@router.post("/agents/{name}/confirm")
def confirm(name: str, body: sc.ConfirmAgentIn, c: Ctx, human: Human) -> sc.AgentView:
    c.registry.confirm(name, body.fingerprint, human)
    return views.Facts(c).agent_view(name)


@router.post("/agents/{name}/reject")
def reject(name: str, c: Ctx, human: Human) -> sc.Ok:
    n = c.registry.reject(name, human)
    return sc.Ok(message=f"{n} enrollment(s) withdrawn")


@router.post("/agents/{name}/revoke")
async def revoke(name: str, c: Ctx, human: Human) -> sc.AgentView:
    c.registry.revoke(name, human)
    await c.dispatcher.revoke(name)
    return views.Facts(c).agent_view(name)
