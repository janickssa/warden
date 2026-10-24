"""Sign-in, sign-out, passkey registration and passkey confirmations (README 17.3 Sign-in, Settings)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from warden.actors import HumanActor
from warden.api.auth import COOKIE, COOKIE_MAX_AGE, Ctx, Guard, Human, SessionDep, session
from warden.api.routes.settings import publish_trust_now
from warden.passkeys import PasskeyRefused, Purpose, actor_id

router = APIRouter(tags=["auth"])


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Options(BaseModel):
    challenge_id: str
    options: dict[str, Any]


class CredentialIn(_In):
    challenge_id: str = Field(max_length=64)
    credential: dict[str, Any]


class Me(BaseModel):
    name: str
    expires_at: str


class RegisterOptionsIn(_In):
    token: str | None = Field(default=None, max_length=100)
    name: str | None = Field(default=None, max_length=40)
    confirm: CredentialIn | None = None


class ConfirmOptionsIn(_In):
    purpose: Purpose
    subject: str = Field(default="", max_length=200)


def _options(cid: str, raw: str) -> Options:
    return Options(challenge_id=cid, options=json.loads(raw))


@router.post("/auth/options", dependencies=[Guard])
def login_options(c: Ctx) -> Options:
    return _options(*c.passkeys.assertion_options("login", "", now=c.now()))


@router.post("/auth/login", dependencies=[Guard])
def login(body: CredentialIn, request: Request, response: Response, c: Ctx) -> Me:
    token, row = c.passkeys.login(
        body.challenge_id,
        body.credential,
        ip=request.client.host if request.client else "?",
        user_agent=request.headers.get("user-agent", ""),
        now=c.now(),
    )
    response.set_cookie(
        COOKIE, token, max_age=COOKIE_MAX_AGE, httponly=True, secure=True, samesite="strict", path="/"
    )
    return Me(name=row.name, expires_at=row.expires_at)


@router.get("/auth/me")
def me(row: SessionDep) -> Me:
    return Me(name=row.name, expires_at=row.expires_at)


@router.post("/auth/logout")
def logout(row: SessionDep, actor: Human, response: Response, c: Ctx) -> dict[str, bool]:
    c.passkeys.revoke_session(row.token_hash, actor=actor, now=c.now())
    response.delete_cookie(COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return {"ok": True}


@router.post("/passkeys/register/options", dependencies=[Guard])
def register_options(body: RegisterOptionsIn, request: Request, c: Ctx) -> Options:
    """With the one-time link from `warden passkey add`, or signed in and confirmed with a passkey."""
    if body.token:
        return _options(*c.passkeys.registration_options(now=c.now(), token=body.token))
    session(request, c)  # signed in
    if body.confirm is None or not body.name:
        raise PasskeyRefused("adding a passkey needs a name and a confirmation with an existing passkey")
    c.passkeys.verify(
        body.confirm.challenge_id, body.confirm.credential, "add_passkey", body.name, now=c.now()
    )
    return _options(*c.passkeys.registration_options(now=c.now(), name=body.name))


@router.post("/passkeys/register", dependencies=[Guard])
async def register(body: CredentialIn, c: Ctx) -> dict[str, str]:
    """Registers the passkey for sign-in at once. Agents learn it as an approver through a publish that
    adds an approver, which loosens and so waits for the offline key (README 17.3 Settings)."""
    row = c.passkeys.register(body.challenge_id, body.credential, now=c.now())
    r = await publish_trust_now(c, HumanActor("dashboard", actor_id(row.name)))
    out = {"credential_id": row.credential_id, "name": row.name}
    if r is not None:
        out["approvers"] = f"{r.outcome} v{r.version}"
    return out


@router.post("/confirm/options")
def confirm_options(body: ConfirmOptionsIn, _: Human, c: Ctx) -> Options:
    """A passkey confirmation bound to one purpose and subject (adding a passkey, settings, lockdown …).
    Approvals and publishes have their own options endpoints, whose challenge is the signed message."""
    if body.purpose in ("login", "approve", "publish"):
        raise PasskeyRefused("use the dedicated endpoint for this")
    return _options(*c.passkeys.assertion_options(body.purpose, body.subject, now=c.now()))
