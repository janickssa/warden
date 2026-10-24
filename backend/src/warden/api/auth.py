"""Session cookie and request checks for `/api` and `/ws` (README 10.2, PLAN M6).

- The session is an httpOnly, Secure, SameSite=Strict cookie. MCP bearer tokens are never accepted here.
- Every state-changing request needs `Origin` equal to `server.public_url`'s origin and the header
  `X-Warden: 1` (a header a cross-site form can't send), so a stray link or form can't act for the human.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, WebSocket

from warden.actors import HumanActor
from warden.api.context import ApiContext
from warden.passkeys import SESSION_TTL, WebSessionRow, human

COOKIE = "warden_session"
SAFE = {"GET", "HEAD", "OPTIONS"}


def ctx(request: Request) -> ApiContext:
    c: ApiContext = request.app.state.ctx
    return c


def check_origin(c: ApiContext, origin: str | None, csrf: str | None) -> None:
    if origin != c.passkeys.rp.origin or csrf != "1":
        raise HTTPException(
            403, detail={"code": "bad_origin", "message": "request refused (origin or header)"}
        )


def guard(request: Request, c: Annotated[ApiContext, Depends(ctx)]) -> None:
    """For unauthenticated but state-changing endpoints (sign-in, passkey registration)."""
    if request.method not in SAFE:
        check_origin(c, request.headers.get("origin"), request.headers.get("x-warden"))


def session(request: Request, c: Annotated[ApiContext, Depends(ctx)]) -> WebSessionRow:
    if request.headers.get("authorization"):
        raise HTTPException(
            401, detail={"code": "wrong_credential", "message": "the dashboard API takes no tokens"}
        )
    row = c.passkeys.session(request.cookies.get(COOKIE), now=c.now())
    if row is None:
        raise HTTPException(401, detail={"code": "signed_out", "message": "sign in with your passkey"})
    if request.method not in SAFE:
        check_origin(c, request.headers.get("origin"), request.headers.get("x-warden"))
    return row


def human_of(row: Annotated[WebSessionRow, Depends(session)]) -> HumanActor:
    return human(row)


def ws_session(ws: WebSocket) -> WebSessionRow | None:
    c: ApiContext = ws.app.state.ctx
    if ws.headers.get("origin") != c.passkeys.rp.origin:
        return None
    return c.passkeys.session(ws.cookies.get(COOKIE), now=c.now())


COOKIE_MAX_AGE = int(SESSION_TTL.total_seconds())

Ctx = Annotated[ApiContext, Depends(ctx)]
SessionDep = Annotated[WebSessionRow, Depends(session)]
Human = Annotated[HumanActor, Depends(human_of)]
Guard = Depends(guard)
