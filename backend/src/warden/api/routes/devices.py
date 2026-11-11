"""Paired iPhones (M8): APNs device tokens. Registering needs a signed-in session; the token is tied to the
passkey (or Face ID device key) of that session and goes away with it."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from warden import push
from warden.api import schemas as sc
from warden.api.auth import Ctx, Human, SessionDep

router = APIRouter(tags=["devices"])


class DeviceIn(sc.In):
    token: str
    name: str = "iPhone"


class DeviceView(BaseModel):
    id: str
    name: str
    created_at: str
    last_ok_at: str | None
    passkey: str


def _view(d: push.DeviceRow) -> DeviceView:
    return DeviceView(
        id=d.id, name=d.name, created_at=d.created_at, last_ok_at=d.last_ok_at, passkey=d.credential_id
    )


@router.post("/devices")
def register(body: DeviceIn, c: Ctx, me: SessionDep, human: Human) -> DeviceView:
    row = push.register(
        c.engine,
        credential_id=me.credential_id,
        name=body.name,
        token=body.token,
        now=c.now(),
        actor=human.label,
    )
    return _view(row)


@router.get("/devices")
def list_devices(c: Ctx, _: Human) -> list[DeviceView]:
    return [_view(d) for d in push.devices(c.engine)]


@router.post("/devices/{device_id}/remove")
def remove(device_id: str, c: Ctx, human: Human) -> sc.Ok:
    push.remove(c.engine, device_id, now=c.now(), actor=human.label)
    return sc.Ok(message="device removed")
