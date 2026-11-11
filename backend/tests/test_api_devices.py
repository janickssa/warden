"""The iPhone over the dashboard API (M8): pair with a link, register the Face ID device key, sign in,
register for push, approve with the device key, and lose it all when the passkey is removed."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from apihelp import ORIGIN, Api, H, make_api
from cryptography.hazmat.primitives.asymmetric import ec
from devicekey import DeviceKey
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from svc import World

from warden.signing import ApprovalKey


@pytest.fixture
def api(engine: Engine, tmp_path: Path) -> Api:
    a = make_api(World(engine=engine, key=ApprovalKey.generate(tmp_path / "k")), tmp_path)
    a.register()
    assert a.login().status_code == 200
    return a


def ok(r: Any) -> Any:
    assert r.status_code == 200, r.text
    return r.json()


def pair(api: Api, name: str = "iPhone") -> str:
    out = ok(api.post("/api/passkeys/pairing", {"name": name, "confirm": api.confirm("add_passkey", name)}))
    assert "/register?token=" in out["link"]
    return str(parse_qs(urlsplit(out["link"]).query)["token"][0])


def test_pair_sign_in_push_and_approve_from_the_iphone(api: Api) -> None:
    token = pair(api)
    phone = TestClient(api.client.app, base_url="https://testserver")
    dk = DeviceKey(ec.generate_private_key(ec.SECP256R1()), "localhost", ORIGIN)
    o = ok(phone.post("/api/passkeys/register/options", json={"token": token}, headers=H))
    reg = ok(
        phone.post(
            "/api/passkeys/register",
            json={"challenge_id": o["challenge_id"], "credential": dk.create(o["options"])},
            headers=H,
        )
    )
    assert reg["name"] == "iPhone"
    assert reg["credential_id"] == dk.id
    o = ok(phone.post("/api/auth/options", headers=H))
    ok(
        phone.post(
            "/api/auth/login",
            json={"challenge_id": o["challenge_id"], "credential": dk.get(o["options"])},
            headers=H,
        )
    )
    dev = ok(phone.post("/api/devices", json={"token": "a1" * 32, "name": "Janick's iPhone"}, headers=H))
    assert dev["passkey"] == dk.id
    assert [d["name"] for d in ok(api.get("/api/devices"))] == ["Janick's iPhone"]

    p = api.world.propose("npm ci")
    o = ok(phone.post(f"/api/plans/{p.id}/approval/options", headers=H))
    done = ok(
        phone.post(
            f"/api/plans/{p.id}/approve",
            json={"hash": p.hash, "challenge_id": o["challenge_id"], "credential": dk.get(o["options"])},
            headers=H,
        )
    )
    assert done["status"] == "approved"
    assert done["approval"]["passkey"] == dk.id
    assert done["approval"]["by"] == "dashboard:iPhone"  # the device key's name says it was the iPhone

    # Removing the device key (from the Mac) signs the phone out and drops its push token.
    ok(api.post(f"/api/passkeys/{dk.id}/remove", api.confirm("remove_passkey", dk.id)))
    assert ok(api.get("/api/devices")) == []
    assert phone.get("/api/status").status_code == 401


def test_pairing_needs_a_confirmation_for_that_name(api: Api) -> None:
    assert api.post("/api/passkeys/pairing", {"name": "iPhone"}).status_code == 422
    other = api.confirm("add_passkey", "Other")
    assert api.post("/api/passkeys/pairing", {"name": "iPhone", "confirm": other}).status_code >= 400
    assert (
        api.post("/api/passkeys/pairing", {"name": "iPhone", "confirm": api.confirm("lockdown")}).status_code
        >= 400
    )
    api.client.cookies.clear()
    assert (
        api.post(
            "/api/passkeys/pairing", {"name": "iPhone", "confirm": {"challenge_id": "x", "credential": {}}}
        ).status_code
        == 401
    )


def test_device_tokens_need_a_session(api: Api) -> None:
    stranger = TestClient(api.client.app, base_url="https://testserver")
    assert stranger.post("/api/devices", json={"token": "a1" * 32}, headers=H).status_code == 401
    assert api.post("/api/devices", {"token": "nothex"}).status_code == 400
    d = ok(api.post("/api/devices", {"token": "b2" * 32}))
    ok(api.post(f"/api/devices/{d['id']}/remove"))
    assert ok(api.get("/api/devices")) == []
