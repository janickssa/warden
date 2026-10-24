"""Dashboard sign-in: passkeys, sessions, CSRF and credential separation (README 10.2, 17.3)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from apihelp import ALICE_CLI, ORIGIN, Api, H, make_api
from softauth import UV, SoftAuthenticator
from sqlalchemy import Engine
from sqlmodel import Session
from svc import World

from warden import audit
from warden.passkeys import PasskeyRefused
from warden.signing import ApprovalKey


@pytest.fixture
def api(engine: Engine, tmp_path: Path) -> Api:
    return make_api(World(engine=engine, key=ApprovalKey.generate(tmp_path / "k")), tmp_path)


def actions(api: Api) -> list[str]:
    with Session(api.world.engine) as s:
        return [e.action for e in audit.entries(s)]


def test_register_login_logout(api: Api) -> None:
    assert api.get("/api/auth/me").status_code == 401
    api.register()
    r = api.login()
    assert r.status_code == 200, r.text
    assert r.json()["name"] == "MacBook"
    cookie = r.headers["set-cookie"].lower()
    for part in ("httponly", "secure", "samesite=strict", "max-age=43200"):
        assert part in cookie
    assert api.get("/api/auth/me").json()["name"] == "MacBook"
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/auth/me").status_code == 401
    assert actions(api) == [
        "passkey_enrollment_created",
        "passkey_registered",
        "signed_in",
        "session_revoked",
    ]


def test_registration_link_is_single_use_and_expires(api: Api) -> None:
    token = api.ctx.passkeys.create_enrollment("MacBook", actor=ALICE_CLI, now=api.ctx.now())
    o = api.post("/api/passkeys/register/options", {"token": token}).json()
    assert (
        api.post(
            "/api/passkeys/register",
            {"challenge_id": o["challenge_id"], "credential": api.auth.create(o["options"])},
        ).status_code
        == 200
    )
    assert api.post("/api/passkeys/register/options", {"token": token}).status_code == 400
    token2 = api.ctx.passkeys.create_enrollment("Backup", actor=ALICE_CLI, now=api.ctx.now())
    api.world.clock.advance(minutes=16)
    assert api.post("/api/passkeys/register/options", {"token": token2}).status_code == 400


def test_unknown_passkey_refused(api: Api) -> None:
    api.register()
    stranger = SoftAuthenticator(ORIGIN, "localhost")
    r = api.login(stranger)
    assert r.status_code == 403
    assert "isn't registered" in r.json()["detail"]["message"]


@pytest.mark.parametrize("variant", ["wrong_origin", "wrong_rp", "no_uv", "replayed", "wrong_purpose"])
def test_bad_assertions_refused(api: Api, variant: str) -> None:
    api.register()
    o = api.post("/api/auth/options").json()
    if variant == "wrong_origin":
        cred = api.auth.get(o["options"], origin="https://evil.example.com")
    elif variant == "wrong_rp":
        cred = api.auth.get(o["options"], rp_id="evil.example.com")
    elif variant == "no_uv":
        api.auth.flags &= ~UV
        cred = api.auth.get(o["options"])
    elif variant == "replayed":
        cred = api.auth.get(o["options"])
        assert (
            api.post("/api/auth/login", {"challenge_id": o["challenge_id"], "credential": cred}).status_code
            == 200
        )
        api.client.cookies.clear()
    else:
        api.post("/api/auth/login", json=None)  # nothing
        cred = api.auth.get(o["options"])
        api.login()  # consumes nothing of `o`
        o2 = api.post("/api/confirm/options", {"purpose": "settings", "subject": "x"}).json()
        r = api.post(
            "/api/auth/login", {"challenge_id": o2["challenge_id"], "credential": api.auth.get(o2["options"])}
        )
        assert r.status_code == 400
        return
    r = api.post("/api/auth/login", {"challenge_id": o["challenge_id"], "credential": cred})
    assert r.status_code in (400, 403)
    assert api.get("/api/auth/me").status_code == 401


def test_session_expires_after_12_hours(api: Api) -> None:
    api.register()
    api.login()
    api.world.clock.advance(hours=11, minutes=59)
    assert api.get("/api/auth/me").status_code == 200
    api.world.clock.advance(minutes=2)
    assert api.get("/api/auth/me").status_code == 401


def test_csrf_and_origin(api: Api) -> None:
    api.register()
    api.login()
    for headers in (
        {},
        {"origin": ORIGIN},
        {"x-warden": "1"},
        {"origin": "https://evil.example.com", "x-warden": "1"},
    ):
        r = api.client.post("/api/auth/logout", headers=headers)
        assert r.status_code == 403, headers
    assert (
        api.client.post(
            "/api/auth/options", headers={"origin": "https://evil.example.com", "x-warden": "1"}
        ).status_code
        == 403
    )
    assert api.post("/api/auth/logout").status_code == 200


def test_tokens_never_work_on_api(api: Api) -> None:
    api.register()
    api.login()
    r = api.get("/api/auth/me", headers={"Authorization": "Bearer wdn_mcp_anything"})
    assert r.status_code == 401


def test_challenge_expires(api: Api) -> None:
    api.register()
    o = api.post("/api/auth/options").json()
    api.world.clock.advance(minutes=3)
    r = api.post(
        "/api/auth/login", {"challenge_id": o["challenge_id"], "credential": api.auth.get(o["options"])}
    )
    assert r.status_code == 400
    assert r.json()["detail"]["code"] == "challenge_invalid"


def test_add_second_passkey_needs_confirmation(api: Api) -> None:
    api.register()
    api.login()
    r = api.post("/api/passkeys/register/options", {"name": "Backup"})
    assert r.status_code == 400
    o = api.post(
        "/api/passkeys/register/options", {"name": "Backup", "confirm": api.confirm("add_passkey", "Backup")}
    ).json()
    backup = SoftAuthenticator(ORIGIN, "localhost", alg=-8)
    r = api.post(
        "/api/passkeys/register",
        {"challenge_id": o["challenge_id"], "credential": backup.create(o["options"])},
    )
    assert r.status_code == 200, r.text
    api.client.cookies.clear()
    assert api.login(backup).status_code == 200


def test_ed25519_and_es256_only(api: Api) -> None:
    token = api.ctx.passkeys.create_enrollment("Key", actor=ALICE_CLI, now=api.ctx.now())
    o = api.post("/api/passkeys/register/options", {"token": token}).json()
    algs = [p["alg"] for p in o["options"]["pubKeyCredParams"]]
    assert sorted(algs) == [-8, -7]
    assert o["options"]["authenticatorSelection"]["userVerification"] == "required"


def test_removed_passkey_ends_its_sessions(api: Api) -> None:
    api.register()
    backup = api.register("Backup", SoftAuthenticator(ORIGIN, "localhost"))
    api.login()
    api.ctx.passkeys.remove(api.auth.id, actor=ALICE_CLI, now=api.ctx.now())
    assert api.get("/api/auth/me").status_code == 401
    with pytest.raises(PasskeyRefused):
        api.ctx.passkeys.remove(backup.id, actor=ALICE_CLI, now=api.ctx.now())


def test_clock_helper(api: Api) -> None:
    assert api.world.clock() + timedelta(0) == api.ctx.now()
    assert H["x-warden"] == "1"
