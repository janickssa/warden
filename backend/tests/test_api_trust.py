"""End-to-end signing from the dashboard (README 10.0, D-11/D-12): approver list and e2e flag in bundles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from apihelp import ALICE_CLI, ORIGIN, Api, make_api
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from softauth import SoftAuthenticator
from sqlalchemy import Engine
from sqlmodel import Session
from svc import World

from warden.errors import ApprovalRefused
from warden.keys import b64url, key_id_for, raw_public
from warden.policy_dist import bundle as bundles
from warden.policy_dist import offline_keys
from warden.policy_dist import publish as publishing
from warden.signing import ApprovalKey


@pytest.fixture
def api(engine: Engine, tmp_path: Path) -> Api:
    a = make_api(World(engine=engine, key=ApprovalKey.generate(tmp_path / "k")), tmp_path)
    a.register()
    assert a.login().status_code == 200
    publishing.publish(
        engine,
        policy=a.world.policy,
        targets=a.world.config().targets,
        online=a.ctx.online,
        approval=a.ctx.approval,
        now=a.ctx.now(),
        actor="cli:alice",
    )
    key = Ed25519PrivateKey.generate()
    with Session(engine) as s, s.begin():
        offline_keys.register(
            s, b64url(raw_public(key.public_key())), role="primary", actor=ALICE_CLI, now=a.ctx.now()
        )
    a.offline = key  # type: ignore[attr-defined]
    return a


def ok(r: Any) -> Any:
    assert r.status_code == 200, r.text
    return r.json()


def sign_pending(api: Api) -> Any:
    key = api.offline  # type: ignore[attr-defined]
    pf = json.loads(api.get("/api/policy/pending/file").text)
    sig = {
        "v": 1,
        "version": pf["version"],
        "key_id": key_id_for(key.public_key()),
        "signatures": [
            {
                "target": it["target"],
                "sig": "ed25519:" + b64url(key.sign(bundles.signing_message(it["bundle"]))),
            }
            for it in pf["items"]
        ],
    }
    return ok(api.post("/api/policy/pending/signature", {"content": json.dumps(sig)}))


def latest_trust(api: Api) -> dict[str, Any]:
    with Session(api.world.engine) as s:
        t = bundles.latest_trust(s)
    assert t is not None
    return t


def toggle_e2e(api: Api, enabled: bool) -> Any:
    return api.post("/api/e2e", {"enabled": enabled, **api.confirm("settings", "e2e")})


def test_turning_e2e_on_ships_approvers_and_needs_offline_key_once(api: Api) -> None:
    assert latest_trust(api) == {"e2e": False, "approvers": [], "webauthn": {"rp_id": "", "origins": []}}
    r = ok(toggle_e2e(api, True))
    assert r["outcome"] == "pending"  # adding approvers and an origin loosens
    pend = ok(api.get("/api/policy"))["pending"]
    changes = {c["path"] for t in pend["targets"] for c in t["changes"]}
    assert {
        "approvals.e2e",
        "approvals.approvers",
        "approvals.webauthn.rp_id",
        "approvals.webauthn.origins",
    } <= changes
    assert sign_pending(api)["outcome"] == "published"
    t = latest_trust(api)
    assert t["e2e"] is True
    assert [a["name"] for a in t["approvers"]] == ["MacBook"]
    assert t["webauthn"] == {"rp_id": "localhost", "origins": [ORIGIN]}


def test_with_e2e_on_every_approval_needs_a_passkey(api: Api) -> None:
    ok(toggle_e2e(api, True))
    sign_pending(api)
    api.world.e2e = True  # what Home.config / warden serve read from the published bundle
    p = api.world.propose("npm ci")
    with pytest.raises(ApprovalRefused) as exc:
        api.world.svc.approve(p.id, p.hash, ALICE_CLI)
    assert exc.value.code == "passkey_required"
    assert "dashboard or app" in exc.value.message
    assert ok(api.post(f"/api/plans/{p.id}/approval/options"))["needs_passkey"] is True
    assert api.post(f"/api/plans/{p.id}/approve", {"hash": p.hash}).status_code == 403
    o = ok(api.post(f"/api/plans/{p.id}/approval/options"))
    d = ok(
        api.post(
            f"/api/plans/{p.id}/approve",
            {"hash": p.hash, "challenge_id": o["challenge_id"], "credential": api.auth.get(o["options"])},
        )
    )
    assert d["approval"]["passkey"] == api.auth.id


def test_removing_a_passkey_tightens_at_once(api: Api) -> None:
    backup = api.register("Backup", SoftAuthenticator(ORIGIN, "localhost"))
    ok(toggle_e2e(api, True))
    sign_pending(api)
    assert len(latest_trust(api)["approvers"]) == 2
    o = ok(api.post("/api/confirm/options", {"purpose": "remove_passkey", "subject": backup.id}))
    r = ok(
        api.post(
            f"/api/passkeys/{backup.id}/remove",
            {"challenge_id": o["challenge_id"], "credential": api.auth.get(o["options"])},
        )
    )
    assert "published" in r["message"]
    assert [a["name"] for a in latest_trust(api)["approvers"]] == ["MacBook"]


def test_turning_e2e_off_waits_for_the_offline_key(api: Api) -> None:
    ok(toggle_e2e(api, True))
    sign_pending(api)
    r = ok(toggle_e2e(api, False))
    assert r["outcome"] == "pending"
    assert latest_trust(api)["e2e"] is True  # still on until signed


def test_e2e_needs_a_confirmation(api: Api) -> None:
    r = api.post("/api/e2e", {"enabled": True, "challenge_id": "x", "credential": {}})
    assert r.status_code == 400


def test_policy_publish_keeps_the_trust(api: Api) -> None:
    ok(toggle_e2e(api, True))
    sign_pending(api)
    before = latest_trust(api)
    text = ok(api.get("/api/policy"))["yaml"].replace("/srv/prod]", "/srv/prod, /srv/dev/secret]")
    pv = ok(api.post("/api/policy/preview", {"yaml": text}))
    assert pv["cls"] == "tighten"
    o = ok(api.post(f"/api/policy/publish/options?preview_id={pv['preview_id']}"))
    ok(
        api.post(
            "/api/policy/publish",
            {
                "preview_id": pv["preview_id"],
                "challenge_id": o["challenge_id"],
                "credential": api.auth.get(o["options"]),
            },
        )
    )
    assert latest_trust(api) == before
