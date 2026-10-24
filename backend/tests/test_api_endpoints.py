"""Dashboard API endpoints (PLAN M6): what each page reads and every human action it can take."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from apihelp import ALICE_CLI, ORIGIN, Api, make_api
from softauth import SoftAuthenticator
from sqlalchemy import Engine
from sqlmodel import Session
from svc import World

from warden import audit
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
    return a


def ok(r: Any) -> Any:
    assert r.status_code == 200, r.text
    return r.json()


def actions(api: Api) -> list[str]:
    with Session(api.world.engine) as s:
        return [e.action for e in audit.entries(s)]


def approve_with_passkey(api: Api, plan_id: str, auth: SoftAuthenticator | None = None) -> Any:
    o = ok(api.post(f"/api/plans/{plan_id}/approval/options"))
    detail = ok(api.get(f"/api/plans/{plan_id}"))
    cred = (auth or api.auth).get(o["options"])
    return api.post(
        f"/api/plans/{plan_id}/approve",
        {"hash": detail["hash"], "challenge_id": o["challenge_id"], "credential": cred},
    )


# --- plans ------------------------------------------------------------------------------------------


def test_lists_filters_and_search(api: Api) -> None:
    a = api.world.propose("npm ci")
    api.world.propose("npm test", goal="Run the tests")
    api.world.propose("rm -rf /", goal="Oops")
    data = ok(api.get("/api/plans"))
    assert data["counts"]["all"] == 3
    assert data["counts"]["awaiting"] == 2
    assert data["counts"]["closed"] == 1
    assert [p["status"] for p in ok(api.get("/api/plans?filter=closed"))["plans"]] == ["rejected"]
    assert [p["id"] for p in ok(api.get("/api/plans?q=npm ci"))["plans"]] == [a.id]
    appr = ok(api.get("/api/approvals"))
    assert appr["counts"]["pending"] == 2
    assert appr["plans"][0]["id"] == a.id  # oldest first
    assert appr["plans"][0]["agent"]["state"] == "missing"


def test_detail_shows_everything(api: Api) -> None:
    p = api.world.propose("npm ci", "npm test")
    d = ok(api.get(f"/api/plans/{p.id}"))
    assert [s["command"] for s in d["step_list"]] == ["npm ci", "npm test"]
    assert d["hash"] == p.hash
    assert d["final_verdict"] == "escalate"  # no gatekeepers configured (D-19)
    assert d["passkey_reasons"] == []
    assert d["passkeys_registered"] == 1
    assert api.get("/api/plans/pln_nope").status_code == 404


def test_approve_low_risk_without_passkey(api: Api) -> None:
    p = api.world.propose("npm ci")
    o = ok(api.post(f"/api/plans/{p.id}/approval/options"))
    assert o["needs_passkey"] is False
    d = ok(api.post(f"/api/plans/{p.id}/approve", {"hash": p.hash}))
    assert d["status"] == "approved"
    assert d["approval"]["by"] == "dashboard:MacBook"
    assert d["approval"]["passkey"] is None


def test_passkey_required_for_group_members(api: Api) -> None:
    p = api.world.propose("npm ci", target="sec-auth", cwd="/srv/app")
    o = ok(api.post(f"/api/plans/{p.id}/approval/options"))
    assert o["needs_passkey"] is True
    assert "group" in o["reasons"][0]
    r = api.post(f"/api/plans/{p.id}/approve", {"hash": p.hash})
    assert r.status_code == 403
    assert r.json()["detail"]["code"] == "passkey_required"
    d = ok(approve_with_passkey(api, p.id))
    assert d["status"] == "approved"
    assert d["approval"]["passkey"] == api.auth.id
    stored = api.world.svc.get(p.id).approval
    assert stored is not None
    assert stored.passkey is not None


def test_passkey_approval_bound_to_its_plan(api: Api) -> None:
    a = api.world.propose("npm ci", target="sec-auth", cwd="/srv/app")
    b = api.world.propose("npm test", target="sec-auth", cwd="/srv/app")
    o = ok(api.post(f"/api/plans/{a.id}/approval/options"))
    cred = api.auth.get(o["options"])
    r = api.post(
        f"/api/plans/{b.id}/approve", {"hash": b.hash, "challenge_id": o["challenge_id"], "credential": cred}
    )
    assert r.status_code == 400
    assert api.world.svc.get(b.id).status.value == "awaiting_approval"
    o = ok(api.post(f"/api/plans/{a.id}/approval/options"))
    stranger = SoftAuthenticator(ORIGIN, "localhost")
    r = api.post(
        f"/api/plans/{a.id}/approve",
        {"hash": a.hash, "challenge_id": o["challenge_id"], "credential": stranger.get(o["options"])},
    )
    assert r.status_code == 403


def test_edits_and_reject(api: Api) -> None:
    p = api.world.propose("npm ci", "npm test")
    d = ok(api.post(f"/api/plans/{p.id}/edits", {"edits": [{"n": 2, "command": "npm run test"}]}))
    assert d["status"] == "awaiting_approval"
    assert d["step_list"][1]["edited"] is True
    assert d["hash"] != p.hash
    r = ok(api.post(f"/api/plans/{p.id}/reject", {"reason": "not now"}))
    assert r["status"] == "rejected"
    assert r["reject_reason"] == "not now"
    assert api.post(f"/api/plans/{p.id}/approve", {"hash": d["hash"]}).status_code == 409


def test_output_endpoint(api: Api) -> None:
    from warden.dispatch import outputs

    p = api.world.propose("npm ci")
    with Session(api.world.engine) as s, s.begin():
        outputs.append(s, plan_id=p.id, n=1, seq=1, stream="stdout", data="\x1b[32mok\x1b[0m\n")
    out = ok(api.get(f"/api/plans/{p.id}/output"))
    assert out["chunks"][0]["data"].endswith("ok\x1b[0m\n")
    assert out["cap_bytes"] == 1024 * 1024


# --- agents -----------------------------------------------------------------------------------------


def test_agents_add_and_withdraw(api: Api) -> None:
    rows = ok(api.get("/api/agents"))["agents"]
    assert {a["name"]: a["status"] for a in rows} == {
        "dev": "not_enrolled",
        "dev2": "not_enrolled",
        "sec-auth": "not_enrolled",
    }
    t = ok(api.post("/api/agents", {"name": "dev"}))
    assert t["token"].startswith("wdn_enr_")
    assert "warden-agent enroll" in t["command"]
    assert ok(api.get("/api/agents/dev/enrollment"))["status"] == "open"
    assert ok(api.post("/api/agents/dev/reject"))["message"].startswith("1")
    assert ok(api.get("/api/agents/dev/enrollment"))["status"] == "rejected"
    assert api.post("/api/agents", {"name": "prod"}).status_code == 400  # not in targets.yaml


# --- policy -----------------------------------------------------------------------------------------


def _publish(api: Api, text: str) -> Any:
    pv = ok(api.post("/api/policy/preview", {"yaml": text}))
    if not pv["preview_id"]:
        return pv
    o = ok(api.post(f"/api/policy/publish/options?preview_id={pv['preview_id']}"))
    return api.post(
        "/api/policy/publish",
        {
            "preview_id": pv["preview_id"],
            "challenge_id": o["challenge_id"],
            "credential": api.auth.get(o["options"]),
        },
    )


def test_publish_tightening_from_the_browser(api: Api) -> None:
    pol = ok(api.get("/api/policy"))
    assert pol["version"] == 1
    assert pol["writable"] is True
    text = pol["yaml"].replace(
        "deny_paths: [/etc, /root, /home, /var/lib/docker, /srv/prod]",
        "deny_paths: [/etc, /root, /home, /var/lib/docker, /srv/prod, /srv/dev/secret]",
    )
    assert text != pol["yaml"]
    pv = ok(api.post("/api/policy/preview", {"yaml": text}))
    assert pv["cls"] == "tighten"
    assert pv["gate_failures"] == []
    assert any("/srv/dev/secret" in line for line in pv["yaml_diff"])
    r = ok(_publish(api, text))
    assert r["outcome"] == "published"
    assert r["version"] == 2
    assert "/srv/dev/secret" in (api.ctx.config_dir / "policy.yaml").read_text()
    assert api.reloads
    assert ok(api.get("/api/policy"))["history"][0]["version"] == 2


def test_publish_needs_a_fresh_passkey_for_that_preview(api: Api) -> None:
    text = ok(api.get("/api/policy"))["yaml"].replace("output_cap_mb: 1", "output_cap_mb: 1\n")
    pv = ok(api.post("/api/policy/preview", {"yaml": text}))
    other = ok(api.post("/api/policy/preview", {"yaml": text + "\n"}))
    o = ok(api.post(f"/api/policy/publish/options?preview_id={other['preview_id']}"))
    r = api.post(
        "/api/policy/publish",
        {
            "preview_id": pv["preview_id"],
            "challenge_id": o["challenge_id"],
            "credential": api.auth.get(o["options"]),
        },
    )
    assert r.status_code == 400


def test_loosening_from_the_browser_waits_for_offline_key(api: Api) -> None:
    text = ok(api.get("/api/policy"))["yaml"].replace("/var/lib/docker, /srv/prod]", "/var/lib/docker]")
    r = ok(_publish(api, text))
    assert r["outcome"] == "pending"
    pol = ok(api.get("/api/policy"))
    assert pol["pending"]["version"] == 2
    assert pol["version"] == 1
    pf = api.get("/api/policy/pending/file")
    assert pf.status_code == 200
    assert json.loads(pf.text)["version"] == 2
    bad = api.post("/api/policy/pending/signature", {"content": "{}"})
    assert bad.status_code == 400
    assert ok(api.post("/api/policy/pending/discard"))["ok"] is True


def test_signature_upload_publishes(api: Api) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from warden.keys import b64url, key_id_for, raw_public
    from warden.policy_dist import bundle as bundles

    key = Ed25519PrivateKey.generate()
    with Session(api.world.engine) as s, s.begin():
        offline_keys.register(
            s, b64url(raw_public(key.public_key())), role="primary", actor=ALICE_CLI, now=api.ctx.now()
        )
    text = ok(api.get("/api/policy"))["yaml"].replace("/var/lib/docker, /srv/prod]", "/var/lib/docker]")
    ok(_publish(api, text))
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
    r = ok(api.post("/api/policy/pending/signature", {"content": json.dumps(sig)}))
    assert r["outcome"] == "published"
    assert r["version"] == 2


def test_gate_failure_gives_no_preview_id(api: Api, monkeypatch: pytest.MonkeyPatch) -> None:
    from warden.plans.models import StepKind

    cases = (
        *publishing.gate_cases(),
        publishing.GateCase(id="npm-ci", kind=StepKind.SHELL, command="npm ci"),
    )
    monkeypatch.setattr(publishing, "gate_cases", lambda: cases)
    pv = ok(api.post("/api/policy/preview", {"yaml": ok(api.get("/api/policy"))["yaml"]}))
    assert pv["preview_id"] is None
    assert pv["gate_failures"]


def test_invalid_yaml_preview(api: Api) -> None:
    pv = ok(api.post("/api/policy/preview", {"yaml": "deny_paths: [relative]\n"}))
    assert pv["ok"] is False
    assert pv["errors"]


def test_groups_view_and_edit(api: Api) -> None:
    gs = ok(api.get("/api/groups"))
    hs = next(g for g in gs if g["name"] == "high-security")
    assert {"read_only_restricted", "passkey_always", "unanimous"} <= set(hs["tags"])
    assert any(m["name"] == "sec-auth" and m["known"] for m in hs["members"])
    edited = {**hs["rules"], "desc": hs["desc"], "members": [*[m["name"] for m in hs["members"]], "dev2"]}
    pv = ok(api.post("/api/groups/preview", {"name": "high-security", "group": edited}))
    assert pv["cls"] == "tighten"
    assert "comments" in pv["note"]


def test_lockdown_and_lift(api: Api) -> None:
    p = api.world.propose("npm ci")
    api.world.svc.approve(p.id, p.hash, ALICE_CLI)
    r = ok(api.post("/api/lockdown"))
    assert r["outcome"] == "published"
    assert api.world.svc.get(p.id).status.value == "held"
    assert ok(api.get("/api/status"))["lockdown"] is True
    assert ok(api.post("/api/lockdown/lift"))["outcome"] == "pending"


# --- audit, feed, settings, status -----------------------------------------------------------------


def test_audit_feed_status(api: Api) -> None:
    p = api.world.propose("npm ci")
    page = ok(api.get("/api/audit"))
    assert page["chain_ok"] is True
    assert page["entries"][0]["seq"] > page["entries"][-1]["seq"]
    assert ok(api.get(f"/api/audit?q={p.id}"))["entries"]
    exp = api.get("/api/audit/export")
    assert exp.status_code == 200
    assert all(json.loads(line) for line in exp.text.splitlines())
    feed = ok(api.get("/api/feed"))["items"]
    assert [i["type"] for i in feed[:2]] == ["verdict", "proposal"]
    assert feed[1]["plan_id"] == p.id
    assert feed[1]["target"] == "dev"
    assert ok(api.get("/api/feed?type=approval"))["items"] == []
    st = ok(api.get("/api/status"))
    assert st["awaiting"] == 1
    assert st["me"] == "MacBook"
    assert [a["name"] for a in st["agents"]] == ["dev", "dev2", "sec-auth"]


def test_settings_changes_are_audited(api: Api) -> None:
    s = ok(api.get("/api/settings"))
    assert s["values"]["approvals.expiry_min"] == 30
    assert s["gatekeepers"]["source"] == "gatekeeper.yaml"
    assert {k["name"] for k in s["keys"]} >= {"Approval key", "Online policy key"}
    r = api.client.put(
        "/api/settings",
        json={"changes": {"approvals.expiry_min": 15, "ui.language": "da"}},
        headers={"origin": ORIGIN, "x-warden": "1"},
    )
    assert r.status_code == 200, r.text
    with Session(api.world.engine) as ss:
        changed = [e for e in audit.entries(ss) if e.action == "setting_changed"]
    assert {json.loads(e.detail)["after"] for e in changed} == {15, "da"}
    bad = api.client.put(
        "/api/settings",
        json={"changes": {"server.public_url": "https://evil"}},
        headers={"origin": ORIGIN, "x-warden": "1"},
    )
    assert bad.status_code == 400
    bad = api.client.put(
        "/api/settings",
        json={"changes": {"approvals.expiry_min": 0}},
        headers={"origin": ORIGIN, "x-warden": "1"},
    )
    assert bad.status_code == 400


def test_passkeys_and_sessions(api: Api) -> None:
    backup = api.register("Backup", SoftAuthenticator(ORIGIN, "localhost"))
    assert {p["name"] for p in ok(api.get("/api/passkeys"))} == {"MacBook", "Backup"}
    sess = ok(api.get("/api/sessions"))
    assert sum(s["current"] for s in sess) == 1
    o = ok(api.post("/api/confirm/options", {"purpose": "remove_passkey", "subject": backup.id}))
    r = api.post(
        f"/api/passkeys/{backup.id}/remove",
        {"challenge_id": o["challenge_id"], "credential": api.auth.get(o["options"])},
    )
    assert ok(r)["ok"] is True
    assert {p["name"] for p in ok(api.get("/api/passkeys"))} == {"MacBook"}


def test_everything_needs_a_session(api: Api) -> None:
    api.client.cookies.clear()
    for path in (
        "/api/plans",
        "/api/approvals",
        "/api/agents",
        "/api/policy",
        "/api/groups",
        "/api/audit",
        "/api/feed",
        "/api/settings",
        "/api/status",
        "/api/sessions",
        "/api/passkeys",
    ):
        assert api.get(path).status_code == 401, path


def test_openapi_schema_is_complete(api: Api) -> None:
    schema = api.get("/api/openapi.json").json()
    paths = set(schema["paths"])
    assert {
        "/api/plans/{plan_id}/approve",
        "/api/policy/publish",
        "/api/agents/{name}/confirm",
        "/api/settings",
    } <= paths
    assert "approve" not in json.dumps([p for p in paths if p.startswith("/mcp")])
