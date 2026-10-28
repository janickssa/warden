"""Schedules over the dashboard API (README 17.3 Schedules): Save as schedule, approve with a passkey,
pause, resume, delete, and the refusals around them."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from apihelp import ALICE_CLI, Api, make_api
from sqlalchemy import Engine
from svc import World

from warden.plans.runs import StepOutcome
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


def succeeded(api: Api) -> str:
    p = api.world.propose("npm ci", "npm test")
    api.world.svc.approve(p.id, p.hash, ALICE_CLI)
    api.world.svc.start_run(p.id)
    api.world.svc.finish_run(p.id, [StepOutcome(n=1, exit_code=0), StepOutcome(n=2, exit_code=0)])
    return p.id


def approve(api: Api, sid: str) -> Any:
    o = ok(api.post(f"/api/schedules/{sid}/approval/options"))
    assert o["needs_passkey"] is True
    return api.post(
        f"/api/schedules/{sid}/approve",
        {"challenge_id": o["challenge_id"], "credential": api.auth.get(o["options"])},
    )


def test_save_approve_pause_resume_delete(api: Api) -> None:
    pid = succeeded(api)
    sch = ok(
        api.post(f"/api/plans/{pid}/schedule", {"name": "nightly-dev-tests", "cron": "0 3 * * *", "days": 90})
    )
    assert sch["status"] == "awaiting_approval"
    assert sch["when"] == "Every day at 03:00"
    assert sch["next_run"] is None
    detail = ok(api.get(f"/api/schedules/{sch['id']}"))
    assert [s["command"] for s in detail["step_list"]] == ["npm ci", "npm test"]
    done = ok(approve(api, sch["id"]))
    assert done["status"] == "active"
    assert done["passkey"] == api.auth.id
    assert done["next_run"].startswith("2026-10-21T01:00:00")  # 03:00 Copenhagen
    assert ok(api.post(f"/api/schedules/{sch['id']}/pause"))["status"] == "paused"
    assert ok(api.post(f"/api/schedules/{sch['id']}/resume"))["status"] == "active"
    assert [s["name"] for s in ok(api.get("/api/schedules"))] == ["nightly-dev-tests"]
    ok(api.post(f"/api/schedules/{sch['id']}/delete"))
    assert ok(api.get("/api/schedules")) == []
    assert api.get(f"/api/schedules/{sch['id']}").status_code == 404
    kinds = {i["type"] for i in ok(api.get("/api/feed?type=schedule"))["items"]}
    assert kinds == {"schedule"}


def test_refusals(api: Api) -> None:
    pid = succeeded(api)
    pending = api.world.propose("npm ci")
    assert (
        api.post(f"/api/plans/{pending.id}/schedule", {"name": "x", "cron": "0 3 * * *"}).status_code == 400
    )
    assert api.post(f"/api/plans/{pid}/schedule", {"name": "x", "cron": "@daily"}).status_code == 400
    assert (
        api.post(f"/api/plans/{pid}/schedule", {"name": "x", "cron": "0 3 * * *", "days": 7}).status_code
        == 400
    )
    a = ok(api.post(f"/api/plans/{pid}/schedule", {"name": "a", "cron": "0 3 * * *"}))
    b = ok(api.post(f"/api/plans/{pid}/schedule", {"name": "b", "cron": "0 4 * * *"}))
    # A passkey assertion for schedule b can't approve schedule a.
    ob = ok(api.post(f"/api/schedules/{b['id']}/approval/options"))
    r = api.post(
        f"/api/schedules/{a['id']}/approve",
        {"challenge_id": ob["challenge_id"], "credential": api.auth.get(ob["options"])},
    )
    assert r.status_code >= 400
    # Nor can a confirmation made for something else (here: lockdown).
    r = api.post(f"/api/schedules/{a['id']}/approve", api.confirm("lockdown"))
    assert r.status_code >= 400
    assert api.post(f"/api/schedules/{a['id']}/pause").status_code == 409  # not active yet
    # Signed out: nothing.
    api.client.cookies.clear()
    assert api.get("/api/schedules").status_code == 401
    assert api.post(f"/api/schedules/{a['id']}/approval/options").status_code == 401
