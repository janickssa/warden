"""Real API responses for the iPhone app's contract tests (M8): WardenCore decodes every one of them.

Regenerate with: UPDATE_FIXTURES=1 uv run pytest tests/test_api_examples.py
The stored examples must keep the same shape (keys) as what the API returns now, so a backend change
that would break the app fails here first.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from apihelp import ALICE_CLI, Api, make_api
from policyhelp import FIXTURES
from sqlalchemy import Engine
from svc import World

from warden.plans.runs import StepOutcome
from warden.policy_dist import publish as publishing
from warden.signing import ApprovalKey

PATH = FIXTURES / "api_examples.json"


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


def collect(api: Api) -> dict[str, Any]:
    waiting = api.world.propose("npm ci", "npm test")
    done = api.world.propose(("git", "git status"))
    api.world.svc.approve(done.id, done.hash, ALICE_CLI)
    api.world.svc.start_run(done.id)
    api.world.svc.finish_run(done.id, [StepOutcome(n=1, exit_code=0, duration_s=1.5)])
    sch = ok(api.post(f"/api/plans/{done.id}/schedule", {"name": "nightly", "cron": "0 3 * * *"}))
    return {
        "status": ok(api.get("/api/status")),
        "me": ok(api.get("/api/auth/me")),
        "approvals": ok(api.get("/api/approvals")),
        "plans": ok(api.get("/api/plans")),
        "plan_waiting": ok(api.get(f"/api/plans/{waiting.id}")),
        "plan_succeeded": ok(api.get(f"/api/plans/{done.id}")),
        "output": ok(api.get(f"/api/plans/{done.id}/output")),
        "approval_options": ok(api.post(f"/api/plans/{waiting.id}/approval/options")),
        "login_options": ok(api.post("/api/auth/options")),
        "feed": ok(api.get("/api/feed")),
        "schedules": ok(api.get("/api/schedules")),
        "schedule": ok(api.get(f"/api/schedules/{sch['id']}")),
        "devices": ok(api.get("/api/devices")),
        "problem": api.post(f"/api/plans/{waiting.id}/approve", {"hash": "sha256:00"}).json(),
    }


def shape(v: Any) -> Any:
    if isinstance(v, dict):
        return {
            k: shape(x) for k, x in sorted(v.items()) if k not in ("notes", "options", "counts", "detail")
        }
    if isinstance(v, list):
        return [shape(v[0])] if v else []
    return type(v).__name__ if v is not None else None


def test_examples_match_the_api(api: Api) -> None:
    fresh = collect(api)
    if os.environ.get("UPDATE_FIXTURES") == "1" or not PATH.exists():
        PATH.write_text(
            json.dumps(fresh, indent=1, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    stored = json.loads(PATH.read_text(encoding="utf-8"))
    for key, value in fresh.items():
        assert set(_keys(stored[key])) == set(_keys(value)), key


def _keys(v: Any, prefix: str = "") -> list[str]:
    out: list[str] = []
    if isinstance(v, dict):
        for k, x in v.items():
            if k in ("notes", "options", "counts", "detail"):
                out.append(prefix + k)
                continue
            out += [prefix + k, *_keys(x, prefix + k + ".")]
    elif isinstance(v, list) and v:
        out += _keys(v[0], prefix + "[].")
    return out
