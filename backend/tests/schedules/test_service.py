"""Schedule service and scheduler with a fake clock (README 11, DECISIONS M7): creation rules, approval,
the slot logic across expiry and pause, missed runs, notify-and-stop, and the dispatch checks."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, col, select
from svc import ALICE, DASH, World

from warden import audit, notify
from warden.errors import ApprovalRefused, InputRefused, NotHuman, WardenError
from warden.keys import b64url
from warden.plans.models import PasskeyAssertion, Plan, PlanStatus
from warden.plans.runs import StepOutcome
from warden.schedules import grant
from warden.schedules.cron import CronError
from warden.schedules.scheduler import Scheduler
from warden.schedules.service import ScheduleRefused, ScheduleService
from warden.signing import SCHEDULE_DOMAIN, ApprovalKey

CLAUDE_LIKE = object()


@pytest.fixture
def world(engine: Engine, tmp_path: Path) -> World:
    return World(engine=engine, key=ApprovalKey.generate(tmp_path / "approval.key"))


@pytest.fixture
def svc(world: World) -> ScheduleService:
    return ScheduleService(
        world.engine, world.svc, approval_key=world.key, default_days=lambda: 90, clock=world.clock
    )


def succeeded(world: World, *commands: str) -> Plan:
    p = world.approve(world.propose(*(commands or ("npm ci", "npm test"))))
    world.svc.start_run(p.id)
    return world.svc.finish_run(p.id, [StepOutcome(n=i, exit_code=0) for i in range(1, len(p.steps) + 1)])


def passkey_for(svc: ScheduleService, sid: str, at: datetime) -> PasskeyAssertion:
    """An assertion whose challenge is the grant (the API verifies the signature; the service the binding)."""
    challenge = b64url(hashlib.sha256(grant.message(svc.payload_for(sid, DASH, at))).digest())
    client = b64url(json.dumps({"type": "webauthn.get", "challenge": challenge}).encode())
    return PasskeyAssertion(
        credential_id="cred", authenticator_data="AA", client_data_json=client, signature="AA"
    )


def active(world: World, svc: ScheduleService, cron: str = "0 3 * * *", days: int = 90) -> str:
    sch = svc.create(succeeded(world).id, name="nightly", cron=cron, days=days, actor=DASH)
    svc.approve(sch.id, DASH, passkey=passkey_for(svc, sch.id, world.clock()), at=world.clock())
    return sch.id


def test_create_only_from_succeeded_plans_by_humans(world: World, svc: ScheduleService) -> None:
    pending = world.propose("npm ci")
    with pytest.raises(ScheduleRefused, match="succeeded"):
        svc.create(pending.id, name="x", cron="0 3 * * *", days=90, actor=DASH)
    ok = succeeded(world)
    with pytest.raises(NotHuman):
        svc.create(ok.id, name="x", cron="0 3 * * *", days=90, actor=CLAUDE_LIKE)  # type: ignore[arg-type]
    for name in ("", "Nightly", "a b", "x" * 64, "../x"):
        with pytest.raises(InputRefused):
            svc.create(ok.id, name=name, cron="0 3 * * *", days=90, actor=DASH)
    with pytest.raises(CronError):
        svc.create(ok.id, name="x", cron="@daily", days=90, actor=DASH)
    with pytest.raises(InputRefused, match="30, 90 or 180"):
        svc.create(ok.id, name="x", cron="0 3 * * *", days=365, actor=DASH)
    sch = svc.create(ok.id, name="nightly", cron="0 3 * * *", days=None, actor=DASH)
    assert sch.status == "awaiting_approval"
    assert sch.row.expiry_days == 90
    assert grant.template_hash(sch.template()) == sch.row.template_hash
    with pytest.raises(InputRefused, match="already exists"):
        svc.create(ok.id, name="nightly", cron="0 4 * * *", days=90, actor=DASH)


def test_approve_needs_the_passkey_over_this_exact_grant(world: World, svc: ScheduleService) -> None:
    sch = svc.create(succeeded(world).id, name="nightly", cron="0 3 * * *", days=30, actor=DASH)
    now = world.clock()
    other = svc.create(succeeded(world).id, name="other", cron="0 3 * * *", days=30, actor=DASH)
    with pytest.raises(ApprovalRefused, match="something else"):
        svc.approve(sch.id, DASH, passkey=passkey_for(svc, other.id, now), at=now)
    with pytest.raises(ApprovalRefused, match="too old"):
        svc.approve(
            sch.id,
            DASH,
            passkey=passkey_for(svc, sch.id, now - timedelta(minutes=5)),
            at=now - timedelta(minutes=5),
        )
    with pytest.raises(NotHuman):
        svc.approve(sch.id, CLAUDE_LIKE, passkey=passkey_for(svc, sch.id, now), at=now)  # type: ignore[arg-type]
    done = svc.approve(sch.id, DASH, passkey=passkey_for(svc, sch.id, now), at=now)
    assert done.status == "active"
    assert done.expires_at == now + timedelta(days=30)
    world.key.verifier().verify(done.payload(), done.approval().signature, domain=SCHEDULE_DOMAIN)
    with pytest.raises(ScheduleRefused, match="active"):
        svc.approve(sch.id, DASH, passkey=passkey_for(svc, sch.id, now), at=now)


def test_due_slots_once_within_15_minutes_and_expiry(world: World, svc: ScheduleService) -> None:
    sid = active(world, svc, days=30)
    # T0 is 20.10.2026 12:00 UTC; 03:00 Copenhagen on the 21st is 01:00 UTC.
    slot = datetime(2026, 10, 21, 1, 0, tzinfo=UTC)
    world.clock.now = slot - timedelta(minutes=1)
    assert svc.due(world.clock()) == []
    world.clock.now = slot + timedelta(minutes=3)
    due = svc.due(world.clock())
    assert [(s.id, t) for s, t in due] == [(sid, slot)]
    svc.mark_fired(due[0][0], slot, None)
    assert svc.due(world.clock()) == []  # never the same slot twice
    world.clock.now = slot + timedelta(days=1, minutes=20)  # Warden was down past the 15 min window
    assert svc.due(world.clock()) == []
    world.clock.now = slot + timedelta(days=30, hours=2)
    assert svc.due(world.clock()) == []
    assert svc.get(sid).status == "expired"


def test_pause_and_resume_skip_what_was_due(world: World, svc: ScheduleService) -> None:
    sid = active(world, svc)
    svc.pause(sid, DASH)
    world.clock.now = datetime(2026, 10, 21, 1, 5, tzinfo=UTC)
    assert svc.due(world.clock()) == []
    svc.resume(sid, ALICE)
    assert svc.due(world.clock()) == []  # the 03:00 slot passed while paused
    world.clock.now = datetime(2026, 10, 22, 1, 2, tzinfo=UTC)
    assert [s.id for s, _ in svc.due(world.clock())] == [sid]
    svc.delete(sid, DASH)
    assert svc.due(world.clock()) == []


class FakeDispatcher:
    """Runs plans through the real PlanService; `outcome` decides each step's exit code."""

    def __init__(self, world: World, *, why: str | None = None, exit_code: int = 0) -> None:
        self.world, self.why, self.exit_code = world, why, exit_code
        self.sent: list[Any] = []

    def cannot_run(self, target: str) -> str | None:
        return self.why

    async def execute(self, plan_id: str) -> Plan:
        env = self.world.svc.validate_for_dispatch(plan_id)
        self.sent.append(env)
        p = self.world.svc.start_run(plan_id)
        outcomes = [StepOutcome(n=1, exit_code=self.exit_code)]
        if self.exit_code == 0:
            outcomes += [StepOutcome(n=i, exit_code=0) for i in range(2, len(p.steps) + 1)]
        return self.world.svc.finish_run(plan_id, outcomes)


def run_tick(sched: Scheduler) -> list[str]:
    async def go() -> list[str]:
        started = await sched.tick()
        await sched.wait()
        return started

    return asyncio.run(go())


def notifications(engine: Engine) -> list[notify.NotificationRow]:
    with Session(engine) as s:
        return list(s.exec(select(notify.NotificationRow).order_by(col(notify.NotificationRow.id))))


def test_a_nightly_run_runs_and_reports(world: World, svc: ScheduleService) -> None:
    sid = active(world, svc)
    disp = FakeDispatcher(world)
    sched = Scheduler(svc, disp, clock=world.clock)  # type: ignore[arg-type]
    world.clock.now = datetime(2026, 10, 21, 1, 0, 30, tzinfo=UTC)
    [run_id] = run_tick(sched)
    run = world.svc.get(run_id)
    assert run.status == PlanStatus.SUCCEEDED
    assert run.requested_by == "scheduler"
    assert run.schedule_id == sid
    env = disp.sent[0]
    assert env.schedule["run_id"] == run_id
    assert env.schedule["slot"] == "2026-10-21T01:00:00+00:00"
    assert env.plan_hash == svc.get(sid).row.template_hash
    assert env.template["schedule_id"] == sid
    sch = svc.get(sid)
    assert (sch.row.last_result, sch.row.last_run_id) == ("succeeded", run_id)
    assert [n.kind for n in notifications(world.engine)] == ["scheduled_done"]
    assert run_tick(sched) == []  # once per slot
    with Session(world.engine) as s:
        actions = [r.action for r in s.exec(select(audit.AuditRow))]
        assert audit.verify(s).ok
    assert {"schedule_created", "schedule_approved", "schedule_fired", "scheduled_run_finished"} <= set(
        actions
    )


def test_a_failed_run_stops_the_schedule_and_notifies(world: World, svc: ScheduleService) -> None:
    sid = active(world, svc)
    sched = Scheduler(svc, FakeDispatcher(world, exit_code=1), clock=world.clock)  # type: ignore[arg-type]
    world.clock.now = datetime(2026, 10, 21, 1, 1, tzinfo=UTC)
    [run_id] = run_tick(sched)
    assert world.svc.get(run_id).status == PlanStatus.FAILED
    sch = svc.get(sid)
    assert sch.status == "stopped"
    assert sch.row.last_result == "failed"
    assert [n.kind for n in notifications(world.engine)] == ["schedule_stopped"]
    world.clock.now = datetime(2026, 10, 22, 1, 1, tzinfo=UTC)
    assert run_tick(sched) == []
    with pytest.raises(ScheduleRefused):
        svc.resume(sid, DASH)


def test_missed_when_the_agent_cant_run_it(world: World, svc: ScheduleService) -> None:
    sid = active(world, svc)
    sched = Scheduler(svc, FakeDispatcher(world, why="dev is offline"), clock=world.clock)  # type: ignore[arg-type]
    world.clock.now = datetime(2026, 10, 21, 1, 1, tzinfo=UTC)
    assert run_tick(sched) == []
    sch = svc.get(sid)
    assert (sch.status, sch.row.last_result, sch.row.last_detail) == ("active", "missed", "dev is offline")
    assert notifications(world.engine) == []


def test_policy_tightening_invalidates_the_schedule(world: World, svc: ScheduleService) -> None:
    sid = active(world, svc)
    deny = world.policy.model_copy(
        update={"commands": world.policy.commands.model_copy(update={"deny_patterns": ("npm\\s+test",)})}
    )
    world.policy = deny
    assert svc.recheck_policy() == [sid]
    assert svc.get(sid).status == "invalidated"
    assert [n.kind for n in notifications(world.engine)] == ["schedule_stopped"]


def test_dispatch_checks_the_run_against_its_schedule(world: World, svc: ScheduleService) -> None:
    sid = active(world, svc)
    sch = svc.get(sid)
    slot = datetime(2026, 10, 21, 1, 0, tzinfo=UTC)
    world.clock.now = slot + timedelta(minutes=1)
    run = svc.create_run(sch, slot)
    world.clock.now = slot + timedelta(minutes=16)
    with pytest.raises(WardenError, match="slot isn't now"):
        world.svc.validate_for_dispatch(run.id)
    world.clock.now = slot + timedelta(minutes=2)
    svc.pause(sid, DASH)
    with pytest.raises(WardenError, match="paused"):
        world.svc.validate_for_dispatch(run.id)
