"""M7 Done-when with the real agent: "nightly job runs and reports" (README 11, DECISIONS M7).

A plan succeeds → it's saved as a schedule → the human approves it with a passkey → the scheduler fires at
the slot → the agent checks the grant and the slot itself and runs it → the run is reported (last result,
audit, notification). Then what a compromised Warden would try: the same slot again, a slot that isn't
now, steps that aren't the approved ones. And a failing run stops the schedule and notifies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harness import HUMAN, World, world
from sqlmodel import Session, select

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from softauth import SoftAuthenticator
from test_e2e_approvals import sign_pending

from warden import audit, notify
from warden.actors import HumanActor
from warden.keys import b64url, raw_public
from warden.plans.models import PasskeyAssertion, PlanStatus
from warden.policy_dist import offline_keys
from warden.policy_dist import publish as publishing
from warden.schedules import grant
from warden.schedules.scheduler import Scheduler
from warden.schedules.service import Schedule, ScheduleService

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or os.geteuid() != 0, reason="needs Go and root (to run the agent as nobody)"
)
ORIGIN, RP = "https://warden.example.dk", "warden.example.dk"
DASH = HumanActor("dashboard", "MacBook")


def now() -> datetime:
    return datetime.now(UTC)


async def trusted_passkey(w: World) -> SoftAuthenticator:
    """A passkey the agent trusts: the approver list published and signed with the offline key."""
    offline = Ed25519PrivateKey.generate()
    with Session(w.engine) as s, s.begin():
        offline_keys.register(
            s, b64url(raw_public(offline.public_key())), role="primary", actor=HUMAN, now=now()
        )
    await w.enroll()
    await w.start_agent()
    auth = SoftAuthenticator(ORIGIN, RP)
    spki = auth.key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    trust = {
        "e2e": False,
        "approvers": [{"credential_id": auth.id, "alg": -7, "public": b64url(spki), "name": "MacBook"}],
        "webauthn": {"rp_id": RP, "origins": [ORIGIN]},
    }
    publishing.publish_trust(w.engine, trust, online=w.online, approval=w.approval, now=now(), actor="x")
    sign_pending(w, offline)
    await w.dispatcher.policy_changed()
    await w.wait_for(lambda: w.dispatcher.sessions["dev"].policy_version == 2)
    return auth


def approve(svc: ScheduleService, sid: str, auth: SoftAuthenticator) -> Schedule:
    # Approved 90 s ago, so the current minute is already a slot of "* * * * *".
    at = now() - timedelta(seconds=90)
    challenge = b64url(hashlib.sha256(grant.message(svc.payload_for(sid, DASH, at))).digest())
    r = auth.get({"challenge": challenge})["response"]
    passkey = PasskeyAssertion(
        credential_id=auth.id,
        authenticator_data=r["authenticatorData"],
        client_data_json=r["clientDataJSON"],
        signature=r["signature"],
    )
    return svc.approve(sid, DASH, passkey=passkey, at=at)


def refusals(w: World) -> list[str]:
    with Session(w.engine) as s:
        return [json.loads(e.detail)["code"] for e in audit.entries(s) if e.action == "plan_refused_by_agent"]


def test_nightly_job_runs_and_reports(monkeypatch: pytest.MonkeyPatch) -> None:
    async def scenario() -> None:
        async with world() as w:
            auth = await trusted_passkey(w)
            svc = ScheduleService(w.engine, w.plans, approval_key=w.approval, default_days=lambda: 90)
            sched = Scheduler(svc, w.dispatcher)

            source = await w.dispatcher.execute(w.approve(w.propose("echo nightly build")).id)
            assert source.status == PlanStatus.SUCCEEDED, w.agent_log()
            sch = svc.create(source.id, name="nightly-dev", cron="* * * * *", days=90, actor=DASH)
            assert await sched.tick() == []  # not approved yet: nothing runs
            approve(svc, sch.id, auth)

            [run_id] = await sched.tick()
            await sched.wait()
            run = w.plans.get(run_id)
            assert run.status == PlanStatus.SUCCEEDED, w.agent_log()
            assert run.schedule_id == sch.id
            done = svc.get(sch.id)
            assert (done.status, done.row.last_result, done.row.last_run_id) == (
                "active",
                "succeeded",
                run_id,
            )
            with Session(w.engine) as s:
                kinds = [n.kind for n in s.exec(select(notify.NotificationRow))]
                actions = {e.action for e in audit.entries(s)}
                assert audit.verify(s).ok
            assert kinds == ["scheduled_done"]
            assert {"schedule_approved", "schedule_fired", "scheduled_run_finished"} <= actions
            assert await sched.tick() == []  # once per slot

            # A compromised Warden replays the same slot: the agent's own claim refuses it.
            slot = run.slot
            assert slot is not None
            replay = svc.create_run(done, slot)
            again = await w.dispatcher.execute(replay.id)
            assert again.status == PlanStatus.FAILED
            assert refusals(w)[-1] == "replayed_plan"

            # …or sends a slot that isn't now (Warden's own check switched off): the agent refuses.
            monkeypatch.setattr(grant, "LATE", timedelta(days=1))
            old = svc.create_run(done, slot - timedelta(minutes=30))
            late = await w.dispatcher.execute(old.id)
            assert late.status == PlanStatus.FAILED
            assert refusals(w)[-1] == "bad_slot"

    asyncio.run(scenario())


def test_failed_run_stops_the_schedule_and_notifies() -> None:
    async def scenario() -> None:
        async with world() as w:
            auth = await trusted_passkey(w)
            svc = ScheduleService(w.engine, w.plans, approval_key=w.approval, default_days=lambda: 90)
            sched = Scheduler(svc, w.dispatcher)
            marker = w.ws / "marker"
            marker.write_text("ok")
            os.chown(marker, w.agent_user.pw_uid, w.agent_user.pw_gid)
            source = await w.dispatcher.execute(w.approve(w.propose(f"cat {marker}")).id)
            assert source.status == PlanStatus.SUCCEEDED, w.agent_log()
            sch = svc.create(source.id, name="needs-marker", cron="* * * * *", days=30, actor=DASH)
            approve(svc, sch.id, auth)
            marker.unlink()  # the world changed since the template was approved

            [run_id] = await sched.tick()
            await sched.wait()
            assert w.plans.get(run_id).status == PlanStatus.FAILED
            stopped = svc.get(sch.id)
            assert stopped.status == "stopped"
            assert stopped.row.last_result == "failed"
            with Session(w.engine) as s:
                assert [n.kind for n in s.exec(select(notify.NotificationRow))] == ["schedule_stopped"]

    asyncio.run(scenario())
