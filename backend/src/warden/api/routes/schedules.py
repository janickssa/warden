"""Schedules (README 11, 17.3 Schedules): create from a succeeded plan, approve with a passkey, pause,
resume, delete. Humans only; Claude has no way to reach any of this."""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter

from warden.api import schemas as sc
from warden.api import views
from warden.api.auth import Ctx, Human
from warden.api.context import ApiContext
from warden.errors import ApprovalRefused, WardenError
from warden.passkeys import challenge_for
from warden.plans.models import PasskeyAssertion
from warden.schedules import grant
from warden.schedules.service import Schedule, ScheduleService

router = APIRouter(tags=["schedules"])


def _svc(c: ApiContext) -> ScheduleService:
    if c.schedules is None:
        raise WardenError("schedules aren't available", code="no_schedules")
    return c.schedules


def view(sch: Schedule, c: ApiContext) -> sc.ScheduleView:
    r = sch.row
    nxt = sch.next_slot(c.now())
    passkey = json.loads(r.passkey)["credential_id"] if r.passkey else None
    return sc.ScheduleView(
        id=r.id,
        name=r.name,
        target=r.target,
        goal=r.goal,
        cron=r.cron,
        when=sch.when,
        status=r.status,
        status_reason=r.status_reason,
        created_by=r.created_by,
        created_at=r.created_at,
        approved_by=r.approved_by,
        approved_at=r.approved_at,
        expires_at=r.expires_at,
        expiry_days=r.expiry_days,
        next_run=nxt.isoformat() if nxt else None,
        last_result=r.last_result,
        last_detail=r.last_detail,
        last_run_at=r.last_run_at,
        last_run_id=r.last_run_id,
        source_plan=r.source_plan,
        template_hash=r.template_hash,
        steps=len(sch.steps),
        passkey=passkey,
    )


def detail(sch: Schedule, c: ApiContext) -> sc.ScheduleDetail:
    svc = _svc(c)
    facts = views.Facts(c)
    risk, verdict = None, None
    try:
        src = c.plans.get(sch.row.source_plan)
        s = views.summary(src, facts)
        risk, verdict = s.risk, s.final_verdict
    except WardenError:
        pass
    steps = [
        sc.StepView(
            n=st.n,
            kind=st.kind.value,
            command=st.command,
            purpose=st.purpose,
            cwd=st.cwd,
            timeout_s=st.timeout_s,
            expect_exit=st.expect_exit,
            edited=False,
        )
        for st in sch.steps
    ]
    return sc.ScheduleDetail(
        **view(sch, c).model_dump(),
        step_list=steps,
        runs=[views.summary(p, facts) for p in svc.runs(sch.id)],
        risk=risk,
        final_verdict=verdict,
    )


@router.get("/schedules")
def list_schedules(c: Ctx, _: Human) -> list[sc.ScheduleView]:
    return [view(s, c) for s in _svc(c).all()]


@router.get("/schedules/{schedule_id}")
def get_schedule(schedule_id: str, c: Ctx, _: Human) -> sc.ScheduleDetail:
    return detail(_svc(c).get(schedule_id), c)


@router.post("/plans/{plan_id}/schedule")
def create(plan_id: str, body: sc.ScheduleIn, c: Ctx, human: Human) -> sc.ScheduleView:
    """ "Save as schedule": a new schedule waiting for its own approval."""
    return view(_svc(c).create(plan_id, name=body.name, cron=body.cron, days=body.days, actor=human), c)


@router.post("/schedules/{schedule_id}/approval/options")
def approval_options(schedule_id: str, c: Ctx, human: Human) -> sc.ApproveOptions:
    """Fixes the approval time now; the passkey's challenge is this exact grant."""
    at = c.now()
    payload = _svc(c).payload_for(schedule_id, human, at)
    cid, raw = c.passkeys.assertion_options(
        "approve_schedule",
        schedule_id,
        now=at,
        challenge=challenge_for(grant.message(payload)),
        data={"at": at.isoformat(), "by": human.label},
    )
    return sc.ApproveOptions(
        needs_passkey=True,
        reasons=["a schedule is a standing approval"],
        challenge_id=cid,
        options=json.loads(raw),
    )


@router.post("/schedules/{schedule_id}/approve")
def approve(schedule_id: str, body: sc.ConfirmIn, c: Ctx, human: Human) -> sc.ScheduleDetail:
    v, ch = c.passkeys.verify(
        body.challenge_id, body.credential, "approve_schedule", schedule_id, now=c.now()
    )
    if ch.data.get("by") != human.label:
        raise ApprovalRefused("that passkey approval was for someone else", code="challenge_invalid")
    sch = _svc(c).approve(
        schedule_id, human, passkey=PasskeyAssertion(**v.assertion), at=datetime.fromisoformat(ch.data["at"])
    )
    return detail(sch, c)


@router.post("/schedules/{schedule_id}/pause")
def pause(schedule_id: str, c: Ctx, human: Human) -> sc.ScheduleView:
    return view(_svc(c).pause(schedule_id, human), c)


@router.post("/schedules/{schedule_id}/resume")
def resume(schedule_id: str, c: Ctx, human: Human) -> sc.ScheduleView:
    return view(_svc(c).resume(schedule_id, human), c)


@router.post("/schedules/{schedule_id}/delete")
def delete(schedule_id: str, c: Ctx, human: Human) -> sc.Ok:
    _svc(c).delete(schedule_id, human)
    return sc.Ok(message="schedule deleted")
