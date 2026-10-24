"""Plans, approvals and the kill switch (README 17.3 Approvals, Plans, Plan detail)."""

from __future__ import annotations

import json
from datetime import datetime

from fastapi import APIRouter, Query
from sqlmodel import Session

from warden.api import schemas as sc
from warden.api import views
from warden.api.auth import Ctx, Human
from warden.dispatch import outputs
from warden.dispatch.server import effective_cap_bytes
from warden.errors import ApprovalRefused
from warden.passkeys import PasskeyRefused, active, challenge_for
from warden.plans.models import PasskeyAssertion, StepEdit
from warden.signing import approval_message

router = APIRouter(tags=["plans"])


def _matches(p: object, q: str) -> bool:
    q = q.lower()
    hay = [p.id, p.goal, p.target, p.requested_by, *(s.command for s in p.steps)]  # type: ignore[attr-defined]
    return any(q in h.lower() for h in hay)


@router.get("/plans")
def list_plans(
    c: Ctx, _: Human, filter: str = "all", q: str = Query(default="", max_length=200)
) -> sc.PlanList:
    facts = views.Facts(c)
    allp = [p for p in c.plans.list_plans() if not q or _matches(p, q)]
    counts = {"all": len(allp)} | {k: sum(p.status in v for p in allp) for k, v in views.FILTERS.items()}
    shown = allp if filter == "all" else [p for p in allp if p.status in views.FILTERS.get(filter, ())]
    return sc.PlanList(plans=[views.summary(p, facts) for p in shown], counts=counts)


@router.get("/approvals")
def approvals(c: Ctx, _: Human) -> sc.PlanList:
    """Pending plans, oldest first, plus the five most recently decided."""
    facts = views.Facts(c)
    pending = c.plans.list_plans(statuses=views.PENDING, oldest_first=True)
    rows = []
    for p in pending:
        s = views.summary(p, facts, with_agent=True)
        s.changed_steps = views.changed_steps(c, p)
        rows.append(s)
    decided = [p for p in c.plans.list_plans() if p.status not in views.PENDING][:5]
    return sc.PlanList(plans=rows + [views.summary(p, facts) for p in decided], counts={"pending": len(rows)})


@router.get("/plans/{plan_id}")
def get_plan(plan_id: str, c: Ctx, _: Human) -> sc.PlanDetail:
    return views.detail(c, c.plans.get(plan_id), views.Facts(c))


@router.get("/plans/{plan_id}/output")
def plan_output(plan_id: str, c: Ctx, _: Human) -> sc.OutputView:
    p = c.plans.get(plan_id)
    with Session(c.engine) as s:
        rows = outputs.read(s, plan_id)
    return sc.OutputView(
        plan_id=plan_id,
        chunks=[sc.OutputChunk(n=r.n, seq=r.seq, stream=r.stream, data=r.data) for r in rows],
        cap_bytes=effective_cap_bytes(c.config(), p.target),
    )


@router.post("/plans/{plan_id}/approval/options")
def approval_options(plan_id: str, c: Ctx, human: Human) -> sc.ApproveOptions:
    """Fixes the approval window now and returns a passkey request whose challenge is that approval."""
    p = c.plans.get(plan_id)
    reasons = c.plans.passkey_reasons(p)
    at = c.now()
    payload = c.plans.approval_payload_for(p, human, at)
    if not active(c.engine):
        if reasons:
            raise PasskeyRefused(
                "approving this plan needs a passkey, and none is registered", code="passkey_required"
            )
        return sc.ApproveOptions(needs_passkey=False, reasons=[])
    cid, raw = c.passkeys.assertion_options(
        "approve",
        plan_id,
        now=at,
        challenge=challenge_for(approval_message(payload)),
        data={"at": at.isoformat(), "by": human.label, "hash": p.hash},
    )
    return sc.ApproveOptions(
        needs_passkey=bool(reasons), reasons=reasons, challenge_id=cid, options=json.loads(raw)
    )


@router.post("/plans/{plan_id}/approve")
def approve(plan_id: str, body: sc.ApproveIn, c: Ctx, human: Human) -> sc.PlanDetail:
    passkey, at = None, None
    if body.credential is not None:
        if not body.challenge_id:
            raise PasskeyRefused("missing challenge", code="challenge_invalid")
        v, ch = c.passkeys.verify(body.challenge_id, body.credential, "approve", plan_id, now=c.now())
        if ch.data.get("by") != human.label or ch.data.get("hash") != body.hash:
            raise ApprovalRefused(
                "that passkey approval was for someone or something else", code="challenge_invalid"
            )
        passkey = PasskeyAssertion(**v.assertion)
        at = datetime.fromisoformat(ch.data["at"])
    p = c.plans.approve(plan_id, body.hash, human, passkey=passkey, at=at)
    return views.detail(c, p, views.Facts(c))


@router.post("/plans/{plan_id}/edits")
def approve_with_edits(plan_id: str, body: sc.EditsIn, c: Ctx, human: Human) -> sc.PlanDetail:
    p = c.plans.approve_with_edits(plan_id, [StepEdit(n=e.n, command=e.command) for e in body.edits], human)
    return views.detail(c, p, views.Facts(c))


@router.post("/plans/{plan_id}/reject")
def reject(plan_id: str, body: sc.RejectIn, c: Ctx, human: Human) -> sc.PlanDetail:
    p = c.plans.reject(plan_id, human, body.reason or None)
    return views.detail(c, p, views.Facts(c))


@router.post("/plans/{plan_id}/kill")
async def kill(plan_id: str, c: Ctx, human: Human) -> sc.Ok:
    await c.dispatcher.kill(plan_id, human.label)
    return sc.Ok(message="kill switch sent")
