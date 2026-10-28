"""The top bar: agents, gatekeepers, running plans, lockdown (README 17.3 Layout); schedules until M7."""

from __future__ import annotations

from fastapi import APIRouter
from sqlmodel import Session

from warden.api import schemas as sc
from warden.api import views
from warden.api.auth import Ctx, SessionDep
from warden.gatekeeper.config import load_gatekeeper
from warden.passkeys import active
from warden.plans.models import PlanStatus
from warden.policy_dist import publish as publishing

router = APIRouter(tags=["status"])


@router.get("/status")
def status(c: Ctx, me: SessionDep) -> sc.StatusView:
    facts = views.Facts(c)
    plans = c.plans.list_plans()
    gk = load_gatekeeper(c.config_dir / "gatekeeper.yaml")
    last: dict[str, tuple[bool, str]] = {}
    for p in plans:  # newest first: the latest verdict per reviewer says whether it's answering
        for g in p.gatekeepers:
            last.setdefault(g.name, (g.unavailable, g.summary))
    gks = []
    for r in gk.reviewers:
        seen = last.get(r.name)
        state = "unknown" if seen is None else ("unavailable" if seen[0] else "up")
        gks.append(
            sc.GatekeeperStatus(
                name=r.name, model=r.model, state=state, why=seen[1] if seen and seen[0] else None
            )
        )
    with Session(c.engine) as s:
        pending = publishing.open_pending(s)
    names = [t.name for t in facts.cfg.targets.targets]
    return sc.StatusView(
        me=me.name,
        policy_version=max(facts.latest.values(), default=0),
        lockdown=facts.lockdown,
        e2e=facts.cfg.e2e,
        agents=[facts.agent_view(n) for n in names],
        gatekeepers=gks,
        running=[p.id for p in plans if p.status == PlanStatus.RUNNING],
        awaiting=sum(p.status in views.PENDING for p in plans),
        pending_publish=pending.version if pending else None,
        language=facts.cfg.settings.ui.language,
        passkeys=len(active(c.engine)),
        schedules_awaiting=sum(s.status == "awaiting_approval" for s in c.schedules.all())
        if c.schedules
        else 0,
    )
