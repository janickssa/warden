"""Turn plans, agents and audit entries into the dashboard's shapes (`schemas.py`)."""

from __future__ import annotations

import json
from typing import Any

from sqlmodel import Session

from warden.api import schemas as sc
from warden.api.context import ApiContext
from warden.dispatch import outputs
from warden.gatekeeper.panel import NO_REVIEWERS, final_verdict, plan_risk
from warden.passkeys import active
from warden.plans import diagnosis
from warden.plans.models import Plan, PlanStatus, Verdict
from warden.policy.effective import effective_rules
from warden.policy_dist import bundle as bundles
from warden.policy_dist.publish import lockdown_state

S = PlanStatus
PENDING = (S.AWAITING_APPROVAL, S.REVIEWING)
DECIDED_AT = (S.APPROVED, S.HELD, S.RUNNING, S.SUCCEEDED, S.FAILED, S.CANCELLED)
FILTERS: dict[str, tuple[PlanStatus, ...]] = {
    "awaiting": (S.AWAITING_APPROVAL, S.REVIEWING),
    "approved_running": (S.APPROVED, S.HELD, S.RUNNING),
    "succeeded": (S.SUCCEEDED,),
    "failed": (S.FAILED,),
    "invalidated": (S.INVALIDATED,),
    "closed": (S.REJECTED, S.EXPIRED, S.CANCELLED),
}
OUTPUT_TAIL = 8000


def iso(dt: Any) -> str:
    return str(dt.isoformat()) if hasattr(dt, "isoformat") else str(dt)


class Facts:
    """Per-request snapshot: latest versions, lockdown, connected agents. Built once, read many times."""

    def __init__(self, ctx: ApiContext) -> None:
        self.ctx = ctx
        cfg = ctx.config()
        self.cfg = cfg
        with Session(ctx.engine) as s:
            self.lockdown = lockdown_state(s)
            self.latest = {
                t.name: (b["version"] if (b := bundles.latest(s, t.name)) else 0) for t in cfg.targets.targets
            }
        self.agents = {a.name: a for a in ctx.registry.list() if a.status == "active"}
        self.revoked = {a.name for a in ctx.registry.list() if a.status == "revoked"} - set(self.agents)
        self.sessions = dict(ctx.dispatcher.sessions)

    def groups_of(self, target: str) -> list[str]:
        return sorted(g for g, grp in self.cfg.policy.groups.items() if target in grp.members)

    def agent_state(self, target: str) -> sc.AgentState:
        latest = self.latest.get(target, 0)
        sess = self.sessions.get(target)
        if self.lockdown:
            return sc.AgentState(
                state="lockdown",
                latest_version=latest,
                policy_version=sess.policy_version if sess else None,
                warning="Lockdown active. You can review and approve this plan; nothing state-changing runs "
                "until lockdown is lifted.",
            )
        if target in self.revoked:
            return sc.AgentState(
                state="revoked",
                latest_version=latest,
                warning=f"{target}’s agent was revoked. Enroll a new agent before this can run.",
            )
        if target not in self.agents:
            return sc.AgentState(
                state="missing", latest_version=latest, warning=f"No agent is enrolled for {target} yet."
            )
        if sess is None:
            return sc.AgentState(
                state="offline",
                latest_version=latest,
                policy_version=self.agents[target].policy_version,
                warning=f"{target}’s agent is offline. You can review and approve; it runs when the agent "
                f"reconnects and is on policy v{latest}.",
            )
        if sess.policy_version < latest:
            return sc.AgentState(
                state="behind",
                latest_version=latest,
                policy_version=sess.policy_version,
                warning=f"{target}’s agent is on policy v{sess.policy_version}, latest is v{latest}. You can "
                "review and approve; the dispatcher holds it until the agent is current.",
            )
        return sc.AgentState(state="current", latest_version=latest, policy_version=sess.policy_version)

    def agent_view(self, name: str) -> sc.AgentView:
        t = self.cfg.targets.get(name)
        row = self.agents.get(name) or next((a for a in self.ctx.registry.list() if a.name == name), None)
        sess = self.sessions.get(name)
        latest = self.latest.get(name, 0)
        if row is None:
            status = "not_enrolled"
        elif row.status == "revoked":
            status = "revoked"
        elif sess is None:
            status = "offline"
        elif sess.policy_version < latest:
            status = "behind"
        else:
            status = "online"
        return sc.AgentView(
            name=name,
            id=row.id if row else None,
            kind=t.kind if t else (row.kind if row else "?"),
            status=status,
            online=sess is not None,
            remote_addr=sess.remote if sess else (row.remote_addr if row else None),
            last_seen=row.last_seen if row else None,
            agent_version=(sess.agent_version if sess else None) or (row.agent_version if row else None),
            policy_version=sess.policy_version if sess else (row.policy_version if row else None),
            latest_version=latest,
            workspace_roots=list(t.workspace_roots) if t else [],
            groups=self.groups_of(name),
            enrolled_at=row.enrolled_at if row else None,
            revoked_at=row.revoked_at if row else None,
            fingerprint=row.fingerprint if row else None,
        )


def _risk(p: Plan) -> Any:
    r = plan_risk(p.gatekeepers)
    return r.value if r else None


def summary(p: Plan, facts: Facts, *, with_agent: bool = False) -> sc.PlanSummary:
    changed = None
    return sc.PlanSummary(
        id=p.id,
        status=p.status.value,
        goal=p.goal,
        target=p.target,
        revises=p.revises,
        requested_by=p.requested_by,
        steps=len(p.steps),
        created_at=iso(p.created_at),
        expires_at=iso(p.expires_at),
        risk=_risk(p),
        final_verdict=p.final_verdict.value,
        gatekeeper_unavailable=any(g.unavailable for g in p.gatekeepers),
        held_reason=p.held_reason,
        failed_at=p.failed_at,
        fail_reason=p.fail_reason,
        invalidated_by=p.invalidated_by,
        changed_steps=changed,
        decided_at=iso(p.approval.at) if p.approval else None,
        agent=facts.agent_state(p.target) if with_agent else None,
    )


def changed_steps(ctx: ApiContext, p: Plan) -> int | None:
    if not p.revises:
        return None
    try:
        rows = ctx.plans.diff(p.revises, p.id)
    except Exception:
        return None
    return sum(1 for r in rows if r.op == "added")


def _output_text(ctx: ApiContext, plan_id: str, n: int) -> str:
    with Session(ctx.engine) as s:
        return "".join(r.data for r in outputs.read(s, plan_id, n))


def detail(ctx: ApiContext, p: Plan, facts: Facts) -> sc.PlanDetail:
    base = summary(p, facts, with_agent=True).model_dump()
    base["changed_steps"] = changed_steps(ctx, p)
    results = {r.n: r for r in p.step_results}
    steps = []
    for st in p.steps:
        r = results.get(st.n)
        steps.append(
            sc.StepView(
                n=st.n,
                kind=st.kind.value,
                command=st.command,
                purpose=st.purpose,
                cwd=st.cwd,
                timeout_s=st.timeout_s,
                expect_exit=st.expect_exit,
                edited=st.edited,
                status=r.status.value if r else None,
                exit_code=r.exit_code if r else None,
                reason=r.reason if r else None,
                duration_s=r.duration_s if r else None,
                output_truncated=r.output_truncated if r else False,
            )
        )
    reviewers = [
        sc.Reviewer(
            name=g.name,
            model=g.model,
            verdict=g.verdict.value,
            risk=g.risk.value,
            summary=g.summary,
            unavailable=g.unavailable,
            notes={s.n: s.note for s in g.per_step if not s.matches_goal or s.note},
        )
        for g in p.gatekeepers
    ]
    answered = {g.verdict for g in p.gatekeepers if not g.unavailable and g.name not in (NO_REVIEWERS,)}
    previous = None
    diff: list[sc.DiffRowView] = []
    if p.revises:
        try:
            prev = ctx.plans.get(p.revises)
            prev_results = {r.n: r.status.value for r in prev.step_results}
            err = _output_text(ctx, prev.id, prev.failed_at)[-OUTPUT_TAIL:] if prev.failed_at else None
            previous = sc.PreviousPlan(
                id=prev.id,
                status=prev.status.value,
                failed_at=prev.failed_at,
                fail_reason=prev.fail_reason,
                error_output=err,
            )
            diff = [
                sc.DiffRowView(
                    op=r.op,
                    old_n=r.old_n,
                    new_n=r.new_n,
                    old_command=r.old_command,
                    new_command=r.new_command,
                    old_status=prev_results.get(r.old_n) if r.old_n else None,
                )
                for r in ctx.plans.diff(prev.id, p.id)
            ]
        except Exception:
            previous = None
    diags = [
        sc.DiagnosisView(
            id=d.id,
            by=d.client,
            note=d.note,
            created_at=d.created_at,
            evidence=[
                sc.Evidence(
                    audit_id=e.audit_id,
                    command=e.command,
                    exit_code=e.exit_code,
                    output=e.output[-OUTPUT_TAIL:],
                )
                for e in d.evidence
            ],
        )
        for d in diagnosis.for_plan(ctx.engine, p.id)
    ]
    revisions = [x.id for x in ctx.plans.list_plans() if x.revises == p.id]
    approval = None
    if p.approval:
        approval = sc.ApprovalView(
            by=p.approval.by,
            at=iso(p.approval.at),
            hash=p.approval.hash,
            key_id=p.approval.signature.key_id,
            passkey=p.approval.passkey.credential_id if p.approval.passkey else None,
        )
    return sc.PlanDetail(
        **base,
        hash=p.hash,
        policy_ok=p.policy_result.ok,
        policy_version=p.policy_result.policy_version,
        violations=[sc.Violation(**v.model_dump()) for v in p.policy_result.violations],
        reviewers=reviewers,
        reviewers_disagree=len(answered) > 1,
        step_list=steps,
        approval=approval,
        invalid_reason=p.invalid_reason,
        reject_reason=p.reject_reason,
        previous=previous,
        diff=diff,
        diagnoses=diags,
        revisions=revisions,
        passkey_reasons=ctx.plans.passkey_reasons(p) if p.status in PENDING else [],
        passkeys_registered=len(active(ctx.engine)),
        e2e=facts.cfg.e2e,
    )


def rules_summary(ctx: ApiContext, target: str) -> dict[str, Any]:
    cfg = ctx.config()
    t = cfg.targets.get(target)
    if t is None:
        return {}
    r = effective_rules(cfg.policy, t)
    return {"read_only": r.read_only_mode.label, "passkey": r.passkey, "unanimous": r.unanimous}


def final_of(p: Plan) -> Verdict:
    return final_verdict(p.gatekeepers)


def detail_json(raw: str, limit: int = 2000) -> dict[str, Any]:
    d: dict[str, Any] = json.loads(raw)
    out: dict[str, Any] = {}
    for k, v in d.items():
        long = isinstance(v, str) and len(v) > limit
        out[k] = f"{v[:limit]}… ({len(v) - limit} more characters)" if long else v
    return out
