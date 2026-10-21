"""Plan lifecycle operations (README section 4). Every change is audited in the same transaction.

Approve, approve-with-edits and reject only accept a HumanActor (invariant 3). Policy runs before any LLM
and its deny is final (invariant 6). Hashes are recomputed at approval and again before dispatch
(invariant 2).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Engine
from sqlmodel import Session
from ulid import ULID

from warden import audit
from warden.actors import Actor, ClaudeActor, HumanActor, SystemActor
from warden.config import Settings
from warden.errors import (
    ApprovalRefused,
    DecidedElsewhere,
    DispatchRefused,
    InputRefused,
    NotHuman,
    SigningError,
)
from warden.gatekeeper.panel import NullPanel, Panel, final_verdict, plan_risk, safe_review
from warden.plans import store
from warden.plans.diff import DiffRow, diff_steps
from warden.plans.hashing import hash_matches, plan_hash
from warden.plans.models import (
    Approval,
    Plan,
    PlanStatus,
    PolicyResult,
    ProposeRequest,
    Risk,
    Step,
    StepEdit,
)
from warden.plans.runs import RunResult, StepOutcome, reduce_run
from warden.plans.state import REVISABLE
from warden.policy.effective import EffectiveRules, effective_rules
from warden.policy.engine import check_plan
from warden.policy.paths import LexicalResolver, PathResolver
from warden.policy.schema import Policy, Targets
from warden.signing import ApprovalKey, ApprovalVerifier, approval_payload
from warden.text import check_free_text, normalize

S = PlanStatus
HASH_PREFIX_MIN = 12


@dataclass(frozen=True)
class Config:
    policy: Policy
    targets: Targets
    settings: Settings
    policy_version: int = 0
    lockdown: bool = False


@dataclass(frozen=True)
class DispatchEnvelope:
    """What the dispatcher sends to the agent (M2): the hashed template plus the signed approval."""

    template: dict[str, object]
    plan_hash: str
    approval: Approval


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _require_human(actor: object) -> HumanActor:
    if not isinstance(actor, HumanActor):
        raise NotHuman("only a human, through an authenticated human channel, can do this")
    return actor


def _violations_detail(result: PolicyResult) -> list[dict[str, object]]:
    return [
        {"code": v.code, "message": v.message, "step": v.step, "group": v.group} for v in result.violations
    ]


class PlanService:
    def __init__(
        self,
        engine: Engine,
        *,
        config: Callable[[], Config],
        approval_key: ApprovalKey,
        panel: Panel | None = None,
        clock: Callable[[], datetime] = _utcnow,
        resolver: PathResolver | None = None,
    ) -> None:
        self._engine = engine
        self._config = config
        self._key = approval_key
        self._verifier: ApprovalVerifier = approval_key.verifier()
        self._panel = panel or NullPanel()
        self._clock = clock
        self._resolver = resolver or LexicalResolver()

    @property
    def resolver(self) -> PathResolver:
        return self._resolver

    # --- helpers ---------------------------------------------------------------------------------------

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None:
            raise ValueError("clock must return timezone-aware datetimes")
        return now

    def _rules(self, target: str) -> EffectiveRules:
        cfg = self._config()
        t = cfg.targets.get(target)
        if t is None:
            raise InputRefused(f"unknown target {target}", code="unknown_target")
        return effective_rules(cfg.policy, t, version=cfg.policy_version, lockdown=cfg.lockdown)

    def _audit(self, s: Session, actor: Actor | str, action: str, subject: str, **detail: Any) -> None:
        label = actor if isinstance(actor, str) else actor.label
        audit.append(s, ts=self._now(), actor=label, action=action, subject=subject, detail=detail)

    def _transition(self, s: Session, plan: Plan, to: PlanStatus, **changes: Any) -> Plan:
        return store.save(s, plan, plan.model_copy(update={"status": to, **changes}))

    def get(self, plan_id: str) -> Plan:
        with Session(self._engine) as s:
            return store.get(s, plan_id)

    def list_plans(
        self, *, statuses: tuple[PlanStatus, ...] | None = None, oldest_first: bool = False
    ) -> list[Plan]:
        with Session(self._engine) as s:
            return store.list_plans(s, statuses=statuses, oldest_first=oldest_first)

    def diff(self, old_id: str, new_id: str) -> list[DiffRow]:
        with Session(self._engine) as s:
            return diff_steps(store.get(s, old_id).steps, store.get(s, new_id).steps)

    # --- propose ---------------------------------------------------------------------------------------

    def _normalise_steps(self, steps: Sequence[Step]) -> tuple[Step, ...]:
        out = []
        for st in steps:
            purpose = normalize(st.purpose)
            check_free_text(purpose, field=f"step {st.n} purpose", max_len=300)
            out.append(
                st.model_copy(
                    update={
                        "command": normalize(st.command),
                        "purpose": purpose,
                        "cwd": normalize(st.cwd),
                        "edited": False,
                    }
                )
            )
        return tuple(out)

    def propose(self, req: ProposeRequest, actor: ClaudeActor | HumanActor) -> Plan:
        """Store the plan, run policy, then gatekeepers. Ends rejected (policy deny) or awaiting_approval."""
        goal = normalize(req.goal)
        check_free_text(goal, field="goal", max_len=500)
        steps = self._normalise_steps(req.steps)
        rules = self._rules(req.target)
        now = self._now()
        previous: Plan | None = None

        with Session(self._engine) as s, s.begin():
            if req.revises is not None:
                previous = store.get(s, req.revises)
                if previous.target != req.target:
                    raise InputRefused("a revision must keep the same target", code="bad_revision")
                if previous.status not in REVISABLE:
                    raise InputRefused(
                        f"{previous.id} is {previous.status.value}; only finished plans can be revised",
                        code="bad_revision",
                    )
            plan = Plan(
                id=f"pln_{ULID()}",
                revises=req.revises,
                goal=goal,
                target=req.target,
                requested_by=actor.label,
                steps=steps,
                hash="",
                status=S.PROPOSED,
                policy_result=PolicyResult(ok=False),
                created_at=now,
                expires_at=now,
            )
            plan = store.insert(s, plan.model_copy(update={"hash": plan_hash(plan)}))
            self._audit(
                s,
                actor,
                "propose_plan",
                plan.id,
                goal=goal,
                target=plan.target,
                revises=plan.revises,
                hash=plan.hash,
                steps=[{"n": x.n, "kind": x.kind.value, "command": x.command, "cwd": x.cwd} for x in steps],
            )
        return self._review(plan, rules, previous, actor=SystemActor())

    def _review(self, plan: Plan, rules: EffectiveRules, previous: Plan | None, *, actor: Actor) -> Plan:
        """Policy first; on pass, gatekeepers; then awaiting_approval. Used by propose and edits."""
        result = check_plan(plan.steps, rules, self._resolver)
        if not result.ok:
            with Session(self._engine) as s, s.begin():
                plan = self._transition(
                    s, store.get(s, plan.id), S.REJECTED, policy_result=result, reject_reason="policy"
                )
                self._audit(
                    s,
                    actor,
                    "policy_deny",
                    plan.id,
                    violations=_violations_detail(result),
                    policy_version=result.policy_version,
                )
            return plan
        verdicts = safe_review(self._panel, plan, rules, previous)
        final = final_verdict(verdicts)
        settings = self._config().settings
        with Session(self._engine) as s, s.begin():
            current = store.get(s, plan.id)
            expires = current.expires_at
            if current.status == S.PROPOSED:
                expires = self._now() + timedelta(minutes=settings.approvals.expiry_min)
            plan = self._transition(
                s,
                current,
                S.AWAITING_APPROVAL,
                policy_result=result,
                gatekeepers=verdicts,
                final_verdict=final,
                expires_at=expires,
            )
            self._audit(
                s,
                actor,
                "review",
                plan.id,
                policy="passed",
                final_verdict=final.value,
                hash=plan.hash,
                gatekeepers=[
                    {"name": v.name, "verdict": v.verdict.value, "unavailable": v.unavailable}
                    for v in verdicts
                ],
            )
        return plan

    # --- human decisions -------------------------------------------------------------------------------

    def _awaiting(self, s: Session, plan_id: str) -> Plan:
        plan = store.get(s, plan_id)
        if plan.status != S.AWAITING_APPROVAL:
            raise DecidedElsewhere(f"{plan_id} is {plan.status.value}, not awaiting approval")
        return plan

    def _expire_if_due(self, plan: Plan) -> bool:
        if self._now() < plan.expires_at:
            return False
        with Session(self._engine) as s, s.begin():
            current = store.get(s, plan.id)
            if (
                current.status in (S.AWAITING_APPROVAL, S.APPROVED, S.HELD)
                and self._now() >= current.expires_at
            ):
                self._transition(s, current, S.EXPIRED)
                self._audit(s, SystemActor(), "expire", plan.id, expired_at=current.expires_at.isoformat())
        return True

    def _check_hash(self, plan: Plan) -> None:
        if not hash_matches(plan.hash, plan_hash(plan)):
            raise ApprovalRefused(f"{plan.id}: stored plan doesn't match its hash", code="hash_mismatch")

    def approve(self, plan_id: str, hash_prefix: str, actor: HumanActor) -> Plan:
        human = _require_human(actor)
        prefix = hash_prefix.strip().lower().removeprefix("sha256:")
        if len(prefix) < HASH_PREFIX_MIN or any(c not in "0123456789abcdef" for c in prefix):
            raise ApprovalRefused(
                f"give at least the first {HASH_PREFIX_MIN} hex characters of the plan hash",
                code="hash_prefix",
            )
        plan = self.get(plan_id)
        if plan.status != S.AWAITING_APPROVAL:
            raise DecidedElsewhere(f"{plan_id} is {plan.status.value}, not awaiting approval")
        if self._expire_if_due(plan):
            raise ApprovalRefused(
                f"{plan_id} expired at {plan.expires_at.isoformat()}; ask Claude to propose again",
                code="expired",
            )
        try:
            self._check_hash(plan)
        except ApprovalRefused:
            with Session(self._engine) as s, s.begin():
                self._audit(
                    s, human, "tamper_detected", plan_id, stored_hash=plan.hash, recomputed=plan_hash(plan)
                )
            raise
        if not plan.hash.removeprefix("sha256:").startswith(prefix):
            raise ApprovalRefused(
                "that hash prefix doesn't match this plan; check you're approving the right plan",
                code="hash_prefix",
            )
        rules = self._rules(plan.target)
        if human.channel == "cli":
            if rules.passkey:
                raise ApprovalRefused(
                    f"{plan.target} is in a group that needs a passkey for every approval; "
                    "approve it in the dashboard or app",
                    code="passkey_required",
                )
            if plan_risk(plan.gatekeepers) == Risk.HIGH:
                raise ApprovalRefused(
                    "high-risk plans need a passkey; approve it in the dashboard or app",
                    code="passkey_required",
                )
        recheck = check_plan(plan.steps, rules, self._resolver)
        if not recheck.ok:
            self._invalidate(plan, recheck)
            raise ApprovalRefused(
                f"{plan_id} no longer passes policy and was invalidated", code="invalidated"
            )

        now = self._now()
        expires = now + timedelta(minutes=self._config().settings.approvals.expiry_min)
        payload = approval_payload(
            plan_hash=plan.hash,
            plan_id=plan.id,
            target=plan.target,
            approved_at=now,
            expires_at=expires,
            by=human.label,
        )
        approval = Approval(by=human.label, at=now, hash=plan.hash, signature=self._key.sign(payload))
        with Session(self._engine) as s, s.begin():
            current = self._awaiting(s, plan_id)
            if current.hash != plan.hash:
                raise DecidedElsewhere(f"{plan_id} changed while you were approving it")
            plan = self._transition(s, current, S.APPROVED, approval=approval, expires_at=expires)
            self._audit(
                s,
                human,
                "approve",
                plan_id,
                hash=plan.hash,
                key_id=approval.signature.key_id,
                final_verdict=plan.final_verdict.value,
                expires_at=expires.isoformat(),
            )
        return plan

    def approve_with_edits(self, plan_id: str, edits: Sequence[StepEdit], actor: HumanActor) -> Plan:
        human = _require_human(actor)
        if not edits:
            raise InputRefused("no edits given", code="no_edits")
        plan = self.get(plan_id)
        if plan.status != S.AWAITING_APPROVAL:
            raise DecidedElsewhere(f"{plan_id} is {plan.status.value}, not awaiting approval")
        if self._expire_if_due(plan):
            raise ApprovalRefused(f"{plan_id} has expired", code="expired")
        self._check_hash(plan)
        by_n = {e.n: normalize(e.command) for e in edits}
        if len(by_n) != len(edits) or not set(by_n) <= {st.n for st in plan.steps}:
            raise InputRefused("each edit must name a different, existing step", code="bad_edit")
        changes = []
        steps = []
        for st in plan.steps:
            if st.n in by_n and by_n[st.n] != st.command:
                changes.append({"n": st.n, "before": st.command, "after": by_n[st.n]})
                steps.append(st.model_copy(update={"command": by_n[st.n], "edited": True}))
            else:
                steps.append(st)
        if not changes:
            raise InputRefused("the edits don't change any command", code="no_edits")
        rules = self._rules(plan.target)
        with Session(self._engine) as s, s.begin():
            current = self._awaiting(s, plan_id)
            edited = current.model_copy(update={"steps": tuple(steps)})
            edited = edited.model_copy(update={"hash": plan_hash(edited)})
            plan = self._transition(
                s,
                current,
                S.REVIEWING,
                steps=edited.steps,
                hash=edited.hash,
                gatekeepers=(),
                final_verdict=final_verdict(()),
            )
            self._audit(
                s,
                human,
                "approve_with_edits",
                plan_id,
                old_hash=current.hash,
                new_hash=plan.hash,
                changes=changes,
            )
        previous = self.get(plan.revises) if plan.revises else None
        return self._review(plan, rules, previous, actor=SystemActor())

    def reject(self, plan_id: str, actor: HumanActor, reason: str | None = None) -> Plan:
        human = _require_human(actor)
        if reason is not None:
            reason = normalize(reason)
            check_free_text(reason, field="reason", max_len=1000, allow_newlines=True)
        with Session(self._engine) as s, s.begin():
            plan = self._transition(
                s, self._awaiting(s, plan_id), S.REJECTED, reject_reason=reason or "rejected"
            )
            self._audit(s, human, "reject", plan_id, reason=reason)
        return plan

    # --- system-driven changes -------------------------------------------------------------------------

    def expire_due(self) -> list[Plan]:
        now = self._now()
        out = []
        with Session(self._engine) as s, s.begin():
            for plan in store.due_for_expiry(s, now):
                out.append(self._transition(s, plan, S.EXPIRED))
                self._audit(s, SystemActor(), "expire", plan.id, expired_at=plan.expires_at.isoformat())
        return out

    def _invalidate(self, plan: Plan, result: PolicyResult) -> Plan:
        first = result.violations[0]
        step = next((x for x in plan.steps if x.n == first.step), None)
        what = f"step {step.n} ({step.command})" if step else "the plan"
        reason = f"Policy v{result.policy_version} denies {what}: {first.message}"
        with Session(self._engine) as s, s.begin():
            current = store.get(s, plan.id)
            new = self._transition(
                s,
                current,
                S.INVALIDATED,
                invalidated_by=result.policy_version,
                invalid_reason=reason,
                policy_result=result,
            )
            self._audit(
                s,
                SystemActor(),
                "plan_invalidated",
                plan.id,
                reason=reason,
                policy_version=result.policy_version,
                violations=_violations_detail(result),
            )
        return new

    def invalidate_against_current_policy(self, target: str | None = None) -> list[Plan]:
        """Re-check waiting and approved plans after a policy change (README 7A step 6)."""
        out = []
        for plan in self.list_plans(statuses=(S.AWAITING_APPROVAL, S.APPROVED, S.HELD)):
            if target is not None and plan.target != target:
                continue
            result = check_plan(plan.steps, self._rules(plan.target), self._resolver)
            if not result.ok:
                out.append(self._invalidate(plan, result))
        return out

    def hold(self, plan_id: str, reason: str) -> Plan:
        with Session(self._engine) as s, s.begin():
            plan = self._transition(s, store.get(s, plan_id), S.HELD, held_reason=reason)
            self._audit(s, SystemActor(), "hold", plan_id, reason=reason)
        return plan

    def release(self, plan_id: str) -> Plan:
        plan = self.get(plan_id)
        if self._expire_if_due(plan):
            raise DispatchRefused(f"{plan_id} expired while held", code="expired")
        with Session(self._engine) as s, s.begin():
            plan = self._transition(s, store.get(s, plan_id), S.APPROVED, held_reason=None)
            self._audit(s, SystemActor(), "release", plan_id)
        return plan

    # --- dispatch --------------------------------------------------------------------------------------

    def _refuse_dispatch(self, plan_id: str, code: str, message: str) -> DispatchRefused:
        with Session(self._engine) as s, s.begin():
            self._audit(s, SystemActor(), "dispatch_refused", plan_id, code=code, message=message)
        return DispatchRefused(message, code=code)

    def validate_for_dispatch(self, plan_id: str) -> DispatchEnvelope:
        """Every check that has to pass before anything is sent to an agent. Fails closed with a reason."""
        plan = self.get(plan_id)
        if plan.status != S.APPROVED or plan.approval is None:
            raise self._refuse_dispatch(
                plan_id, "not_approved", f"{plan_id} is {plan.status.value}, not approved"
            )
        if self._expire_if_due(plan):
            raise self._refuse_dispatch(plan_id, "expired", f"{plan_id}'s approval expired")
        recomputed = plan_hash(plan)
        if not (hash_matches(plan.hash, recomputed) and hash_matches(plan.approval.hash, recomputed)):
            raise self._refuse_dispatch(
                plan_id, "hash_mismatch", f"{plan_id} doesn't match the hash that was approved"
            )
        payload = approval_payload(
            plan_hash=plan.approval.hash,
            plan_id=plan.id,
            target=plan.target,
            approved_at=plan.approval.at,
            expires_at=plan.expires_at,
            by=plan.approval.by,
        )
        try:
            self._verifier.verify(payload, plan.approval.signature)
        except SigningError as exc:
            raise self._refuse_dispatch(plan_id, "bad_signature", f"{plan_id}: {exc.message}") from exc
        try:
            rules = self._rules(plan.target)
        except InputRefused as exc:
            raise self._refuse_dispatch(plan_id, "unknown_target", exc.message) from exc
        result = check_plan(plan.steps, rules, self._resolver)
        if not result.ok:
            self._invalidate(plan, result)
            raise self._refuse_dispatch(plan_id, "policy_violation", f"{plan_id} no longer passes policy")
        return DispatchEnvelope(template=plan.template(), plan_hash=plan.hash, approval=plan.approval)

    def start_run(self, plan_id: str) -> Plan:
        envelope = self.validate_for_dispatch(plan_id)
        with Session(self._engine) as s, s.begin():
            current = store.get(s, plan_id)
            if current.hash != envelope.plan_hash:
                raise DecidedElsewhere(f"{plan_id} changed during dispatch")
            plan = self._transition(s, current, S.RUNNING)
            self._audit(s, SystemActor(), "run_started", plan_id, hash=plan.hash)
        return plan

    def finish_run(self, plan_id: str, outcomes: Sequence[StepOutcome]) -> Plan:
        with Session(self._engine) as s, s.begin():
            current = store.get(s, plan_id)
            if current.status != S.RUNNING:
                raise DecidedElsewhere(f"{plan_id} is {current.status.value}, not running")
            result: RunResult = reduce_run(current.steps, outcomes)
            plan = self._transition(
                s,
                current,
                result.status,
                step_results=result.steps,
                failed_at=result.failed_at,
                fail_reason=result.fail_reason,
            )
            for r in result.steps:
                if r.status.value in ("succeeded", "failed", "cancelled"):
                    self._audit(
                        s,
                        f"agent:{plan.target}",
                        "step_ok" if r.status.value == "succeeded" else "step_failed",
                        f"{plan_id} · step {r.n}",
                        exit_code=r.exit_code,
                        reason=r.reason,
                    )
            self._audit(
                s,
                SystemActor(),
                "run_finished",
                plan_id,
                status=plan.status.value,
                failed_at=plan.failed_at,
                fail_reason=plan.fail_reason,
            )
        return plan
