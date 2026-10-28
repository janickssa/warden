"""Schedules (README 11, DECISIONS M7): create from a succeeded plan, approve with a passkey, run, report.

Only a human creates, approves, pauses, resumes or deletes a schedule; there is no MCP tool for any of it.
The approved grant (`grant.py`) is what agents check on every run, so nothing here can widen a schedule:
the steps, target, cron and window are fixed at approval. A changed template is a new schedule.

States: awaiting_approval → active ⇄ paused; active → stopped (a run failed: notify and stop), expired,
invalidated (policy now denies the steps); any → deleted. Stopped, expired, invalidated and deleted are
final: make a new schedule from a plan that works.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import TypeAdapter
from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, col, select
from ulid import ULID

from warden import audit, notify
from warden.actors import HumanActor
from warden.errors import ApprovalRefused, InputRefused, NotFound, NotHuman, SigningError, WardenError
from warden.keys import b64url, unb64url
from warden.plans.models import Approval, ApprovalSignature, PasskeyAssertion, Plan, PlanStatus, Step
from warden.plans.service import DispatchEnvelope, PlanService
from warden.schedules import grant
from warden.schedules.cron import Cron, describe
from warden.signing import SCHEDULE_DOMAIN, ApprovalKey
from warden.text import normalize

_STEPS: TypeAdapter[tuple[Step, ...]] = TypeAdapter(tuple[Step, ...])
Status = Literal["awaiting_approval", "active", "paused", "stopped", "expired", "invalidated", "deleted"]
FINAL = ("stopped", "expired", "invalidated", "deleted")
LIVE = ("awaiting_approval", "active", "paused")
EXPIRY_DAYS = (30, 90, 180)
NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
CHALLENGE_MAX_AGE_S = 180


class ScheduleRefused(WardenError):
    code = "schedule_refused"


class ScheduleRow(SQLModel, table=True):
    __tablename__ = "schedules"

    id: str = Field(primary_key=True)
    name: str = Field(index=True)
    target: str
    goal: str
    steps: str  # JSON list of Step
    template_hash: str
    cron: str
    expiry_days: int
    on_failure: str = "notify_and_stop"
    source_plan: str
    created_by: str
    created_at: str
    status: str = Field(index=True)
    approved_by: str | None = None
    approved_at: str | None = None
    expires_at: str | None = None
    signature: str | None = None  # JSON ApprovalSignature
    passkey: str | None = None  # JSON PasskeyAssertion
    last_slot: str | None = None
    last_run_id: str | None = None
    last_result: str | None = None  # succeeded | failed | missed
    last_detail: str | None = None
    last_run_at: str | None = None
    status_reason: str | None = None
    updated_at: str


@dataclass(frozen=True)
class Schedule:
    row: ScheduleRow

    @property
    def id(self) -> str:
        return self.row.id

    @property
    def status(self) -> str:
        return self.row.status

    @property
    def steps(self) -> tuple[Step, ...]:
        return _STEPS.validate_json(self.row.steps)

    @property
    def cron(self) -> Cron:
        return Cron.parse(self.row.cron)

    @property
    def when(self) -> str:
        return describe(self.cron)

    def template(self) -> dict[str, object]:
        return grant.template(
            schedule_id=self.id, target=self.row.target, goal=self.row.goal, steps=self.steps
        )

    @property
    def approved_at(self) -> datetime | None:
        return datetime.fromisoformat(self.row.approved_at) if self.row.approved_at else None

    @property
    def expires_at(self) -> datetime | None:
        return datetime.fromisoformat(self.row.expires_at) if self.row.expires_at else None

    @property
    def last_slot(self) -> datetime | None:
        return datetime.fromisoformat(self.row.last_slot) if self.row.last_slot else None

    def payload(self) -> dict[str, object]:
        if self.approved_at is None or self.expires_at is None or self.row.approved_by is None:
            raise ScheduleRefused(f"{self.id} isn't approved", code="not_approved")
        return grant.payload(
            schedule_id=self.id,
            template_hash=self.row.template_hash,
            target=self.row.target,
            cron=self.row.cron,
            approved_at=self.approved_at,
            expires_at=self.expires_at,
            by=self.row.approved_by,
        )

    def approval(self) -> Approval:
        """The grant as a run plan's approval (shown in the dashboard and audit; agents check the grant)."""
        if self.row.signature is None or self.approved_at is None or self.row.approved_by is None:
            raise ScheduleRefused(f"{self.id} isn't approved", code="not_approved")
        return Approval(
            by=self.row.approved_by,
            at=self.approved_at,
            hash=self.row.template_hash,
            signature=ApprovalSignature.model_validate_json(self.row.signature),
            passkey=PasskeyAssertion.model_validate_json(self.row.passkey) if self.row.passkey else None,
        )

    def next_slot(self, now: datetime) -> datetime | None:
        if self.status != "active" or self.expires_at is None:
            return None
        after = max(now, self.last_slot or now)
        nxt = self.cron.next_after(after)
        return nxt if nxt is not None and nxt < self.expires_at else None


def _human(actor: object) -> HumanActor:
    if not isinstance(actor, HumanActor):
        raise NotHuman("only a human can change schedules")
    return actor


class ScheduleService:
    def __init__(
        self,
        engine: Engine,
        plans: PlanService,
        *,
        approval_key: ApprovalKey,
        default_days: Callable[[], int],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._plans = plans
        self._key = approval_key
        self._verifier = approval_key.verifier()
        self._default_days = default_days
        self._clock = clock
        plans.scheduled_dispatch = self.envelope_for

    # --- reading ----------------------------------------------------------------------------------------

    def get(self, schedule_id: str) -> Schedule:
        with Session(self._engine, expire_on_commit=False) as s:
            row = s.get(ScheduleRow, schedule_id)
        if row is None or row.status == "deleted":
            raise NotFound(f"no schedule {schedule_id}")
        return Schedule(row)

    def all(self, *, include_final: bool = True) -> list[Schedule]:
        with Session(self._engine, expire_on_commit=False) as s:
            rows = s.exec(select(ScheduleRow).order_by(col(ScheduleRow.name))).all()
        return [Schedule(r) for r in rows if r.status != "deleted" and (include_final or r.status in LIVE)]

    def runs(self, schedule_id: str, limit: int = 20) -> list[Plan]:
        return [p for p in self._plans.list_plans() if p.schedule_id == schedule_id][:limit]

    # --- writing ----------------------------------------------------------------------------------------

    def _audit(self, s: Session, actor: str, action: str, subject: str, **detail: Any) -> None:
        audit.append(s, ts=self._clock(), actor=actor, action=action, subject=subject, detail=detail)

    def _update(self, s: Session, schedule_id: str, *, expect: Sequence[str], **changes: Any) -> ScheduleRow:
        row = s.get(ScheduleRow, schedule_id)
        if row is None or row.status == "deleted":
            raise NotFound(f"no schedule {schedule_id}")
        if row.status not in expect:
            raise ScheduleRefused(f"{schedule_id} is {row.status.replace('_', ' ')}", code="wrong_state")
        for k, v in changes.items():
            setattr(row, k, v)
        row.updated_at = self._clock().isoformat()
        s.add(row)
        s.flush()
        return row

    def create(self, plan_id: str, *, name: str, cron: str, days: int | None, actor: HumanActor) -> Schedule:
        """ "Save as schedule" on a succeeded plan. It needs its own approval before it can run."""
        human = _human(actor)
        name = normalize(name.strip())
        if not NAME.match(name):
            raise InputRefused("name: lowercase letters, numbers and dashes, at most 63", code="bad_name")
        c = Cron.parse(cron)
        days = self._default_days() if days is None else days
        if days not in EXPIRY_DAYS:
            raise InputRefused("a schedule expires after 30, 90 or 180 days", code="bad_expiry")
        plan = self._plans.get(plan_id)
        if plan.status != PlanStatus.SUCCEEDED or plan.schedule_id is not None:
            raise ScheduleRefused(
                "only a plan that succeeded (and isn't itself a scheduled run) can become a schedule",
                code="not_succeeded",
            )
        result = self._plans.check_steps(plan.target, plan.steps)
        if not result.ok:
            raise ScheduleRefused("the current policy denies these steps", code="policy_violation")
        now = self._clock()
        sid = f"sch_{ULID()}"
        steps = [st.model_copy(update={"edited": False}) for st in plan.steps]
        tpl = grant.template(schedule_id=sid, target=plan.target, goal=plan.goal, steps=steps)
        row = ScheduleRow(
            id=sid,
            name=name,
            target=plan.target,
            goal=plan.goal,
            steps=json.dumps([st.model_dump(mode="json") for st in steps]),
            template_hash=grant.template_hash(tpl),
            cron=c.expr,
            expiry_days=days,
            source_plan=plan.id,
            created_by=human.label,
            created_at=now.isoformat(),
            status="awaiting_approval",
            updated_at=now.isoformat(),
        )
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            if s.exec(
                select(ScheduleRow).where(col(ScheduleRow.name) == name, col(ScheduleRow.status).in_(LIVE))
            ).first():
                raise InputRefused(f"a schedule named {name} already exists", code="name_taken")
            s.add(row)
            self._audit(
                s,
                human.label,
                "schedule_created",
                sid,
                name=name,
                cron=c.expr,
                expiry_days=days,
                source_plan=plan.id,
                template_hash=row.template_hash,
                target=plan.target,
            )
        return Schedule(row)

    def payload_for(self, schedule_id: str, human: HumanActor, at: datetime) -> dict[str, object]:
        """The grant the human's passkey signs (its SHA-256 is the WebAuthn challenge)."""
        sch = self.get(schedule_id)
        if sch.status != "awaiting_approval":
            raise ScheduleRefused(f"{schedule_id} is {sch.status.replace('_', ' ')}", code="wrong_state")
        return grant.payload(
            schedule_id=sch.id,
            template_hash=sch.row.template_hash,
            target=sch.row.target,
            cron=sch.row.cron,
            approved_at=at,
            expires_at=at + timedelta(days=sch.row.expiry_days),
            by=human.label,
        )

    def approve(
        self, schedule_id: str, actor: HumanActor, *, passkey: PasskeyAssertion, at: datetime
    ) -> Schedule:
        """Approve with the approval key plus the human's passkey (always: it's a standing approval).

        `passkey` must already be verified against a registered passkey by the caller; here we check its
        challenge is this exact grant, so an assertion for another schedule, window or approver fails."""
        human = _human(actor)
        now = self._clock()
        if abs((now - at).total_seconds()) > CHALLENGE_MAX_AGE_S:
            raise ApprovalRefused("the passkey approval is too old; approve again", code="challenge_invalid")
        payload = self.payload_for(schedule_id, human, at)
        expected = b64url(hashlib.sha256(grant.message(payload)).digest())
        try:
            signed = json.loads(unb64url(passkey.client_data_json))["challenge"]
        except (ValueError, KeyError, TypeError) as exc:
            raise ApprovalRefused("malformed passkey approval", code="challenge_invalid") from exc
        if signed != expected:
            raise ApprovalRefused(
                "the passkey signed something else than this schedule", code="challenge_invalid"
            )
        sch = self.get(schedule_id)
        if grant.template_hash(sch.template()) != sch.row.template_hash:
            raise ApprovalRefused(f"{schedule_id} doesn't match its stored hash", code="hash_mismatch")
        result = self._plans.check_steps(sch.row.target, sch.steps)
        if not result.ok:
            raise ScheduleRefused("the current policy denies these steps", code="policy_violation")
        sig = self._key.sign_grant(payload)
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            row = self._update(
                s,
                schedule_id,
                expect=("awaiting_approval",),
                status="active",
                approved_by=human.label,
                approved_at=at.isoformat(),
                expires_at=str(payload["expires_at"]),
                signature=sig.model_dump_json(),
                passkey=passkey.model_dump_json(),
            )
            self._audit(
                s,
                human.label,
                "schedule_approved",
                schedule_id,
                template_hash=row.template_hash,
                cron=row.cron,
                expires_at=row.expires_at,
                key_id=sig.key_id,
                passkey=passkey.credential_id,
            )
        return Schedule(row)

    def pause(self, schedule_id: str, actor: HumanActor) -> Schedule:
        human = _human(actor)
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            row = self._update(s, schedule_id, expect=("active",), status="paused")
            self._audit(s, human.label, "schedule_paused", schedule_id)
        return Schedule(row)

    def resume(self, schedule_id: str, actor: HumanActor) -> Schedule:
        """No new approval: the steps, target, cron and window are the approved ones and can't change."""
        human = _human(actor)
        sch = self.get(schedule_id)
        if sch.expires_at is not None and sch.expires_at <= self._clock():
            self._finalise(sch, "expired", "the approval window ended")
            raise ScheduleRefused(f"{schedule_id} has expired", code="expired")
        with Session(self._engine, expire_on_commit=False) as s, s.begin():
            # Skip what was due while paused: the next run is the next slot from now.
            row = self._update(
                s, schedule_id, expect=("paused",), status="active", last_slot=self._clock().isoformat()
            )
            self._audit(s, human.label, "schedule_resumed", schedule_id)
        return Schedule(row)

    def delete(self, schedule_id: str, actor: HumanActor) -> None:
        human = _human(actor)
        with Session(self._engine) as s, s.begin():
            self._update(s, schedule_id, expect=(*LIVE, *FINAL[:3]), status="deleted")
            self._audit(s, human.label, "schedule_deleted", schedule_id)

    def _finalise(
        self, sch: Schedule, status: Status, reason: str, *, kind: notify.Kind | None = None
    ) -> None:
        with Session(self._engine) as s, s.begin():
            row = s.get(ScheduleRow, sch.id)
            if row is None or row.status in FINAL:
                return
            row.status, row.status_reason, row.updated_at = status, reason, self._clock().isoformat()
            s.add(row)
            self._audit(s, "scheduler", f"schedule_{status}", sch.id, reason=reason)
            if kind:
                notify.add(
                    s,
                    kind=kind,
                    title=f"■ {row.name} stopped",
                    body=reason,
                    subject=sch.id,
                    now=self._clock(),
                )

    # --- running ----------------------------------------------------------------------------------------

    def due(self, now: datetime) -> list[tuple[Schedule, datetime]]:
        """Active schedules with a slot in the last 15 minutes that hasn't fired. Expires what's done."""
        out = []
        for sch in self.all(include_final=False):
            if sch.status != "active" or sch.approved_at is None or sch.expires_at is None:
                continue
            if sch.expires_at <= now:
                self._finalise(sch, "expired", "the approval window ended")
                continue
            floor = max(sch.approved_at, now - grant.LATE)
            if sch.last_slot is not None:
                floor = max(floor, sch.last_slot + timedelta(seconds=1))
            slot = sch.cron.latest_at_or_before(now, not_before=floor)
            if slot is not None and slot < sch.expires_at:
                out.append((sch, slot))
        return out

    def mark_fired(self, sch: Schedule, slot: datetime, run_id: str | None) -> None:
        with Session(self._engine) as s, s.begin():
            self._update(
                s,
                sch.id,
                expect=("active",),
                last_slot=slot.isoformat(),
                last_run_id=run_id,
                last_run_at=slot.isoformat(),
            )

    def missed(self, sch: Schedule, slot: datetime, reason: str, run_id: str | None = None) -> None:
        with Session(self._engine) as s, s.begin():
            self._update(
                s,
                sch.id,
                expect=("active",),
                last_slot=slot.isoformat(),
                last_run_id=run_id,
                last_result="missed",
                last_detail=reason,
                last_run_at=slot.isoformat(),
            )
            if run_id is None:
                self._audit(s, "scheduler", "schedule_missed", sch.id, slot=slot.isoformat(), reason=reason)

    def run_missed(self, run: Plan, reason: str) -> None:
        """A run plan that was created but couldn't start: expire it if it's still approved, record a miss."""
        if run.schedule_id is None or run.slot is None:
            return
        current = self._plans.get(run.id)
        if current.status == PlanStatus.APPROVED:
            self._plans.expire_run(run.id, reason)
        try:
            sch = self.get(run.schedule_id)
        except NotFound:
            return
        if sch.status == "active":
            self.missed(sch, run.slot, reason, run.id)

    def recheck_policy(self) -> list[str]:
        """After a publish: a schedule whose steps the new policy denies is invalidated and notified."""
        out = []
        for sch in self.all(include_final=False):
            try:
                result = self._plans.check_steps(sch.row.target, sch.steps)
            except InputRefused:
                continue
            if not result.ok:
                why = "; ".join(v.message for v in result.violations[:3]) or "the policy denies these steps"
                self._finalise(sch, "invalidated", why, kind="schedule_stopped")
                out.append(sch.id)
        return out

    def record_result(self, plan: Plan) -> None:
        """A scheduled run finished: report it; a failure stops the schedule (on_failure: notify_and_stop)."""
        if plan.schedule_id is None:
            return
        try:
            sch = self.get(plan.schedule_id)
        except NotFound:
            return
        ok = plan.status == PlanStatus.SUCCEEDED
        duration = sum((r.duration_s or 0) for r in plan.step_results)
        detail = (
            f"{round(duration)} s"
            if ok
            else f"step {plan.failed_at} · {plan.fail_reason or plan.status.value}"
            if plan.failed_at
            else plan.status.value
        )
        now = self._clock()
        with Session(self._engine) as s, s.begin():
            row = s.get(ScheduleRow, sch.id)
            if row is None:
                return
            if row.last_run_id == plan.id:
                row.last_result = "succeeded" if ok else "failed"
                row.last_detail = detail
                row.updated_at = now.isoformat()
                s.add(row)
            self._audit(
                s,
                "scheduler",
                "scheduled_run_finished",
                plan.id,
                schedule=sch.id,
                status=plan.status.value,
                detail=detail,
            )
            notify.add(
                s,
                kind="scheduled_done" if ok else "schedule_stopped",
                title=f"{'✓' if ok else '✕'} {row.name}",
                body=detail if ok else f"Failed at {detail}. The schedule is stopped.",
                subject=plan.id,
                now=now,
            )
        if not ok:
            self._finalise(sch, "stopped", f"run {plan.id} {plan.status.value}: {detail}")

    def envelope_for(self, plan: Plan) -> DispatchEnvelope:
        """Everything that must hold before a scheduled run goes to its agent (the agent checks it again)."""
        if plan.schedule_id is None or plan.slot is None:
            raise ScheduleRefused(f"{plan.id} isn't a scheduled run", code="not_scheduled")
        sch = self.get(plan.schedule_id)
        now = self._clock()
        if sch.status != "active":
            raise ScheduleRefused(f"{sch.id} is {sch.status}", code="not_active")
        if sch.expires_at is None or not (now < sch.expires_at and plan.slot < sch.expires_at):
            raise ScheduleRefused(f"{sch.id} has expired", code="expired")
        if not sch.cron.is_slot(plan.slot) or not (plan.slot - grant.EARLY <= now <= plan.slot + grant.LATE):
            raise ScheduleRefused(f"{plan.id}'s slot isn't now", code="bad_slot")
        tpl = sch.template()
        if grant.template_hash(tpl) != sch.row.template_hash or plan.hash != sch.row.template_hash:
            raise ScheduleRefused(f"{plan.id} doesn't match {sch.id}'s approved steps", code="hash_mismatch")
        if [st.template() for st in plan.steps] != [st.template() for st in sch.steps]:
            raise ScheduleRefused(f"{plan.id} doesn't match {sch.id}'s approved steps", code="hash_mismatch")
        approval = sch.approval()
        try:
            self._verifier.verify(sch.payload(), approval.signature, domain=SCHEDULE_DOMAIN)
        except SigningError as exc:
            raise ScheduleRefused(f"{sch.id}: {exc.message}", code="bad_signature") from exc
        if approval.passkey is None:
            raise ScheduleRefused(f"{sch.id} has no passkey signature", code="passkey_required")
        result = self._plans.check_steps(sch.row.target, sch.steps)
        if not result.ok:
            self._finalise(
                sch, "invalidated", "the current policy denies these steps", kind="schedule_stopped"
            )
            raise ScheduleRefused(f"{sch.id}'s steps no longer pass policy", code="policy_violation")
        g = {k: v for k, v in sch.payload().items() if k not in ("v", "kind")}
        return DispatchEnvelope(
            template=tpl,
            plan_hash=sch.row.template_hash,
            approval=approval,
            schedule={
                "run_id": plan.id,
                "slot": plan.slot.isoformat(),
                "grant": {
                    **g,
                    "signature": approval.signature.model_dump(),
                    "passkey": approval.passkey.model_dump(),
                },
            },
        )

    def create_run(self, sch: Schedule, slot: datetime) -> Plan:
        source = None
        try:
            source = self._plans.get(sch.row.source_plan)
        except NotFound:
            source = None
        return self._plans.create_scheduled_run(
            schedule_id=sch.id,
            slot=slot,
            goal=sch.row.goal,
            target=sch.row.target,
            steps=sch.steps,
            template_hash=sch.row.template_hash,
            approval=sch.approval(),
            source=source,
            expires_at=slot + grant.LATE,
        )
