"""Diagnosis after a failed plan (README 4, DECISIONS D-14): Claude's note plus evidence it can't fake.

Claude supplies a plain-text note and the audit IDs of `read_only` commands it ran. Warden attaches the real
command, exit code and output from the audit log. Every check fails closed. Posting never changes the plan.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, col, select
from ulid import ULID

from warden import audit
from warden.actors import ClaudeActor, HumanActor
from warden.errors import InputRefused, WardenError
from warden.plans import store
from warden.plans.models import PlanStatus
from warden.text import check_free_text, normalize

MAX_NOTE = 4000
MAX_IDS = 20
MAX_PER_PLAN = 10


class DiagnosisRefused(WardenError):
    code = "diagnosis_refused"


class DiagnosisRow(SQLModel, table=True):
    __tablename__ = "diagnoses"

    id: str = Field(primary_key=True)
    plan_id: str = Field(index=True)
    client: str
    note: str
    audit_ids: str  # JSON list of ints
    created_at: str


@dataclass(frozen=True)
class Evidence:
    audit_id: int
    command: str
    exit_code: int | None
    output: str
    truncated: bool


@dataclass(frozen=True)
class Diagnosis:
    id: str
    plan_id: str
    client: str
    note: str
    created_at: str
    evidence: tuple[Evidence, ...]


def _failure_seq(s: Session, plan_id: str) -> int | None:
    row = s.exec(
        select(audit.AuditRow)
        .where(col(audit.AuditRow.action) == "run_finished", col(audit.AuditRow.subject) == plan_id)
        .order_by(col(audit.AuditRow.seq).desc())
        .limit(1)
    ).first()
    return None if row is None else row.seq


def _evidence(row: audit.AuditRow) -> Evidence:
    d: dict[str, Any] = json.loads(row.detail)
    return Evidence(
        audit_id=row.seq,
        command=str(d.get("command", "")),
        exit_code=d.get("exit_code"),
        output=str(d.get("output", "")),
        truncated=bool(d.get("truncated", False)),
    )


def post(
    engine: Engine, *, plan_id: str, note: str, audit_ids: list[int], actor: ClaudeActor, now: datetime
) -> Diagnosis:
    note = normalize(note)
    try:
        check_free_text(note, field="note", max_len=MAX_NOTE, allow_newlines=True)
    except InputRefused as exc:
        raise DiagnosisRefused(exc.message, code="bad_note") from exc
    if not note.strip():
        raise DiagnosisRefused("the note is empty", code="bad_note")
    if len(audit_ids) > MAX_IDS:
        raise DiagnosisRefused(f"at most {MAX_IDS} read_only audit IDs", code="too_many_ids")
    if len(set(audit_ids)) != len(audit_ids):
        raise DiagnosisRefused("duplicate audit IDs", code="duplicate_ids")

    with Session(engine) as s, s.begin():
        plan = store.get(s, plan_id)
        if plan.status != PlanStatus.FAILED:
            raise DiagnosisRefused(
                f"{plan_id} is {plan.status.value}; diagnoses are for failed plans", code="not_failed"
            )
        existing = s.exec(select(DiagnosisRow).where(col(DiagnosisRow.plan_id) == plan_id)).all()
        if len(existing) >= MAX_PER_PLAN:
            raise DiagnosisRefused(
                f"{plan_id} already has {MAX_PER_PLAN} diagnoses", code="too_many_diagnoses"
            )
        failed_seq = _failure_seq(s, plan_id)
        if failed_seq is None:
            raise DiagnosisRefused(f"no failure recorded for {plan_id}", code="not_failed")
        rows = []
        for seq in audit_ids:
            row = s.get(audit.AuditRow, seq)
            why = None
            if row is None or row.action != "read_only":
                why = "isn't a read_only command that ran"
            elif row.actor != actor.label:
                why = "was run by another client"
            elif json.loads(row.detail).get("target") != plan.target:
                why = f"ran on another target than {plan.target}"
            elif seq <= failed_seq:
                why = "ran before the plan failed"
            if why or row is None:
                raise DiagnosisRefused(f"audit entry {seq} {why}", code="bad_evidence")
            rows.append(row)
        chain = audit.verify(s)
        if not chain.ok:
            raise DiagnosisRefused(f"audit chain broken at {chain.bad_seq}", code="audit_invalid")
        d = DiagnosisRow(
            id=f"dgn_{ULID()}",
            plan_id=plan_id,
            client=actor.label,
            note=note,
            audit_ids=json.dumps(audit_ids),
            created_at=now.isoformat(),
        )
        s.add(d)
        audit.append(
            s,
            ts=now,
            actor=actor.label,
            action="diagnosis_posted",
            subject=plan_id,
            detail={"diagnosis": d.id, "note": note, "audit_ids": audit_ids},
        )
        return Diagnosis(d.id, plan_id, d.client, note, d.created_at, tuple(_evidence(r) for r in rows))


def for_plan(engine: Engine, plan_id: str) -> list[Diagnosis]:
    with Session(engine) as s:
        out = []
        for d in s.exec(
            select(DiagnosisRow)
            .where(col(DiagnosisRow.plan_id) == plan_id)
            .order_by(col(DiagnosisRow.created_at))
        ):
            ids: list[int] = json.loads(d.audit_ids)
            rows = [r for r in (s.get(audit.AuditRow, i) for i in ids) if r is not None]
            out.append(
                Diagnosis(d.id, d.plan_id, d.client, d.note, d.created_at, tuple(_evidence(r) for r in rows))
            )
        return out


# --- the human's side: "Diagnose & propose fix…" in the dashboard (D-14) ------------------------------


class HumanNoteRow(SQLModel, table=True):
    __tablename__ = "diagnosis_requests"

    plan_id: str = Field(primary_key=True)
    note: str
    by: str
    created_at: str


def request(engine: Engine, *, plan_id: str, note: str, actor: HumanActor, now: datetime) -> None:
    """Ask Claude to diagnose a failed plan. The note reaches Claude through `get_plan` (`human_note`); it
    never changes the plan. Plain text, the same rules as Claude's notes, and replaced if asked again."""
    note = normalize(note)
    try:
        check_free_text(note, field="note", max_len=MAX_NOTE, allow_newlines=True)
    except InputRefused as exc:
        raise DiagnosisRefused(exc.message, code="bad_note") from exc
    with Session(engine) as s, s.begin():
        plan = store.get(s, plan_id)
        if plan.status != PlanStatus.FAILED:
            raise DiagnosisRefused(
                f"{plan_id} is {plan.status.value}; only failed plans are diagnosed", code="not_failed"
            )
        row = s.get(HumanNoteRow, plan_id)
        if row is None:
            row = HumanNoteRow(plan_id=plan_id, note=note, by=actor.label, created_at=now.isoformat())
        else:
            row.note, row.by, row.created_at = note, actor.label, now.isoformat()
        s.add(row)
        audit.append(
            s, ts=now, actor=actor.label, action="diagnosis_requested", subject=plan_id, detail={"note": note}
        )


def human_note(engine: Engine, plan_id: str) -> HumanNoteRow | None:
    with Session(engine) as s:
        return s.get(HumanNoteRow, plan_id)
