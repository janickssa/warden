"""SQLite plan store. Each plan is stored as validated JSON plus indexed columns.

Updates are compare-and-set on a version counter, so two channels deciding the same plan at once can't
both succeed: the loser gets DecidedElsewhere ("Approved on iPhone 14:32", README 17.6).
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import update
from sqlmodel import Field, Session, SQLModel, col, select

from warden.errors import DecidedElsewhere, NotFound
from warden.plans.models import Plan, PlanStatus
from warden.plans.state import check_transition


class PlanRow(SQLModel, table=True):
    __tablename__ = "plans"

    id: str = Field(primary_key=True)
    status: str = Field(index=True)
    target: str = Field(index=True)
    revises: str | None = Field(default=None, index=True)
    hash: str
    created_at: str = Field(index=True)
    expires_at: str = Field(index=True)
    version: int
    body: str


def _utc(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat()


def _row(plan: Plan) -> dict[str, object]:
    return {
        "id": plan.id,
        "status": plan.status.value,
        "target": plan.target,
        "revises": plan.revises,
        "hash": plan.hash,
        "created_at": _utc(plan.created_at),
        "expires_at": _utc(plan.expires_at),
        "version": plan.version,
        "body": plan.model_dump_json(),
    }


def insert(session: Session, plan: Plan) -> Plan:
    plan = plan.model_copy(update={"version": 1})
    session.add(PlanRow(**_row(plan)))  # type: ignore[arg-type]
    session.flush()
    return plan


def get(session: Session, plan_id: str) -> Plan:
    row = session.get(PlanRow, plan_id)
    if row is None:
        raise NotFound(f"no plan {plan_id}")
    return Plan.model_validate_json(row.body)


def save(session: Session, old: Plan, new: Plan) -> Plan:
    """Write `new` if the stored plan is still exactly `old` (same version). Checks the transition."""
    if new.status != old.status:
        check_transition(old.status, new.status)
    new = new.model_copy(update={"version": old.version + 1})
    values = _row(new)
    del values["id"]
    result = session.execute(
        update(PlanRow).where(col(PlanRow.id) == old.id, col(PlanRow.version) == old.version).values(**values)
    )
    if result.rowcount != 1:  # type: ignore[attr-defined]
        current = get(session, old.id)
        raise DecidedElsewhere(f"{old.id} changed while you were looking at it (now {current.status.value})")
    return new


def list_plans(
    session: Session,
    *,
    statuses: tuple[PlanStatus, ...] | None = None,
    target: str | None = None,
    oldest_first: bool = False,
) -> list[Plan]:
    stmt = select(PlanRow)
    if statuses:
        stmt = stmt.where(col(PlanRow.status).in_([s.value for s in statuses]))
    if target:
        stmt = stmt.where(col(PlanRow.target) == target)
    order = col(PlanRow.created_at)
    stmt = stmt.order_by(order if oldest_first else order.desc())
    return [Plan.model_validate_json(r.body) for r in session.exec(stmt)]


def due_for_expiry(session: Session, now: datetime) -> list[Plan]:
    waiting = (PlanStatus.AWAITING_APPROVAL, PlanStatus.APPROVED, PlanStatus.HELD)
    stmt = select(PlanRow).where(
        col(PlanRow.status).in_([s.value for s in waiting]), col(PlanRow.expires_at) <= _utc(now)
    )
    return [Plan.model_validate_json(r.body) for r in session.exec(stmt)]
