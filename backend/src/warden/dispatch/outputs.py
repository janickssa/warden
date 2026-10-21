"""Step output storage. Chunks go here; each step's SHA-256 goes into the hash-chained audit log, so the
stored output can't be changed without the audit chain showing it (invariant 7)."""

from __future__ import annotations

import hashlib

from sqlmodel import Field, Session, SQLModel, col, select


class StepOutputRow(SQLModel, table=True):
    __tablename__ = "step_output"

    id: int | None = Field(default=None, primary_key=True)
    plan_id: str = Field(index=True)
    n: int
    seq: int
    stream: str
    data: str


def append(session: Session, *, plan_id: str, n: int, seq: int, stream: str, data: str) -> None:
    session.add(StepOutputRow(plan_id=plan_id, n=n, seq=seq, stream=stream, data=data))


def read(session: Session, plan_id: str, n: int | None = None) -> list[StepOutputRow]:
    stmt = select(StepOutputRow).where(col(StepOutputRow.plan_id) == plan_id)
    if n is not None:
        stmt = stmt.where(col(StepOutputRow.n) == n)
    return list(session.exec(stmt.order_by(col(StepOutputRow.n), col(StepOutputRow.seq))))


def digest(rows: list[StepOutputRow]) -> str:
    h = hashlib.sha256()
    for r in rows:
        h.update(f"{r.stream}\0".encode())
        h.update(r.data.encode())
    return "sha256:" + h.hexdigest()
