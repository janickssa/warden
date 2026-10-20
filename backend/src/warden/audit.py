"""Append-only audit log with a SHA-256 hash chain (invariant 7, README section 12).

Rows are never updated or deleted (SQLite triggers refuse it). Each row's hash covers its sequence number,
time, actor, action, subject, canonical detail and the previous row's hash, so editing, deleting or
reordering any row breaks `verify()`.
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlmodel import Field, Session, SQLModel, col, select

from warden.errors import AuditError
from warden.plans.canonical import canonical_bytes, sha256_tagged
from warden.text import normalize

GENESIS = "sha256:" + "0" * 64


class AuditRow(SQLModel, table=True):
    __tablename__ = "audit"

    seq: int = Field(primary_key=True)
    ts: str
    actor: str = Field(index=True)
    action: str = Field(index=True)
    subject: str
    detail: str
    prev: str
    hash: str


def _row_hash(*, seq: int, ts: str, actor: str, action: str, subject: str, detail: Any, prev: str) -> str:
    body = {
        "seq": seq,
        "ts": ts,
        "actor": actor,
        "action": action,
        "subject": subject,
        "detail": detail,
        "prev": prev,
    }
    return sha256_tagged(canonical_bytes(body))


def append(
    session: Session,
    *,
    ts: datetime,
    actor: str,
    action: str,
    subject: str,
    detail: Mapping[str, Any] | None = None,
) -> AuditRow:
    """Append one entry inside the caller's transaction (so it commits or rolls back with the change)."""
    if ts.tzinfo is None:
        raise AuditError("audit timestamps must be timezone-aware")
    last = session.exec(select(AuditRow).order_by(col(AuditRow.seq).desc()).limit(1)).first()
    seq = 1 if last is None else last.seq + 1
    prev = GENESIS if last is None else last.hash
    ts_s = ts.isoformat()
    actor, action, subject = normalize(actor), normalize(action), normalize(subject)
    detail_obj = dict(detail or {})
    row = AuditRow(
        seq=seq,
        ts=ts_s,
        actor=actor,
        action=action,
        subject=subject,
        detail=canonical_bytes(detail_obj).decode(),
        prev=prev,
        hash=_row_hash(
            seq=seq, ts=ts_s, actor=actor, action=action, subject=subject, detail=detail_obj, prev=prev
        ),
    )
    session.add(row)
    session.flush()
    return row


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    count: int
    bad_seq: int | None = None
    reason: str | None = None


def verify(session: Session) -> VerifyResult:
    prev = GENESIS
    expected_seq = 1
    count = 0
    for row in session.exec(select(AuditRow).order_by(col(AuditRow.seq))):
        if row.seq != expected_seq:
            return VerifyResult(False, count, row.seq, f"sequence gap: expected {expected_seq}")
        if row.prev != prev:
            return VerifyResult(False, count, row.seq, "previous-hash link broken")
        try:
            detail = json.loads(row.detail)
            recomputed = _row_hash(
                seq=row.seq,
                ts=row.ts,
                actor=row.actor,
                action=row.action,
                subject=row.subject,
                detail=detail,
                prev=row.prev,
            )
        except Exception as exc:  # unreadable JSON, non-canonical content, anything else: fail closed
            return VerifyResult(False, count, row.seq, f"unreadable entry: {exc}")
        if recomputed != row.hash:
            return VerifyResult(False, count, row.seq, "entry hash doesn't match its contents")
        prev = row.hash
        expected_seq += 1
        count += 1
    return VerifyResult(True, count)


def entries(session: Session, *, subject_prefix: str | None = None) -> list[AuditRow]:
    stmt = select(AuditRow).order_by(col(AuditRow.seq))
    if subject_prefix:
        stmt = stmt.where(col(AuditRow.subject).startswith(subject_prefix))
    return list(session.exec(stmt))


def export_jsonl(session: Session) -> Iterator[str]:
    for row in session.exec(select(AuditRow).order_by(col(AuditRow.seq))):
        yield canonical_bytes(
            {
                "seq": row.seq,
                "ts": row.ts,
                "actor": row.actor,
                "action": row.action,
                "subject": row.subject,
                "detail": json.loads(row.detail),
                "prev": row.prev,
                "hash": row.hash,
            }
        ).decode()
