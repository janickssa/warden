"""Notifications outbox (README 10.3, 17.4): what the iPhone app pushes from M8.

Warden records every notification here, in the same transaction as the event that caused it. Delivery
(APNs, per-type preferences in `settings.notifications`) reads the undelivered rows; the dashboard shows the
same events in the feed. Nothing here can approve anything.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from sqlmodel import Field, Session, SQLModel, col, select

Kind = Literal["approval_needed", "plan_failed", "agent_refused", "scheduled_done", "schedule_stopped"]


class NotificationRow(SQLModel, table=True):
    __tablename__ = "notifications"

    id: int | None = Field(default=None, primary_key=True)
    kind: str = Field(index=True)
    title: str
    body: str
    subject: str  # plan or schedule ID the notification opens
    created_at: str
    delivered_at: str | None = None


def add(s: Session, *, kind: Kind, title: str, body: str, subject: str, now: datetime) -> NotificationRow:
    row = NotificationRow(kind=kind, title=title, body=body, subject=subject, created_at=now.isoformat())
    s.add(row)
    s.flush()
    return row


def pending(s: Session, limit: int = 100) -> list[NotificationRow]:
    stmt = (
        select(NotificationRow)
        .where(col(NotificationRow.delivered_at).is_(None))
        .order_by(col(NotificationRow.id))
    )
    return list(s.exec(stmt.limit(limit)))
