"""Notifications outbox (README 10.3, 17.4): what the iPhone app gets as push notifications.

Warden records every notification here, in the same transaction as the event that caused it; `push.py`
delivers the undelivered rows over APNs, honouring `settings.notifications`. A push carries a title, a
body, a category and a plan or schedule ID, never commands or output: those are fetched over WireGuard
when the notification is opened. Nothing here can approve anything.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from sqlmodel import Field, Session, SQLModel, col, select

Kind = Literal["approval_needed", "plan_failed", "agent_refused", "scheduled_done", "schedule_stopped"]
# Notification categories the app registers (README 17.4): APPROVAL offers Approve (Face ID) and Reject;
# OPEN only opens the app (high-risk plans must be reviewed there).
Category = Literal["APPROVAL", "OPEN"]
# Which `settings.notifications` switch decides each kind.
PREFERENCE: dict[str, str] = {
    "approval_needed": "approval_needed",
    "plan_failed": "plan_failed",
    "schedule_stopped": "plan_failed",
    "agent_refused": "agent_refused",
    "scheduled_done": "scheduled_done",
}


class NotificationRow(SQLModel, table=True):
    __tablename__ = "notifications"

    id: int | None = Field(default=None, primary_key=True)
    kind: str = Field(index=True)
    title: str
    body: str
    subject: str  # plan or schedule ID the notification opens
    category: str = "OPEN"
    created_at: str
    delivered_at: str | None = None


def add(
    s: Session,
    *,
    kind: Kind,
    title: str,
    body: str,
    subject: str,
    now: datetime,
    category: Category = "OPEN",
) -> NotificationRow:
    row = NotificationRow(
        kind=kind, title=title, body=body, subject=subject, category=category, created_at=now.isoformat()
    )
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


# --- texts (README 17.4), in the dashboard's language ------------------------------------------------------

_RISK = {
    "en": {"low": "● Low risk", "medium": "▲ Medium risk", "high": "■ High risk"},
    "da": {"low": "● Lav risiko", "medium": "▲ Middel risiko", "high": "■ Høj risiko"},
}
_TEXT = {
    "en": {
        "approval": "Approval needed · {target}",
        "approval_high": "■ High-risk plan · {target}",
        "steps": "{n} steps",
        "step": "1 step",
        "failed": "✕ Failed at step {n} · {target}",
        "failed_plain": "✕ Failed · {target}",
        "refused": "▲ Agent refused a step · {target}",
    },
    "da": {
        "approval": "Godkendelse nødvendig · {target}",
        "approval_high": "■ Plan med høj risiko · {target}",
        "steps": "{n} trin",
        "step": "1 trin",
        "failed": "✕ Fejlede ved trin {n} · {target}",
        "failed_plain": "✕ Fejlede · {target}",
        "refused": "▲ Agent nægtede et trin · {target}",
    },
}


def _t(lang: str) -> dict[str, str]:
    return _TEXT.get(lang, _TEXT["en"])


def _clip(text: str, n: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def approval_needed(
    s: Session,
    *,
    plan_id: str,
    target: str,
    goal: str,
    steps: int,
    risk: str | None,
    lang: str,
    now: datetime,
) -> NotificationRow:
    t = _t(lang)
    high = risk == "high"
    count = t["step"] if steps == 1 else t["steps"].format(n=steps)
    parts = [_clip(goal, 120), count]
    if risk:
        parts.append(_RISK.get(lang, _RISK["en"])[risk])
    return add(
        s,
        kind="approval_needed",
        title=(t["approval_high"] if high else t["approval"]).format(target=target),
        body=" · ".join(parts),
        subject=plan_id,
        now=now,
        category="OPEN" if high else "APPROVAL",
    )


def plan_failed(
    s: Session,
    *,
    plan_id: str,
    target: str,
    goal: str,
    failed_at: int | None,
    reason: str | None,
    lang: str,
    now: datetime,
) -> NotificationRow:
    """No step output in the push: it's untrusted text from the target and would pass through Apple."""
    t = _t(lang)
    title = (
        t["failed"].format(n=failed_at, target=target)
        if failed_at
        else t["failed_plain"].format(target=target)
    )
    body = _clip(goal, 120) + (f" · {_clip(reason, 60)}" if reason else "")
    return add(s, kind="plan_failed", title=title, body=body, subject=plan_id, now=now)


def agent_refused(
    s: Session, *, plan_id: str, target: str, reason: str, lang: str, now: datetime
) -> NotificationRow:
    return add(
        s,
        kind="agent_refused",
        title=_t(lang)["refused"].format(target=target),
        body=f"{plan_id} · {_clip(reason, 140)}",
        subject=plan_id,
        now=now,
    )
