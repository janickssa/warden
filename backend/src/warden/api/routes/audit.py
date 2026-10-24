"""Audit log and live feed (README 17.3 Audit log, Live feed)."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator

from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from sqlmodel import Session, col, or_, select

from warden import audit
from warden.api import schemas as sc
from warden.api import views
from warden.api.auth import Ctx, Human

router = APIRouter(tags=["audit"])

FEED_TYPES: dict[str, str] = {
    "propose_plan": "proposal",
    "review": "verdict",
    "policy_deny": "verdict",
    "approve": "approval",
    "approve_with_edits": "approval",
    "reject": "rejection",
    "read_only": "read_only",
    "read_only_refused": "read_only",
    "run_started": "run",
    "run_finished": "run",
    "step_ok": "run",
    "step_failed": "run",
    "step_refused": "run",
    "plan_refused_by_agent": "run",
    "held_released": "run",
    "hold": "run",
    "kill": "kill",
    "expire": "expired",
    "plan_invalidated": "policy",
    "policy_publish": "policy",
    "policy_pending": "policy",
    "policy_pending_discarded": "policy",
    "policy_pending_superseded": "policy",
    "policy_sign_upload_refused": "policy",
    "policy_publish_blocked": "policy",
    "agent_connected": "agent",
    "agent_disconnected": "agent",
    "agent_enrolled": "agent",
    "agent_revoked": "agent",
    "bundle_ack": "agent",
    "bundle_rejected": "agent",
    "diagnosis_posted": "proposal",
    "diagnosis_requested": "proposal",
}
LOCKDOWN = {"lockdown", "lockdown_lift"}


AUDIT_KINDS: dict[str, re.Pattern[str]] = {
    "plans": re.compile(r"propose|verdict|review|edit|expire|execute|run_|diagnos|hold|release"),
    "decisions": re.compile(r"approve|reject|kill"),
    "output": re.compile(r"read_only|step_"),
    "policy": re.compile(
        r"policy|agent|lockdown|step_refused|invalidat|group|read_only_refused|bundle|trust"
    ),
    "settings": re.compile(r"settings|passkey|session|mcp_client"),
}


@router.get("/audit")
def audit_page(
    c: Ctx,
    _: Human,
    *,
    q: str = Query(default="", max_length=200),
    kind: str = "all",
    before: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> sc.AuditPage:
    pattern = AUDIT_KINDS.get(kind)
    out: list[audit.AuditRow] = []
    cursor = before
    with Session(c.engine) as s:
        while len(out) < limit:
            stmt = select(audit.AuditRow).order_by(col(audit.AuditRow.seq).desc()).limit(500)
            if cursor:
                stmt = stmt.where(col(audit.AuditRow.seq) < cursor)
            if q:
                like = f"%{q}%"
                stmt = stmt.where(
                    or_(
                        col(audit.AuditRow.actor).like(like),
                        col(audit.AuditRow.action).like(like),
                        col(audit.AuditRow.subject).like(like),
                        col(audit.AuditRow.detail).like(like),
                    )
                )
            rows = list(s.exec(stmt))
            if not rows:
                break
            for r in rows:
                cursor = r.seq
                if pattern is None or pattern.search(r.action):
                    out.append(r)
                    if len(out) >= limit:
                        break
        chain = audit.verify(s)
    return sc.AuditPage(
        entries=[
            sc.AuditEntry(
                seq=r.seq,
                ts=r.ts,
                actor=r.actor,
                action=r.action,
                subject=r.subject,
                detail=views.detail_json(r.detail),
                hash=r.hash,
                prev=r.prev,
            )
            for r in out
        ],
        chain_ok=chain.ok,
        chain_count=chain.count,
        chain_bad_seq=chain.bad_seq,
    )


@router.get("/audit/export")
def export(c: Ctx, _: Human) -> StreamingResponse:
    def lines() -> Iterator[str]:
        with Session(c.engine) as s:
            for line in audit.export_jsonl(s):
                yield line + "\n"

    return StreamingResponse(
        lines(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="warden-audit.jsonl"'},
    )


def _target(subject: str, detail: dict[str, object]) -> str | None:
    t = detail.get("target")
    if isinstance(t, str):
        return t
    head = subject.split(" · ", maxsplit=1)[0]
    return head if head and not head.startswith("pln_") and " " not in head else None


def _client_kind(actor: str) -> str:
    """dashboard, cli, iphone, agent, warden, or claude (MCP clients are named freely, so: everyone else)."""
    head = actor.split(":", 1)[0]
    if head in ("dashboard", "cli", "iphone", "agent"):
        return head
    return "warden" if actor in ("warden", "scheduler") or actor.startswith("warden:") else "claude"


@router.get("/feed")
def feed(
    c: Ctx,
    _: Human,
    *,
    type: str = "all",
    target: str = "all",
    client: str = "all",
    before: int | None = None,
    limit: int = Query(default=100, ge=1, le=500),
) -> sc.Feed:
    plans = {p.id: p.target for p in c.plans.list_plans()}
    items: list[sc.FeedItem] = []
    cursor = before
    with Session(c.engine) as s:
        while len(items) < limit:
            stmt = select(audit.AuditRow).order_by(col(audit.AuditRow.seq).desc()).limit(500)
            if cursor:
                stmt = stmt.where(col(audit.AuditRow.seq) < cursor)
            rows = list(s.exec(stmt))
            if not rows:
                break
            for r in rows:
                cursor = r.seq
                kind = "lockdown" if r.subject in LOCKDOWN else FEED_TYPES.get(r.action)
                if kind is None:
                    continue
                d = json.loads(r.detail)
                plan_id = r.subject.split(" · ")[0] if r.subject.startswith("pln_") else None
                tgt = plans.get(plan_id) if plan_id else _target(r.subject, d)
                if type not in ("all", kind) and not (
                    type == "policy_agents" and kind in ("policy", "agent", "lockdown")
                ):
                    continue
                if target not in ("all", tgt):
                    continue
                if client != "all" and _client_kind(r.actor) != client:
                    continue
                items.append(
                    sc.FeedItem(
                        seq=r.seq,
                        ts=r.ts,
                        type=kind,
                        actor=r.actor,
                        action=r.action,
                        subject=r.subject,
                        target=tgt,
                        plan_id=plan_id,
                    )
                )
                if len(items) >= limit:
                    break
    return sc.Feed(items=items)
