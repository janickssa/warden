"""Policy, groups and lockdown from the browser (README 7A, 7B, 17.3 Policy/Groups; Done-when of M6).

Editing produces a *preview*: the new YAML is parsed, compiled for every target, classified against what
agents run, and run through the publish test gate. Publishing a preview needs a passkey confirmation bound to
that preview. It writes `policy.yaml` atomically (the file stays the single source of truth, §16 rule 8),
then publishes exactly as `warden policy publish` does: tightening goes out at once, loosening waits for the
offline key.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlmodel import Session, col, select

from warden import audit
from warden.api import schemas as sc
from warden.api import views
from warden.api.auth import Ctx, Human
from warden.api.context import ApiContext
from warden.config import parse_policy
from warden.errors import ConfigError, WardenError
from warden.plans.models import PlanStatus
from warden.policy.schema import Policy
from warden.policy_dist import bundle as bundles
from warden.policy_dist import publish as publishing
from warden.policy_dist.classify import classify

router = APIRouter(tags=["policy"])
PREVIEW_TTL = timedelta(minutes=30)
_previews: dict[str, Preview] = {}


@dataclass
class Preview:
    id: str
    text: str
    sha: str
    policy: Policy
    expires_at: datetime
    by: str


def _policy_path(c: ApiContext) -> Path:
    return c.config_dir / "policy.yaml"


def _changes(changes: Any) -> list[dict[str, str]]:
    return [{"path": x.path, "op": x.op, "effect": x.effect, "detail": x.detail} for x in changes]


def preview_text(c: ApiContext, text: str, by: str, *, note: str | None = None) -> sc.PolicyPreview:
    current = _policy_path(c).read_text(encoding="utf-8")
    diff = list(
        difflib.unified_diff(current.splitlines(), text.splitlines(), "policy.yaml", "new", lineterm="")
    )
    try:
        policy = parse_policy(text)
    except ConfigError as exc:
        return sc.PolicyPreview(
            preview_id=None,
            ok=False,
            errors=[exc.message],
            cls=None,
            targets=[],
            gate_failures=[],
            gate_cases=len(publishing.gate_cases()),
            yaml_diff=diff,
            note=note,
        )
    cfg = c.config()
    failures = publishing.run_gate(policy, cfg.targets)
    with Session(c.engine) as s:
        lock = publishing.lockdown_state(s)
        trust = bundles.latest_trust(s)  # publishing policy never changes the approval trust
        approval_keys = bundles.approval_key_refs(c.approval)
        rows = []
        for t in cfg.targets.targets:
            new = {
                "rules": bundles.compiled_for(policy, cfg.targets, t.name, lockdown=lock, trust=trust),
                "approval_keys": approval_keys,
            }
            prev = bundles.latest(s, t.name)
            if prev is None:
                rows.append(sc.TargetChangeView(target=t.name, cls="initial", changes=[]))
                continue
            cl = classify({"rules": prev["rules"], "approval_keys": prev["approval_keys"]}, new)
            rows.append(sc.TargetChangeView(target=t.name, cls=cl.cls, changes=_changes(cl.changes)))
    classes = {r.cls for r in rows}
    overall = (
        "loosen"
        if "loosen" in classes
        else "tighten"
        if "tighten" in classes
        else "initial"
        if "initial" in classes
        else "none"
    )
    pid = None
    if not failures:
        now = c.now()
        for k in [k for k, p in _previews.items() if p.expires_at <= now]:
            del _previews[k]
        pid = secrets.token_urlsafe(12)
        _previews[pid] = Preview(
            pid, text, hashlib.sha256(text.encode()).hexdigest(), policy, now + PREVIEW_TTL, by
        )
    return sc.PolicyPreview(
        preview_id=pid,
        ok=not failures,
        errors=[],
        cls=overall,
        targets=rows,
        gate_failures=failures,
        gate_cases=len(publishing.gate_cases()),
        yaml_diff=diff,
        note=note,
    )


def _history(c: ApiContext) -> list[sc.HistoryRow]:
    by_version: dict[int, sc.HistoryRow] = {}
    with Session(c.engine) as s:
        for r in s.exec(
            select(audit.AuditRow)
            .where(col(audit.AuditRow.action) == "policy_publish")
            .order_by(col(audit.AuditRow.seq))
        ):
            d = json.loads(r.detail)
            v = int(d["version"])
            row = by_version.get(v) or sc.HistoryRow(
                version=v,
                at=r.ts,
                by=r.actor,
                cls="none",
                signed_with=d.get("signed_with", "online"),
                targets=0,
            )
            row.targets += 1
            rank = {"none": 0, "tighten": 1, "initial": 2, "loosen": 3}
            if rank.get(d.get("class", "none"), 0) > rank.get(row.cls, 0):
                row.cls = d["class"]
            by_version[v] = row
    return sorted(by_version.values(), key=lambda r: -r.version)[:30]


@router.get("/policy")
def get_policy(c: Ctx, _: Human) -> sc.PolicyView:
    facts = views.Facts(c)
    cfg = facts.cfg
    path = _policy_path(c)
    with Session(c.engine) as s:
        version = bundles.published_version(s)
        pending = publishing.open_pending(s)
        unpublished = False
        compiled: dict[str, Any] = {}
        for t in cfg.targets.targets:
            b = bundles.latest(s, t.name)
            compiled[t.name] = b["rules"] if b else None
            if b is None or b["rules"] != bundles.compiled_for(
                cfg.policy, cfg.targets, t.name, lockdown=facts.lockdown, trust=bundles.trust_of(b["rules"])
            ):
                unpublished = True
    rollout = [
        sc.RolloutRow(
            agent=a.name,
            version=a.policy_version,
            online=a.online,
            current=(a.policy_version or 0) >= version,
        )
        for a in (facts.agent_view(n) for n in facts.agents)
    ]
    pend = None
    if pending is not None:
        pend = sc.PendingView(
            version=pending.version,
            reason=pending.reason,
            created_at=pending.created_at,
            created_by=pending.created_by,
            targets=[
                sc.TargetChangeView(target=i["target"], cls=i["class"], changes=i["changes"])
                for i in publishing.pending_items(pending)
            ],
        )
    return sc.PolicyView(
        yaml=path.read_text(encoding="utf-8"),
        version=version,
        lockdown=facts.lockdown,
        e2e=cfg.e2e,
        rollout=rollout,
        pending=pend,
        history=_history(c),
        compiled=compiled,
        unpublished_changes=unpublished,
        writable=os.access(path, os.W_OK) and os.access(path.parent, os.W_OK),
    )


@router.post("/policy/preview")
def preview(body: sc.PolicyIn, c: Ctx, human: Human) -> sc.PolicyPreview:
    return preview_text(c, body.yaml, human.label)


@router.post("/policy/publish/options")
def publish_options(preview_id: str, c: Ctx, human: Human) -> sc.ApproveOptions:
    p = _previews.get(preview_id)
    if p is None or p.expires_at <= c.now() or p.by != human.label:
        raise WardenError("that preview expired; preview the change again", code="preview_expired")
    cid, raw = c.passkeys.assertion_options("publish", preview_id, now=c.now())
    return sc.ApproveOptions(
        needs_passkey=True,
        reasons=["publishing policy needs your passkey"],
        challenge_id=cid,
        options=json.loads(raw),
    )


def _write_atomic(path: Path, text: str) -> None:
    tmp = path.with_name(f".{path.name}.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def result_view(r: publishing.PublishResult, reloaded: dict[str, Any] | None) -> sc.PublishResultView:
    return sc.PublishResultView(
        outcome=r.outcome,
        version=r.version,
        loosens=list(r.loosens),
        pushed=list((reloaded or {}).get("pushed", [])),
        invalidated=list((reloaded or {}).get("invalidated", [])),
    )


@router.post("/policy/publish")
async def publish(body: sc.PublishIn, c: Ctx, human: Human) -> sc.PublishResultView:
    p = _previews.get(body.preview_id)
    if p is None or p.expires_at <= c.now() or p.by != human.label:
        raise WardenError("that preview expired; preview the change again", code="preview_expired")
    c.passkeys.verify(body.challenge_id, body.credential, "publish", body.preview_id, now=c.now())
    del _previews[body.preview_id]
    path = _policy_path(c)
    old = path.read_text(encoding="utf-8")
    if hashlib.sha256(old.encode()).hexdigest() != p.sha:
        try:
            _write_atomic(path, p.text)
        except OSError as exc:
            raise WardenError(
                f"can't write {path} ({exc.strerror}); make it writable by the Warden user",
                code="not_writable",
            ) from exc
    cfg = c.config()
    try:
        r = publishing.publish(
            c.engine,
            policy=p.policy,
            targets=cfg.targets,
            online=c.online,
            approval=c.approval,
            now=c.now(),
            actor=human.label,
        )
    except WardenError:
        _write_atomic(path, old)
        raise
    reloaded = await c.reload()
    return result_view(r, reloaded)


@router.get("/policy/pending/file")
def pending_file(c: Ctx, _: Human) -> JSONResponse:
    pf = publishing.publish_file(c.engine)
    return JSONResponse(
        pf, headers={"Content-Disposition": f'attachment; filename="bundle-v{pf["version"]}.json"'}
    )


@router.post("/policy/pending/signature")
async def upload_signature(body: sc.SignatureIn, c: Ctx, human: Human) -> sc.PublishResultView:
    r = publishing.sign_upload(c.engine, body.content, now=c.now(), actor=human.label)
    return result_view(r, await c.reload())


@router.post("/policy/pending/discard")
def discard(c: Ctx, human: Human) -> sc.Ok:
    v = publishing.discard(c.engine, now=c.now(), actor=human.label)
    return sc.Ok(message=f"pending v{v} discarded")


@router.post("/lockdown")
async def lockdown(c: Ctx, human: Human) -> sc.PublishResultView:
    """Kill running plans, hold approved ones, publish read-only-only rules (README 7A Lockdown)."""
    r = publishing.lockdown(c.engine, online=c.online, approval=c.approval, now=c.now(), actor=human.label)
    for p in c.plans.list_plans(statuses=(PlanStatus.APPROVED,)):
        c.plans.hold(p.id, "lockdown")
    return result_view(r, await c.reload())


@router.post("/lockdown/lift")
async def lift(c: Ctx, human: Human) -> sc.PublishResultView:
    r = publishing.lift(c.engine, online=c.online, approval=c.approval, now=c.now(), actor=human.label)
    return result_view(r, await c.reload())


# --- groups (README 7B) -------------------------------------------------------------------------------


@router.get("/groups")
def groups(c: Ctx, _: Human) -> list[sc.GroupView]:
    cfg = c.config()
    out = []
    for name, g in cfg.policy.groups.items():
        tags = []
        if g.read_only.mode != "allowed":
            tags.append(f"read_only_{g.read_only.mode}")
        if g.approvals.passkey:
            tags.append("passkey_always")
        if g.gatekeepers.unanimous:
            tags.append("unanimous")
        members = [
            sc.GroupMember(
                name=m,
                kind=(t.kind if (t := cfg.targets.get(m)) else "not in targets.yaml"),
                known=t is not None,
            )
            for m in g.members
        ]
        out.append(
            sc.GroupView(
                name=name,
                desc=g.desc,
                members=members,
                tags=tags,
                rules=g.model_dump(exclude={"desc", "members"}),
            )
        )
    return out


@router.post("/groups/preview")
def group_preview(body: sc.GroupEditIn, c: Ctx, human: Human) -> sc.PolicyPreview:
    """Rewrites the `groups:` part of policy.yaml. Comments in the file aren't kept (say so in the UI)."""
    data = yaml.safe_load(_policy_path(c).read_text(encoding="utf-8")) or {}
    groups_ = dict(data.get("groups") or {})
    if body.rename_from and body.rename_from in groups_:
        groups_.pop(body.rename_from)
    if body.group is None:
        groups_.pop(body.name, None)
    else:
        groups_[body.name] = body.group
    data["groups"] = groups_
    text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    return preview_text(
        c,
        text,
        human.label,
        note="Saving from the group editor rewrites policy.yaml; comments in it are not kept.",
    )
