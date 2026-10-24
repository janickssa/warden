"""Publishing policy changes (README 7A "Publishing a rule change", "Tighten vs. loosen", "Lockdown").

Every publish creates one new global version with a bundle for every target. Warden classifies each target's
change against the bundle it last published (the agent does the same against what it has installed):

- every target tightens, is unchanged or is new → signed with the online key and stored at once;
- any target loosens → a pending publish. Its bundles are online-signed but not live. `warden-sign` adds the
  offline signature, `sign_upload` verifies it against the registered offline keys and publishes.

The publish test gate (`must_deny.yaml`) runs before anything is stored. Lockdown re-signs the current rules
with `lockdown: true` (always a tightening); lifting it is a loosening and needs the offline key.
Functions take the engine and run their own transactions, so refusals are audited even when they raise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from functools import cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, ValidationError
from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, col, select

from warden import audit
from warden.errors import WardenError
from warden.keys import OnlineKey
from warden.passkeys import RelyingParty, trust_for
from warden.plans.canonical import canonical_bytes
from warden.plans.models import Step, StepKind
from warden.policy.effective import effective_rules
from warden.policy.engine import check_plan
from warden.policy.paths import LexicalResolver
from warden.policy.schema import Policy, Targets
from warden.policy_dist import bundle as bundles
from warden.policy_dist import offline_keys
from warden.policy_dist.classify import Change, classify
from warden.signing import ApprovalKey

GATE_FILE = Path(__file__).with_name("must_deny.yaml")

Outcome = Literal["published", "pending", "unchanged"]


class GateFailed(WardenError):
    code = "policy_test_failed"


class PublishRefused(WardenError):
    code = "publish_refused"


class PendingRow(SQLModel, table=True):
    __tablename__ = "policy_pending"

    version: int = Field(primary_key=True)
    base_version: int
    status: str = Field(index=True)  # pending | published | discarded | superseded
    reason: str  # publish | lockdown_lift
    body: str  # canonical JSON: [{target, class, changes, previous, bundle}]
    created_at: str
    created_by: str
    closed_at: str | None = None


@dataclass(frozen=True)
class TargetChange:
    target: str
    cls: str  # initial | none | tighten | loosen
    changes: tuple[Change, ...]
    bundle: dict[str, Any]
    previous: dict[str, Any] | None = None


@dataclass(frozen=True)
class PublishResult:
    outcome: Outcome
    version: int
    targets: tuple[TargetChange, ...] = ()
    superseded: int | None = None
    notes: tuple[str, ...] = field(default=())

    @property
    def loosens(self) -> tuple[str, ...]:
        return tuple(t.target for t in self.targets if t.cls == "loosen")


# --- test gate -------------------------------------------------------------------------------------------


class GateCase(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    kind: StepKind
    command: str


@cache
def gate_cases() -> tuple[GateCase, ...]:
    raw = yaml.safe_load(GATE_FILE.read_text(encoding="utf-8"))
    return tuple(GateCase.model_validate(c) for c in raw)


def run_gate(policy: Policy, targets: Targets) -> list[str]:
    """Return one line per attack the new policy would allow. Empty means the gate passed."""
    failures = []
    resolver = LexicalResolver()
    for t in targets.targets:
        rules = effective_rules(policy, t)
        for case in gate_cases():
            try:
                step = Step(
                    n=1,
                    kind=case.kind,
                    command=case.command,
                    purpose="publish test gate",
                    cwd=t.workspace_roots[0],
                    timeout_s=60,
                )
            except (ValidationError, WardenError):
                continue  # refused before the policy engine even sees it
            if check_plan([step], rules, resolver).ok:
                failures.append(f"{t.name}: {case.id} ({case.command!r}) would be allowed")
    return failures


# --- state -----------------------------------------------------------------------------------------------


def lockdown_state(session: Session) -> bool:
    """Lockdown is whatever the latest published bundles say."""
    row = session.exec(
        select(bundles.BundleRow).order_by(col(bundles.BundleRow.version).desc()).limit(1)
    ).first()
    return bool(row is not None and json.loads(row.body)["rules"].get("lockdown"))


def open_pending(session: Session) -> PendingRow | None:
    return session.exec(select(PendingRow).where(col(PendingRow.status) == "pending")).first()


def _next_version(session: Session) -> int:
    reserved = session.exec(select(PendingRow).order_by(col(PendingRow.version).desc()).limit(1)).first()
    return max(bundles.published_version(session), reserved.version if reserved else 0) + 1


def _audit(engine: Engine, now: datetime, actor: str, action: str, subject: str, **detail: Any) -> None:
    with Session(engine) as s, s.begin():
        audit.append(s, ts=now, actor=actor, action=action, subject=subject, detail=detail)


def _content(b: dict[str, Any]) -> dict[str, Any]:
    return {"rules": b["rules"], "approval_keys": b["approval_keys"]}


def _changes_detail(changes: tuple[Change, ...]) -> list[dict[str, str]]:
    return [{"path": c.path, "op": c.op, "effect": c.effect, "detail": c.detail} for c in changes]


def _prepare(
    session: Session,
    rules_for: dict[str, dict[str, Any]],
    *,
    approval: ApprovalKey,
    online: OnlineKey,
    version: int,
    now: datetime,
) -> list[TargetChange]:
    keys = bundles.approval_key_refs(approval)
    out = []
    for target, rules in rules_for.items():
        prev = bundles.latest(session, target)
        new = {"rules": rules, "approval_keys": keys}
        changes: tuple[Change, ...] = ()
        if prev is None:
            cls, label = "initial", "initial"
        else:
            c = classify(_content(prev), new)
            cls, changes = c.cls, c.changes
            label = "loosen" if cls == "loosen" else "tighten"
        bundle = bundles.sign_bundle(
            bundles.build_bundle(
                version=version, target=target, rules=rules, change=label, approval_keys=keys, issued_at=now
            ),
            online,
        )
        out.append(TargetChange(target, cls, tuple(changes), bundle, _content(prev) if prev else None))
    return out


def _store(session: Session, items: list[TargetChange], *, now: datetime, actor: str, how: str) -> None:
    for it in items:
        digest = bundles.bundle_sha256(it.bundle)
        session.add(
            bundles.BundleRow(
                target=it.target,
                version=it.bundle["version"],
                sha256=digest,
                body=canonical_bytes(it.bundle).decode(),
                created_at=now.isoformat(),
            )
        )
        audit.append(
            session,
            ts=now,
            actor=actor,
            action="policy_publish",
            subject=f"{it.target} · v{it.bundle['version']} · {it.cls}",
            detail={
                "target": it.target,
                "version": it.bundle["version"],
                "class": it.cls,
                "sha256": digest,
                "signed_with": how,
                "changes": _changes_detail(it.changes),
            },
        )


def _supersede(session: Session, *, now: datetime, actor: str, why: str) -> int | None:
    row = open_pending(session)
    if row is None:
        return None
    row.status, row.closed_at = "superseded", now.isoformat()
    session.add(row)
    audit.append(
        session,
        ts=now,
        actor=actor,
        action="policy_pending_superseded",
        subject=f"v{row.version}",
        detail={"why": why},
    )
    return row.version


def _publish_rules(
    engine: Engine,
    rules_for: dict[str, dict[str, Any]],
    *,
    online: OnlineKey,
    approval: ApprovalKey,
    now: datetime,
    actor: str,
    reason: str,
) -> PublishResult:
    with Session(engine) as s, s.begin():
        version = _next_version(s)
        items = _prepare(s, rules_for, approval=approval, online=online, version=version, now=now)
        if all(it.cls == "none" for it in items):
            return PublishResult("unchanged", bundles.published_version(s))
        superseded = _supersede(s, now=now, actor=actor, why=f"new publish v{version}")
        if not any(it.cls == "loosen" for it in items):
            _store(s, items, now=now, actor=actor, how="online")
            return PublishResult("published", version, tuple(items), superseded)
        body = [
            {
                "target": it.target,
                "class": it.cls,
                "changes": _changes_detail(it.changes),
                "previous": it.previous,
                "bundle": it.bundle,
            }
            for it in items
        ]
        s.add(
            PendingRow(
                version=version,
                base_version=bundles.published_version(s),
                status="pending",
                reason=reason,
                body=canonical_bytes(body).decode(),
                created_at=now.isoformat(),
                created_by=actor,
            )
        )
        audit.append(
            s,
            ts=now,
            actor=actor,
            action="policy_pending",
            subject=f"v{version} · {reason}",
            detail={
                "loosens": [it.target for it in items if it.cls == "loosen"],
                "changes": {it.target: _changes_detail(it.changes) for it in items},
            },
        )
        return PublishResult("pending", version, tuple(items), superseded)


# --- public operations -----------------------------------------------------------------------------------


def publish(
    engine: Engine,
    *,
    policy: Policy,
    targets: Targets,
    online: OnlineKey,
    approval: ApprovalKey,
    now: datetime,
    actor: str,
) -> PublishResult:
    """`warden policy publish`: compile policy.yaml + targets.yaml and publish (or hold) the change."""
    failures = run_gate(policy, targets)
    if failures:
        _audit(engine, now, actor, "policy_publish_blocked", "test gate", failures=failures)
        raise GateFailed("the publish test gate failed:\n  " + "\n  ".join(failures))
    with Session(engine) as s:
        lock = lockdown_state(s)
        trust = bundles.latest_trust(s)  # approval trust only changes through publish_trust
    rules_for = {
        t.name: bundles.compiled_for(policy, targets, t.name, lockdown=lock, trust=trust)
        for t in targets.targets
    }
    return _publish_rules(
        engine, rules_for, online=online, approval=approval, now=now, actor=actor, reason="publish"
    )


def _latest_rules(
    engine: Engine, *, lockdown: bool | None = None, trust: dict[str, Any] | None = None
) -> dict[str, dict[str, Any]]:
    """Every target's published rules, with lockdown and/or the approval trust replaced."""
    with Session(engine) as s:
        names = sorted(set(s.exec(select(bundles.BundleRow.target)).all()))
        out = {}
        for name in names:
            b = bundles.latest(s, name)
            if b is None:
                continue
            rules = dict(b["rules"])
            if lockdown is not None:
                rules["lockdown"] = lockdown
            if trust is not None:
                rules["approvals"] = {"passkey": rules["approvals"]["passkey"], **trust}
            out[name] = rules
    if not out:
        raise PublishRefused("nothing is published yet; run `warden policy publish` first")
    return out


def lockdown(
    engine: Engine, *, online: OnlineKey, approval: ApprovalKey, now: datetime, actor: str
) -> PublishResult:
    """Re-sign every target's current rules with lockdown on. Always a tightening, so it goes out at once."""
    with Session(engine) as s:
        if lockdown_state(s):
            raise PublishRefused("lockdown is already on", code="already_locked")
    return _publish_rules(
        engine,
        _latest_rules(engine, lockdown=True),
        online=online,
        approval=approval,
        now=now,
        actor=actor,
        reason="lockdown",
    )


def lift(
    engine: Engine, *, online: OnlineKey, approval: ApprovalKey, now: datetime, actor: str
) -> PublishResult:
    """Restore the current rules without lockdown: a loosening, pending until the offline key signs it."""
    with Session(engine) as s:
        if not lockdown_state(s):
            raise PublishRefused("lockdown isn't on", code="not_locked")
    return _publish_rules(
        engine,
        _latest_rules(engine, lockdown=False),
        online=online,
        approval=approval,
        now=now,
        actor=actor,
        reason="lockdown_lift",
    )


def publish_trust(
    engine: Engine,
    trust: dict[str, Any],
    *,
    online: OnlineKey,
    approval: ApprovalKey,
    now: datetime,
    actor: str,
) -> PublishResult:
    """Ship a new approval trust (e2e flag, approver passkeys, WebAuthn RP) with the current rules.

    Turning e2e on, removing an approver or an origin tightens and goes out at once. Adding an approver,
    turning e2e off or changing the RP loosens and waits for the offline key (README 17.3 Settings, D-12).
    """
    if trust["e2e"] and not trust["approvers"]:
        raise PublishRefused("end-to-end signing needs at least one registered passkey", code="no_approvers")
    return _publish_rules(
        engine,
        _latest_rules(engine, trust=trust),
        online=online,
        approval=approval,
        now=now,
        actor=actor,
        reason="trust",
    )


def publish_trust_if_changed(
    engine: Engine,
    rp: RelyingParty,
    *,
    e2e: bool | None,
    online: OnlineKey,
    approval: ApprovalKey,
    now: datetime,
    actor: str,
) -> PublishResult | None:
    """After a passkey is added or removed, or e2e is toggled: publish the new trust if it differs."""
    with Session(engine) as s:
        current = bundles.latest_trust(s)
    if current is None:
        return None
    trust = trust_for(engine, rp, e2e=current["e2e"] if e2e is None else e2e)
    if trust == current:
        return None
    return publish_trust(engine, trust, online=online, approval=approval, now=now, actor=actor)


def pending_items(row: PendingRow) -> list[dict[str, Any]]:
    return list(json.loads(row.body))


def publish_file(engine: Engine) -> dict[str, Any]:
    """What `warden-sign sign` reads (agent/internal/offline/publish.go PublishFile)."""
    with Session(engine) as s:
        row = open_pending(s)
        if row is None:
            raise PublishRefused("there is no pending publish", code="no_pending")
        return {
            "v": 1,
            "version": row.version,
            "items": [
                {"target": it["target"], "previous": it["previous"], "bundle": it["bundle"]}
                for it in pending_items(row)
            ],
        }


class _TargetSig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    target: str
    sig: str


class _SigFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    v: Literal[1]
    version: int
    key_id: str
    signatures: tuple[_TargetSig, ...]


def _check_upload(s: Session, row: PendingRow | None, sf: _SigFile) -> tuple[str, str] | None:
    if row is None:
        return "no_pending", "there is no pending publish"
    if row.version != sf.version:
        return "wrong_version", f"the signature is for v{sf.version}; the pending publish is v{row.version}"
    if row.base_version != bundles.published_version(s):
        return "stale_pending", "policy was published since this was prepared; publish again"
    items = pending_items(row)
    sigs = {t.target: t.sig for t in sf.signatures}
    if len(sigs) != len(sf.signatures) or set(sigs) != {it["target"] for it in items}:
        return (
            "bad_offline_signature",
            "the signature file must cover every target in the pending publish once",
        )
    for it in items:
        if not offline_keys.verify(s, sf.key_id, sigs[it["target"]], bundles.signing_message(it["bundle"])):
            return (
                "bad_offline_signature",
                f"{it['target']}: not a valid signature from a registered offline key",
            )
    return None


def sign_upload(engine: Engine, raw: str, *, now: datetime, actor: str) -> PublishResult:
    """Verify `warden-sign`'s signature file against the registered offline keys, then publish."""
    try:
        sf = _SigFile.model_validate_json(raw)
    except ValidationError as exc:
        msg = f"not a warden-sign signature file: {exc.error_count()} error(s)"
        _audit(
            engine,
            now,
            actor,
            "policy_sign_upload_refused",
            "offline signature",
            code="bad_signature_file",
            message=msg,
        )
        raise PublishRefused(msg, code="bad_signature_file") from exc
    with Session(engine) as s, s.begin():
        row = open_pending(s)
        problem = _check_upload(s, row, sf)
        if problem is not None or row is None:
            code, msg = problem or ("no_pending", "there is no pending publish")
            audit.append(
                s,
                ts=now,
                actor=actor,
                action="policy_sign_upload_refused",
                subject="offline signature",
                detail={"code": code, "message": msg, "key_id": sf.key_id, "version": sf.version},
            )
        else:
            sigs = {t.target: t.sig for t in sf.signatures}
            out = []
            for it in pending_items(row):
                signed = {
                    **it["bundle"],
                    "signatures": [
                        *it["bundle"]["signatures"],
                        {"key": "offline", "key_id": sf.key_id, "alg": "ed25519", "sig": sigs[it["target"]]},
                    ],
                }
                changes = tuple(Change(c["path"], c["op"], c["effect"], c["detail"]) for c in it["changes"])
                out.append(TargetChange(it["target"], it["class"], changes, signed, it["previous"]))
            _store(s, out, now=now, actor=actor, how=f"online+offline {sf.key_id}")
            row.status, row.closed_at = "published", now.isoformat()
            s.add(row)
            return PublishResult("published", row.version, tuple(out))
    raise PublishRefused(msg, code=code)


def discard(engine: Engine, *, now: datetime, actor: str) -> int:
    with Session(engine) as s, s.begin():
        row = open_pending(s)
        if row is None:
            raise PublishRefused("there is no pending publish", code="no_pending")
        row.status, row.closed_at = "discarded", now.isoformat()
        s.add(row)
        audit.append(
            s, ts=now, actor=actor, action="policy_pending_discarded", subject=f"v{row.version}", detail={}
        )
        return row.version
