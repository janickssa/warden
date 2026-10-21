"""Signed, versioned policy bundles (README 7A, invariant 11).

A bundle is the compiled rules for one target plus the approval keys agents trust, signed with the online
key. Agents refuse unsigned, older, tampered, unknown-field or wrong-target bundles.

M2 scope (PLAN.md): each target gets one initial bundle (version 1). Changing policy afterwards needs M3's
publish flow (classifier + offline key), so until then `publish_initial` refuses to replace a bundle and
the dispatcher refuses plans while central policy differs from what the agent enforces.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from sqlmodel import Field, Session, SQLModel, col, select

from warden import audit
from warden.errors import WardenError
from warden.keys import OnlineKey
from warden.plans.canonical import canonical_bytes
from warden.policy.effective import effective_rules
from warden.policy.schema import Policy, Targets
from warden.policy_dist.compile import compile_rules
from warden.signing import ApprovalKey

DOMAIN = b"warden-bundle-v1\n"
BUNDLE_SCHEMA = 1
MIN_AGENT_VERSION = "0.1.0"


class PolicyUnpublished(WardenError):
    code = "policy_unpublished"


class BundleRow(SQLModel, table=True):
    __tablename__ = "bundles"

    id: int | None = Field(default=None, primary_key=True)
    target: str = Field(index=True)
    version: int = Field(index=True)
    sha256: str
    body: str
    created_at: str


def signing_message(bundle: dict[str, Any]) -> bytes:
    unsigned = {k: v for k, v in bundle.items() if k != "signatures"}
    return DOMAIN + canonical_bytes(unsigned)


def build_bundle(
    *,
    version: int,
    target: str,
    rules: dict[str, Any],
    change: str,
    approval_keys: list[dict[str, str]],
    issued_at: datetime,
) -> dict[str, Any]:
    return {
        "schema": BUNDLE_SCHEMA,
        "version": version,
        "issued_at": issued_at.isoformat(),
        "target": target,
        "min_agent_version": MIN_AGENT_VERSION,
        "change": change,
        "rules": rules,
        "approval_keys": approval_keys,
    }


def sign_bundle(bundle: dict[str, Any], online: OnlineKey) -> dict[str, Any]:
    sig = online.sign(signing_message(bundle))
    return {
        **bundle,
        "signatures": [{"key": "online", "key_id": online.key_id, "alg": "ed25519", "sig": sig}],
    }


def bundle_sha256(bundle: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(bundle)).hexdigest()


def approval_key_refs(approval: ApprovalKey) -> list[dict[str, str]]:
    return [{"key_id": approval.key_id, "public": approval.public_b64}]


def compiled_for(policy: Policy, targets: Targets, target: str) -> dict[str, Any]:
    t = targets.get(target)
    if t is None:
        raise WardenError(f"unknown target {target}", code="unknown_target")
    return compile_rules(effective_rules(policy, t), t)


def latest(session: Session, target: str) -> dict[str, Any] | None:
    row = session.exec(
        select(BundleRow)
        .where(col(BundleRow.target) == target)
        .order_by(col(BundleRow.version).desc())
        .limit(1)
    ).first()
    return None if row is None else dict(json.loads(row.body))


def published_version(session: Session) -> int:
    row = session.exec(select(BundleRow).order_by(col(BundleRow.version).desc()).limit(1)).first()
    return 0 if row is None else row.version


def publish_initial(
    session: Session,
    *,
    policy: Policy,
    targets: Targets,
    online: OnlineKey,
    approval: ApprovalKey,
    now: datetime,
    actor: str,
) -> list[str]:
    """Create bundle v1 for every target that has none. Returns the targets published.

    Refuses if an existing bundle differs from the current policy: changing published rules is M3.
    """
    published = []
    keys = approval_key_refs(approval)
    for t in targets.targets:
        rules = compiled_for(policy, targets, t.name)
        existing = latest(session, t.name)
        if existing is not None:
            if existing["rules"] != rules or existing["approval_keys"] != keys:
                raise PolicyUnpublished(
                    f"{t.name}: policy changed since bundle v{existing['version']}; publishing changes "
                    "(tighten/loosen with the offline key) arrives in M3"
                )
            continue
        bundle = sign_bundle(
            build_bundle(
                version=1, target=t.name, rules=rules, change="initial", approval_keys=keys, issued_at=now
            ),
            online,
        )
        digest = bundle_sha256(bundle)
        session.add(
            BundleRow(
                target=t.name,
                version=1,
                sha256=digest,
                body=canonical_bytes(bundle).decode(),
                created_at=now.isoformat(),
            )
        )
        audit.append(
            session,
            ts=now,
            actor=actor,
            action="policy_publish",
            subject=f"{t.name} · v1 · initial",
            detail={"target": t.name, "version": 1, "sha256": digest, "key_id": online.key_id},
        )
        published.append(t.name)
    return published


def check_published(session: Session, policy: Policy, targets: Targets, target: str) -> dict[str, Any]:
    """The bundle the agent enforces, if central policy still matches it; otherwise refuse."""
    bundle = latest(session, target)
    if bundle is None:
        raise PolicyUnpublished(f"no policy bundle for {target}; run `warden policy publish`")
    if bundle["rules"] != compiled_for(policy, targets, target):
        raise PolicyUnpublished(
            f"policy.yaml no longer matches bundle v{bundle['version']} for {target}; plans can't run until "
            "the change is published (M3)"
        )
    return bundle
