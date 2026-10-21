"""Policy bundles (README 7A) and the cross-language vectors the Go agent verifies.

Regenerate vectors with: UPDATE_FIXTURES=1 uv run pytest tests/test_bundle.py
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from factories import T0
from policyhelp import FIXTURES, fixture_policy, fixture_targets
from sqlalchemy import Engine
from sqlmodel import Session

from warden.keys import OnlineKey
from warden.plans.canonical import canonical_bytes
from warden.plans.hashing import plan_hash
from warden.plans.models import Plan, PlanStatus, PolicyResult, Step, StepKind
from warden.policy_dist import bundle as b
from warden.policy_dist import publish
from warden.signing import ApprovalKey, approval_payload


def fixed_keys() -> tuple[OnlineKey, ApprovalKey]:
    online = OnlineKey(Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
    approval = ApprovalKey(Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64))))
    return online, approval


@pytest.fixture
def keys(tmp_path: Path) -> tuple[OnlineKey, ApprovalKey]:
    return OnlineKey.generate(tmp_path / "online.key"), ApprovalKey.generate(tmp_path / "approval.key")


def test_published_policy_must_match_config(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    online, approval = keys
    publish.publish(
        engine,
        policy=fixture_policy(),
        targets=fixture_targets(),
        online=online,
        approval=approval,
        now=T0,
        actor="cli:alice",
    )
    policy = fixture_policy()
    looser = policy.model_copy(update={"commands": policy.commands.model_copy(update={"deny_patterns": ()})})
    with Session(engine) as s:
        assert b.check_published(s, policy, fixture_targets(), "dev")["version"] == 1
        with pytest.raises(b.PolicyUnpublished):
            b.check_published(s, looser, fixture_targets(), "dev")


def test_no_bundle_refused(engine: Engine) -> None:
    with Session(engine) as s, pytest.raises(b.PolicyUnpublished):
        b.check_published(s, fixture_policy(), fixture_targets(), "dev")


def test_signature_covers_everything_but_signatures(keys: tuple[OnlineKey, ApprovalKey]) -> None:
    online, approval = keys
    rules = b.compiled_for(fixture_policy(), fixture_targets(), "dev")
    signed = b.sign_bundle(
        b.build_bundle(
            version=1,
            target="dev",
            rules=rules,
            change="initial",
            approval_keys=b.approval_key_refs(approval),
            issued_at=T0,
        ),
        online,
    )
    msg = b.signing_message(signed)
    assert msg.startswith(b.DOMAIN)
    assert b"signatures" not in msg
    tampered = {**signed, "target": "dev2"}
    assert b.signing_message(tampered) != msg


# --- vectors for the Go agent -------------------------------------------------------------------------


def make_vectors() -> dict[str, object]:
    online, approval = fixed_keys()
    rules = b.compiled_for(fixture_policy(), fixture_targets(), "dev")
    refs = b.approval_key_refs(approval)
    bundle = b.sign_bundle(
        b.build_bundle(
            version=1, target="dev", rules=rules, change="initial", approval_keys=refs, issued_at=T0
        ),
        online,
    )
    bundle_v2 = b.sign_bundle(
        b.build_bundle(
            version=2,
            target="dev",
            rules=rules,
            change="tighten",
            approval_keys=refs,
            issued_at=T0 + timedelta(hours=1),
        ),
        online,
    )
    plan = Plan(
        id="pln_01JB7Q3K0000000000000000AA",
        revises=None,
        goal="Install and test",
        target="dev",
        requested_by="claude-code",
        steps=(
            Step(
                n=1,
                kind=StepKind.SHELL,
                command="npm ci",
                purpose="Install",
                cwd="/srv/dev/myapp",
                timeout_s=300,
            ),
            Step(
                n=2,
                kind=StepKind.SHELL,
                command="npm test",
                purpose="Test",
                cwd="/srv/dev/myapp",
                timeout_s=300,
            ),
        ),
        hash="",
        status=PlanStatus.APPROVED,
        policy_result=PolicyResult.passed(),
        created_at=T0,
        expires_at=T0 + timedelta(minutes=30),
    )
    h = plan_hash(plan)
    expires = T0 + timedelta(minutes=30)
    payload = approval_payload(
        plan_hash=h, plan_id=plan.id, target="dev", approved_at=T0, expires_at=expires, by="cli:alice"
    )
    sig = approval.sign(payload)
    return {
        "online_public": online.public_b64,
        "online_key_id": online.key_id,
        "bundle_v1": bundle,
        "bundle_v2_tighten": bundle_v2,
        "run": {
            "template": plan.template(),
            "plan_hash": h,
            "approval": {
                "by": "cli:alice",
                "at": T0.isoformat(),
                "expires_at": expires.isoformat(),
                "hash": h,
                "signature": sig.model_dump(),
            },
        },
    }


def test_agent_vectors_are_current() -> None:
    text = json.dumps(make_vectors(), indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path = FIXTURES / "agent_vectors.json"
    if os.environ.get("UPDATE_FIXTURES") == "1":
        path.write_text(text, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == text, "run UPDATE_FIXTURES=1 to regenerate"


def test_vector_hash_is_canonical() -> None:
    v = make_vectors()
    run = v["run"]
    assert isinstance(run, dict)
    import hashlib

    assert run["plan_hash"] == "sha256:" + hashlib.sha256(canonical_bytes(run["template"])).hexdigest()
