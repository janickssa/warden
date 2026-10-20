"""Plan lifecycle through the service: every transition in README section 4."""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine, text
from sqlmodel import Session
from svc import ALICE, CLAUDE, DASH, World, make_world

from warden import audit
from warden.actors import HumanActor
from warden.errors import ApprovalRefused, DecidedElsewhere, DispatchRefused, InputRefused, NotHuman
from warden.plans.models import GatekeeperVerdict, PlanStatus, Risk, StepEdit, StepStatus, Verdict
from warden.plans.runs import StepOutcome

S = PlanStatus
DEPLOY: list[str | tuple[str, str]] = [
    ("git", "git -C /srv/dev/myapp checkout v1.4.2"),
    "npm ci",
    ("docker", "docker compose -p dev-myapp up -d"),
    ("http_check", "curl -I http://localhost:8080/health"),
]


@pytest.fixture
def w(engine: Engine, tmp_path: Path) -> World:
    return make_world(engine, tmp_path)


def actions(w: World) -> list[str]:
    with Session(w.engine) as s:
        return [e.action for e in audit.entries(s)]


# --- propose -------------------------------------------------------------------------------------------


def test_propose_reaches_awaiting_with_escalate_and_no_gatekeepers(w: World) -> None:
    p = w.propose(*DEPLOY)
    assert p.status == S.AWAITING_APPROVAL
    assert p.final_verdict == Verdict.ESCALATE  # no gatekeepers configured: never auto-allow (D-19)
    assert p.policy_result.ok
    assert p.hash.startswith("sha256:")
    assert p.requested_by == "claude-code"
    assert (p.expires_at - p.created_at).total_seconds() == 30 * 60
    assert actions(w) == ["propose_plan", "review"]


def test_policy_deny_is_final(w: World) -> None:
    p = w.propose("npm ci", "npm publish")
    assert p.status == S.REJECTED
    assert p.reject_reason == "policy"
    assert p.policy_result.violations[0].step == 2
    with pytest.raises(DecidedElsewhere):
        w.approve(p)
    with pytest.raises(DecidedElsewhere):
        w.svc.approve_with_edits(p.id, [StepEdit(n=2, command="npm test")], ALICE)
    assert actions(w) == ["propose_plan", "policy_deny"]


def test_unknown_target_refused(w: World) -> None:
    with pytest.raises(InputRefused, match="unknown target"):
        w.propose("npm ci", target="prod")


def test_claude_cannot_mark_steps_edited(w: World) -> None:
    from warden.plans.models import ProposeRequest, Step, StepKind

    req = ProposeRequest(
        goal="x",
        target="dev",
        steps=(
            Step(
                n=1,
                kind=StepKind.SHELL,
                command="npm ci",
                purpose="p",
                cwd="/srv/dev/myapp",
                timeout_s=60,
                edited=True,
            ),
        ),
    )
    assert not w.svc.propose(req, CLAUDE).steps[0].edited


def test_invisible_characters_in_goal_refused(w: World) -> None:
    with pytest.raises(InputRefused):
        w.propose("npm ci", goal="Deploy\u202emyapp")


# --- approve -------------------------------------------------------------------------------------------


def test_approve(w: World) -> None:
    p = w.approve(w.propose(*DEPLOY))
    assert p.status == S.APPROVED
    assert p.approval is not None
    assert p.approval.by == "cli:alice"
    assert p.approval.hash == p.hash
    assert p.approval.signature.key_id == w.key.key_id
    assert actions(w)[-1] == "approve"


@pytest.mark.parametrize("actor", [CLAUDE, "cli:alice", None])
def test_only_humans_can_approve_edit_or_reject(w: World, actor: object) -> None:
    p = w.propose("npm ci")
    with pytest.raises(NotHuman):
        w.svc.approve(p.id, p.hash[7:19], actor)  # type: ignore[arg-type]
    with pytest.raises(NotHuman):
        w.svc.approve_with_edits(p.id, [StepEdit(n=1, command="npm test")], actor)  # type: ignore[arg-type]
    with pytest.raises(NotHuman):
        w.svc.reject(p.id, actor)  # type: ignore[arg-type]
    assert w.svc.get(p.id).status == S.AWAITING_APPROVAL


@pytest.mark.parametrize("prefix", ["", "abc", "sha256:12", "zzzzzzzzzzzzzz", "0" * 12])
def test_approve_needs_matching_hash_prefix(w: World, prefix: str) -> None:
    p = w.propose("npm ci")
    with pytest.raises(ApprovalRefused):
        w.svc.approve(p.id, prefix, ALICE)


def test_full_hash_and_sha256_prefix_accepted(w: World) -> None:
    p = w.propose("npm ci")
    assert w.svc.approve(p.id, p.hash, ALICE).status == S.APPROVED


def test_approve_twice_is_decided_elsewhere(w: World) -> None:
    p = w.propose("npm ci")
    w.approve(p)
    with pytest.raises(DecidedElsewhere):
        w.approve(p, DASH)


def test_tampered_plan_in_db_refused_on_approve(w: World) -> None:
    p = w.propose("npm ci")
    body = w.svc.get(p.id).model_dump_json().replace("npm ci", "npm test")
    with w.engine.begin() as conn:
        conn.execute(text("UPDATE plans SET body=:b WHERE id=:i"), {"b": body, "i": p.id})
    with pytest.raises(ApprovalRefused) as exc:
        w.approve(p)
    assert exc.value.code == "hash_mismatch"
    assert "tamper_detected" in actions(w)


def test_cli_cannot_approve_passkey_group(w: World) -> None:
    p = w.propose("npm test", target="sec-auth", cwd="/srv/app")
    with pytest.raises(ApprovalRefused) as exc:
        w.approve(p)
    assert exc.value.code == "passkey_required"


def test_cli_cannot_approve_high_risk(engine: Engine, tmp_path: Path) -> None:
    class HighRisk:
        def review(self, *_: object) -> tuple[GatekeeperVerdict, ...]:
            return (
                GatekeeperVerdict(
                    name="local",
                    model="m",
                    verdict=Verdict.ESCALATE,
                    risk=Risk.HIGH,
                    summary="Changes the schema",
                ),
            )

    w = make_world(engine, tmp_path, panel=HighRisk())
    p = w.propose("npm ci")
    with pytest.raises(ApprovalRefused) as exc:
        w.approve(p)
    assert exc.value.code == "passkey_required"


def test_gatekeeper_deny_still_reaches_human(engine: Engine, tmp_path: Path) -> None:
    class Deny:
        def review(self, *_: object) -> tuple[GatekeeperVerdict, ...]:
            return (
                GatekeeperVerdict(
                    name="local", model="m", verdict=Verdict.DENY, risk=Risk.MEDIUM, summary="x"
                ),
            )

    w = make_world(engine, tmp_path, panel=Deny())
    p = w.propose("npm ci")
    assert p.status == S.AWAITING_APPROVAL
    assert p.final_verdict == Verdict.DENY
    assert w.approve(p, DASH).status == S.APPROVED  # the human has the final say over gatekeepers


def test_crashing_panel_counts_as_escalate(engine: Engine, tmp_path: Path) -> None:
    class Crash:
        def review(self, *_: object) -> tuple[GatekeeperVerdict, ...]:
            raise TimeoutError

    w = make_world(engine, tmp_path, panel=Crash())
    p = w.propose("npm ci")
    assert p.final_verdict == Verdict.ESCALATE
    assert p.gatekeepers[0].unavailable


# --- approve with edits --------------------------------------------------------------------------------


def test_approve_with_edits_rereviews_with_new_hash(w: World) -> None:
    p = w.propose("npm ci", "npm test")
    edited = w.svc.approve_with_edits(p.id, [StepEdit(n=2, command="npm run build")], DASH)
    assert edited.id == p.id
    assert edited.status == S.AWAITING_APPROVAL  # back for a fresh approval; nothing runs yet
    assert edited.hash != p.hash
    assert edited.steps[1].edited
    assert edited.steps[1].command == "npm run build"
    assert not edited.steps[0].edited
    assert actions(w)[-2:] == ["approve_with_edits", "review"]
    with Session(w.engine) as s:
        entry = next(e for e in audit.entries(s) if e.action == "approve_with_edits")
    assert '"before":"npm test"' in entry.detail
    assert '"after":"npm run build"' in entry.detail
    # The old hash can't be used to approve the edited plan.
    with pytest.raises(ApprovalRefused):
        w.svc.approve(p.id, p.hash[7:19], DASH)
    assert w.svc.approve(p.id, edited.hash[7:19], DASH).status == S.APPROVED


def test_edit_that_policy_denies_is_rejected(w: World) -> None:
    p = w.propose("npm ci")
    edited = w.svc.approve_with_edits(p.id, [StepEdit(n=1, command="npm ci; rm -rf /")], DASH)
    assert edited.status == S.REJECTED
    assert edited.policy_result.violations[0].code == "forbidden_char"


@pytest.mark.parametrize(
    "edits",
    [
        [],
        [StepEdit(n=9, command="npm ci")],
        [StepEdit(n=1, command="npm ci")],
        [StepEdit(n=1, command="npm test"), StepEdit(n=1, command="npm ci")],
    ],
)
def test_bad_edits_refused(w: World, edits: list[StepEdit]) -> None:
    p = w.propose("npm ci")
    with pytest.raises(InputRefused):
        w.svc.approve_with_edits(p.id, edits, DASH)
    assert w.svc.get(p.id).status == S.AWAITING_APPROVAL


# --- reject / expire -----------------------------------------------------------------------------------


def test_reject_with_reason(w: World) -> None:
    p = w.svc.reject(w.propose("npm ci").id, DASH, "Not now")
    assert p.status == S.REJECTED
    assert p.reject_reason == "Not now"


def test_expiry_after_30_min(w: World) -> None:
    p = w.propose("npm ci")
    w.clock.advance(minutes=29, seconds=59)
    assert w.svc.expire_due() == []
    w.clock.advance(seconds=1)
    assert [x.id for x in w.svc.expire_due()] == [p.id]
    assert w.svc.get(p.id).status == S.EXPIRED


def test_approving_expired_plan_refused(w: World) -> None:
    p = w.propose("npm ci")
    w.clock.advance(minutes=31)
    with pytest.raises(ApprovalRefused) as exc:
        w.approve(p)
    assert exc.value.code == "expired"
    assert w.svc.get(p.id).status == S.EXPIRED


def test_approved_but_never_run_expires(w: World) -> None:
    p = w.approve(w.propose("npm ci"))
    w.clock.advance(minutes=31)
    assert [x.id for x in w.svc.expire_due()] == [p.id]


# --- invalidated / held --------------------------------------------------------------------------------


def _tighten(w: World) -> None:
    """Policy v2 adds a deny pattern for `npm test`."""
    cmds = w.policy.commands
    w.policy = w.policy.model_copy(
        update={"commands": cmds.model_copy(update={"deny_patterns": (*cmds.deny_patterns, r"npm\s+test")})}
    )
    w.version = 2


@pytest.mark.parametrize("approve_first", [False, True])
def test_new_policy_invalidates_waiting_and_approved(w: World, approve_first: bool) -> None:
    p = w.propose("npm ci", "npm test")
    if approve_first:
        w.approve(p)
    keep = w.propose("npm ci")
    _tighten(w)
    out = w.svc.invalidate_against_current_policy()
    assert [x.id for x in out] == [p.id]
    got = w.svc.get(p.id)
    assert got.status == S.INVALIDATED
    assert got.invalidated_by == 2
    assert got.invalid_reason is not None
    assert got.invalid_reason.startswith("Policy v2 denies step 2 (npm test)")
    assert w.svc.get(keep.id).status == S.AWAITING_APPROVAL


def test_approve_after_tightening_invalidates(w: World) -> None:
    p = w.propose("npm test")
    _tighten(w)
    with pytest.raises(ApprovalRefused) as exc:
        w.approve(p)
    assert exc.value.code == "invalidated"
    assert w.svc.get(p.id).status == S.INVALIDATED


def test_hold_and_release(w: World) -> None:
    p = w.approve(w.propose("npm ci"))
    held = w.svc.hold(p.id, "dev is behind on policy (v41)")
    assert held.status == S.HELD
    with pytest.raises(DispatchRefused):
        w.svc.validate_for_dispatch(p.id)
    assert w.svc.release(p.id).status == S.APPROVED
    w.svc.validate_for_dispatch(p.id)


def test_held_plan_can_be_invalidated_or_expire(w: World) -> None:
    a = w.approve(w.propose("npm test"))
    w.svc.hold(a.id, "lockdown")
    _tighten(w)
    assert [x.id for x in w.svc.invalidate_against_current_policy()] == [a.id]
    b = w.approve(w.propose("npm ci"))
    w.svc.hold(b.id, "agent offline")
    w.clock.advance(minutes=31)
    with pytest.raises(DispatchRefused):
        w.svc.release(b.id)
    assert w.svc.get(b.id).status == S.EXPIRED


# --- dispatch, run, revise -----------------------------------------------------------------------------


def test_validate_for_dispatch(w: World) -> None:
    p = w.approve(w.propose(*DEPLOY))
    env = w.svc.validate_for_dispatch(p.id)
    assert env.plan_hash == p.hash
    assert env.template["target"] == "dev"


def test_dispatch_refuses_unapproved(w: World) -> None:
    p = w.propose("npm ci")
    with pytest.raises(DispatchRefused) as exc:
        w.svc.validate_for_dispatch(p.id)
    assert exc.value.code == "not_approved"


def test_dispatch_refuses_tampered_step(w: World) -> None:
    p = w.approve(w.propose("npm ci"))
    body = w.svc.get(p.id).model_dump_json().replace('"npm ci"', '"npm test"')
    with w.engine.begin() as conn:
        conn.execute(text("UPDATE plans SET body=:b WHERE id=:i"), {"b": body, "i": p.id})
    with pytest.raises(DispatchRefused) as exc:
        w.svc.validate_for_dispatch(p.id)
    assert exc.value.code == "hash_mismatch"
    assert "dispatch_refused" in actions(w)


def test_dispatch_refuses_retargeted_plan(w: World) -> None:
    p = w.approve(w.propose("npm ci"))
    body = w.svc.get(p.id).model_dump_json().replace('"target":"dev"', '"target":"dev2"')
    with w.engine.begin() as conn:
        conn.execute(text("UPDATE plans SET body=:b WHERE id=:i"), {"b": body, "i": p.id})
    with pytest.raises(DispatchRefused) as exc:
        w.svc.validate_for_dispatch(p.id)
    assert exc.value.code == "hash_mismatch"


def test_dispatch_refuses_forged_approval(w: World, tmp_path: Path) -> None:
    from warden.signing import ApprovalKey, approval_payload

    p = w.approve(w.propose("npm ci"))
    assert p.approval is not None
    mallory = ApprovalKey.generate(tmp_path / "mallory.key")
    payload = approval_payload(
        plan_hash=p.hash,
        plan_id=p.id,
        target=p.target,
        approved_at=p.approval.at,
        expires_at=p.expires_at,
        by=p.approval.by,
    )
    forged = p.model_copy(
        update={"approval": p.approval.model_copy(update={"signature": mallory.sign(payload)})}
    )
    with w.engine.begin() as conn:
        conn.execute(text("UPDATE plans SET body=:b WHERE id=:i"), {"b": forged.model_dump_json(), "i": p.id})
    with pytest.raises(DispatchRefused) as exc:
        w.svc.validate_for_dispatch(p.id)
    assert exc.value.code == "bad_signature"


def test_run_succeeds(w: World) -> None:
    p = w.approve(w.propose("npm ci", "npm test"))
    w.svc.start_run(p.id)
    done = w.svc.finish_run(p.id, [StepOutcome(n=1, exit_code=0), StepOutcome(n=2, exit_code=0)])
    assert done.status == S.SUCCEEDED
    assert [r.status for r in done.step_results] == [StepStatus.SUCCEEDED, StepStatus.SUCCEEDED]


def test_cannot_start_twice(w: World) -> None:
    p = w.approve(w.propose("npm ci"))
    w.svc.start_run(p.id)
    with pytest.raises(DispatchRefused):
        w.svc.start_run(p.id)


def test_fail_stop_and_revise(w: World) -> None:
    """The prototype's story: npm ci fails at step 3, Claude revises, the human sees the diff."""
    first = w.approve(w.propose(*DEPLOY[:1], "npm ci", *DEPLOY[2:]))
    w.svc.start_run(first.id)
    failed = w.svc.finish_run(first.id, [StepOutcome(n=1, exit_code=0), StepOutcome(n=2, exit_code=1)])
    assert failed.status == S.FAILED
    assert failed.failed_at == 2
    assert failed.fail_reason == "exit_code"
    assert [r.status for r in failed.step_results] == [
        StepStatus.SUCCEEDED,
        StepStatus.FAILED,
        StepStatus.SKIPPED,
        StepStatus.SKIPPED,
    ]
    # A failed plan is never resumed.
    with pytest.raises(DecidedElsewhere):
        w.approve(failed)
    with pytest.raises(DispatchRefused):
        w.svc.start_run(failed.id)

    revision = w.propose(
        DEPLOY[0], "npm install --package-lock-only", "npm ci", *DEPLOY[2:], revises=first.id
    )
    assert revision.revises == first.id
    rows = w.svc.diff(first.id, revision.id)
    assert [r.op for r in rows] == ["same", "added", "same", "same", "same"]
    assert w.approve(revision, DASH).status == S.APPROVED


def test_revision_rules(w: World) -> None:
    waiting = w.propose("npm ci")
    with pytest.raises(InputRefused):
        w.propose("npm ci", revises=waiting.id)  # can't revise a plan that hasn't finished
    rejected = w.svc.reject(w.propose("npm ci").id, DASH)
    with pytest.raises(InputRefused):
        w.propose("npm ci", target="dev2", revises=rejected.id)  # same target only
    assert w.propose("npm ci", revises=rejected.id).revises == rejected.id


def test_kill_switch_cancels(w: World) -> None:
    p = w.approve(w.propose("npm ci", "npm test"))
    w.svc.start_run(p.id)
    done = w.svc.finish_run(p.id, [StepOutcome(n=1, exit_code=None, killed=True)])
    assert done.status == S.CANCELLED
    assert [r.status for r in done.step_results] == [StepStatus.CANCELLED, StepStatus.SKIPPED]


def test_audit_chain_verifies_after_everything(w: World) -> None:
    test_fail_stop_and_revise(w)
    with Session(w.engine) as s:
        assert audit.verify(s).ok


def test_human_actor_ids_are_validated() -> None:
    with pytest.raises(ValueError, match="invalid"):
        HumanActor("cli", "alice; rm -rf /")
