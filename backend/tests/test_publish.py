"""Publishing policy (README 7A): tighten now, loosen only with the offline key, test gate, lockdown."""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from factories import T0
from policyhelp import fixture_policy, fixture_targets
from sqlalchemy import Engine
from sqlmodel import Session

from warden import audit
from warden.actors import HumanActor
from warden.keys import OnlineKey, b64url, key_id_for, raw_public
from warden.plans.models import StepKind
from warden.policy.schema import Policy
from warden.policy_dist import bundle as b
from warden.policy_dist import offline_keys
from warden.policy_dist import publish as pub
from warden.signing import ApprovalKey

ALICE = HumanActor("cli", "alice")


@pytest.fixture
def keys(tmp_path: Path) -> tuple[OnlineKey, ApprovalKey]:
    return OnlineKey.generate(tmp_path / "online.key"), ApprovalKey.generate(tmp_path / "approval.key")


class Laptop:
    """Stands in for warden-sign: an offline key Warden only knows the public half of."""

    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = b64url(raw_public(self.private.public_key()))
        self.key_id = key_id_for(self.private.public_key())

    def sign(self, publish_file: dict[str, object], *, key_id: str | None = None) -> str:
        items = publish_file["items"]
        assert isinstance(items, list)
        sigs = [
            {
                "target": it["target"],
                "sig": "ed25519:" + b64url(self.private.sign(b.signing_message(it["bundle"]))),
            }
            for it in items
        ]
        return json.dumps(
            {"v": 1, "version": publish_file["version"], "key_id": key_id or self.key_id, "signatures": sigs}
        )


def register(engine: Engine, laptop: Laptop, role: str = "primary") -> None:
    with Session(engine) as s, s.begin():
        offline_keys.register(s, laptop.public, role=role, actor=ALICE, now=T0)


def do_publish(engine: Engine, keys: tuple[OnlineKey, ApprovalKey], policy: Policy) -> pub.PublishResult:
    online, approval = keys
    return pub.publish(
        engine,
        policy=policy,
        targets=fixture_targets(),
        online=online,
        approval=approval,
        now=T0,
        actor="cli:alice",
    )


def tighter(p: Policy) -> Policy:
    return p.model_copy(update={"deny_paths": (*p.deny_paths, "/srv/dev/secret")})


def looser(p: Policy) -> Policy:
    return p.model_copy(update={"deny_paths": tuple(d for d in p.deny_paths if d != "/srv/prod")})


def version(engine: Engine) -> int:
    with Session(engine) as s:
        return b.published_version(s)


def actions(engine: Engine) -> list[str]:
    with Session(engine) as s:
        return [e.action for e in audit.entries(s)]


def test_first_publish_is_initial_then_unchanged(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    r = do_publish(engine, keys, fixture_policy())
    assert r.outcome == "published"
    assert r.version == 1
    assert [(t.target, t.cls, t.bundle["change"]) for t in r.targets] == [
        ("dev", "initial", "initial"),
        ("dev2", "initial", "initial"),
        ("sec-auth", "initial", "initial"),
    ]
    again = do_publish(engine, keys, fixture_policy())
    assert again.outcome == "unchanged"
    assert version(engine) == 1


def test_tightening_publishes_at_once(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    do_publish(engine, keys, fixture_policy())
    r = do_publish(engine, keys, tighter(fixture_policy()))
    assert r.outcome == "published"
    assert version(engine) == 2
    dev = next(t for t in r.targets if t.target == "dev")
    assert dev.cls == "tighten"
    assert [c.text() for c in dev.changes] == ["↓ deny_paths add /srv/dev/secret"]
    assert dev.bundle["change"] == "tighten"
    assert [sig["key"] for sig in dev.bundle["signatures"]] == ["online"]
    with Session(engine) as s:
        latest = b.latest(s, "dev")
        assert latest is not None
        assert latest["version"] == 2
        assert "/srv/dev/secret" in latest["rules"]["deny_paths"]


def test_loosening_waits_for_the_offline_key(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    laptop = Laptop()
    register(engine, laptop)
    do_publish(engine, keys, fixture_policy())
    r = do_publish(engine, keys, looser(fixture_policy()))
    assert r.outcome == "pending"
    assert r.loosens == ("dev", "dev2", "sec-auth")
    assert version(engine) == 1  # nothing live yet
    pf = pub.publish_file(engine)
    assert pf["version"] == 2
    assert pf["items"][0]["previous"]["rules"]["deny_paths"][-1] == "/srv/prod"

    done = pub.sign_upload(engine, laptop.sign(pf), now=T0, actor="cli:alice")
    assert done.outcome == "published"
    assert version(engine) == 2
    with Session(engine) as s:
        latest = b.latest(s, "dev")
        assert latest is not None
        assert [sig["key"] for sig in latest["signatures"]] == ["online", "offline"]
        assert latest["change"] == "loosen"
        assert pub.open_pending(s) is None


def test_backup_key_can_sign(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    primary, backup = Laptop(), Laptop()
    register(engine, primary)
    register(engine, backup, "backup")
    do_publish(engine, keys, fixture_policy())
    do_publish(engine, keys, looser(fixture_policy()))
    assert pub.sign_upload(engine, backup.sign(pub.publish_file(engine)), now=T0, actor="x").version == 2


@pytest.mark.parametrize(
    "case", ["stranger", "claims_registered_id", "missing_target", "wrong_version", "junk"]
)
def test_bad_signature_files_refused(engine: Engine, keys: tuple[OnlineKey, ApprovalKey], case: str) -> None:
    laptop = Laptop()
    register(engine, laptop)
    do_publish(engine, keys, fixture_policy())
    do_publish(engine, keys, looser(fixture_policy()))
    pf = pub.publish_file(engine)
    if case == "stranger":
        raw = Laptop().sign(pf)
    elif case == "claims_registered_id":
        raw = Laptop().sign(pf, key_id=laptop.key_id)
    elif case == "missing_target":
        d = json.loads(laptop.sign(pf))
        d["signatures"] = d["signatures"][:-1]
        raw = json.dumps(d)
    elif case == "wrong_version":
        d = json.loads(laptop.sign(pf))
        d["version"] = 3
        raw = json.dumps(d)
    else:
        raw = '{"v": 1, "surprise": true}'
    with pytest.raises(pub.PublishRefused):
        pub.sign_upload(engine, raw, now=T0, actor="cli:alice")
    assert version(engine) == 1
    assert actions(engine)[-1] == "policy_sign_upload_refused"
    with Session(engine) as s:
        assert pub.open_pending(s) is not None


def test_no_offline_key_means_nothing_can_loosen(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    do_publish(engine, keys, fixture_policy())
    do_publish(engine, keys, looser(fixture_policy()))
    with pytest.raises(pub.PublishRefused):
        pub.sign_upload(engine, Laptop().sign(pub.publish_file(engine)), now=T0, actor="x")
    assert version(engine) == 1


def test_signature_doesnt_cover_a_different_bundle(
    engine: Engine, keys: tuple[OnlineKey, ApprovalKey]
) -> None:
    """A signature over what Warden showed can't be reused for other rules."""
    laptop = Laptop()
    register(engine, laptop)
    do_publish(engine, keys, fixture_policy())
    do_publish(engine, keys, looser(fixture_policy()))
    pf = pub.publish_file(engine)
    pf["items"][0]["bundle"]["rules"]["deny_paths"] = []
    with pytest.raises(pub.PublishRefused):
        pub.sign_upload(engine, laptop.sign(pf), now=T0, actor="x")


def test_urgent_tighten_supersedes_pending(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    laptop = Laptop()
    register(engine, laptop)
    do_publish(engine, keys, fixture_policy())
    do_publish(engine, keys, looser(fixture_policy()))
    old = pub.publish_file(engine)
    r = do_publish(engine, keys, tighter(fixture_policy()))
    assert r.outcome == "published"
    assert r.superseded == 2
    assert r.version == 3  # v2 was reserved and is never reused
    with pytest.raises(pub.PublishRefused):
        pub.sign_upload(engine, laptop.sign(old), now=T0, actor="x")
    assert version(engine) == 3


def test_discard(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    do_publish(engine, keys, fixture_policy())
    do_publish(engine, keys, looser(fixture_policy()))
    assert pub.discard(engine, now=T0, actor="x") == 2
    with pytest.raises(pub.PublishRefused):
        pub.discard(engine, now=T0, actor="x")
    assert do_publish(engine, keys, tighter(fixture_policy())).version == 3


def test_test_gate_blocks_publish(
    engine: Engine, keys: tuple[OnlineKey, ApprovalKey], monkeypatch: pytest.MonkeyPatch
) -> None:
    do_publish(engine, keys, fixture_policy())
    # Every shipped gate case is also refused by the baseline, so a policy alone can't fail them today.
    # Prove the mechanism with a case the fixture policy allows.
    cases = (*pub.gate_cases(), pub.GateCase(id="npm-ci", kind=StepKind.SHELL, command="npm ci"))
    monkeypatch.setattr(pub, "gate_cases", lambda: cases)
    with pytest.raises(pub.GateFailed) as exc:
        do_publish(engine, keys, tighter(fixture_policy()))
    assert "npm-ci" in exc.value.message
    assert version(engine) == 1
    assert actions(engine)[-1] == "policy_publish_blocked"


def test_gate_passes_for_fixture_policy() -> None:
    assert pub.run_gate(fixture_policy(), fixture_targets()) == []
    assert len(pub.gate_cases()) >= 20


def test_lockdown_and_lift(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    online, approval = keys
    laptop = Laptop()
    register(engine, laptop)
    do_publish(engine, keys, fixture_policy())
    r = pub.lockdown(engine, online=online, approval=approval, now=T0, actor="cli:alice")
    assert r.outcome == "published"
    assert {t.cls for t in r.targets} == {"tighten"}
    with Session(engine) as s:
        assert pub.lockdown_state(s)
        # the dispatcher's consistency check still passes: policy.yaml + lockdown is what's published
        b.check_published(s, fixture_policy(), fixture_targets(), "dev")
    with pytest.raises(pub.PublishRefused):
        pub.lockdown(engine, online=online, approval=approval, now=T0, actor="x")

    # An urgent tighten during lockdown keeps lockdown on.
    t = do_publish(engine, keys, tighter(fixture_policy()))
    assert t.outcome == "published"
    with Session(engine) as s:
        assert pub.lockdown_state(s)

    lifted = pub.lift(engine, online=online, approval=approval, now=T0 + timedelta(minutes=5), actor="x")
    assert lifted.outcome == "pending"
    with Session(engine) as s:
        assert pub.lockdown_state(s)  # still locked until signed
    pub.sign_upload(engine, laptop.sign(pub.publish_file(engine)), now=T0, actor="x")
    with Session(engine) as s:
        assert not pub.lockdown_state(s)
        latest = b.latest(s, "dev")
        assert latest is not None
        assert "/srv/dev/secret" in latest["rules"]["deny_paths"]  # the tighten made during lockdown stays
    with pytest.raises(pub.PublishRefused):
        pub.lift(engine, online=online, approval=approval, now=T0, actor="x")


def test_lockdown_needs_something_published(engine: Engine, keys: tuple[OnlineKey, ApprovalKey]) -> None:
    online, approval = keys
    with pytest.raises(pub.PublishRefused):
        pub.lockdown(engine, online=online, approval=approval, now=T0, actor="x")


def test_offline_key_registration(engine: Engine) -> None:
    a, c = Laptop(), Laptop()
    register(engine, a)
    with Session(engine) as s, s.begin(), pytest.raises(offline_keys.OfflineKeyRefused):
        offline_keys.register(s, Laptop().public, role="primary", actor=ALICE, now=T0)
    with Session(engine) as s, s.begin(), pytest.raises(offline_keys.OfflineKeyRefused):
        offline_keys.register(s, a.public, role="backup", actor=ALICE, now=T0)
    for bad in ("not-base64!", b64url(b"short")):
        with Session(engine) as s, s.begin(), pytest.raises(offline_keys.OfflineKeyRefused):
            offline_keys.register(s, bad, role="backup", actor=ALICE, now=T0)
    register(engine, c, "backup")
    with Session(engine) as s:
        assert [r["key_id"] for r in offline_keys.refs(s)] == [a.key_id, c.key_id]
    assert actions(engine) == ["offline_key_registered"] * 2
