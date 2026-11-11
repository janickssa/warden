"""Push for the iPhone app (M8): which events notify, what the payload holds, and APNs delivery."""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from factories import T0
from sqlalchemy import Engine
from sqlmodel import Session, select
from svc import ALICE, World

from warden import notify, push
from warden.config import NotificationSettings, PushSettings, Settings
from warden.plans.runs import StepOutcome
from warden.signing import ApprovalKey


@pytest.fixture
def world(engine: Engine, tmp_path: Path) -> World:
    return World(engine=engine, key=ApprovalKey.generate(tmp_path / "approval.key"))


def rows(engine: Engine) -> list[notify.NotificationRow]:
    with Session(engine) as s:
        return list(s.exec(select(notify.NotificationRow)))


def test_events_queue_notifications(world: World) -> None:
    p = world.propose("npm ci", "npm test")
    [n] = rows(world.engine)
    assert (n.kind, n.subject, n.category) == ("approval_needed", p.id, "APPROVAL")
    assert n.title == "Approval needed · dev"
    assert n.body.endswith("· 2 steps")  # no gatekeeper answered, so no risk to show
    world.svc.approve(p.id, p.hash, ALICE)
    world.svc.start_run(p.id)
    world.svc.finish_run(p.id, [StepOutcome(n=1, exit_code=2)])
    failed = rows(world.engine)[-1]
    assert (failed.kind, failed.title) == ("plan_failed", "✕ Failed at step 1 · dev")
    assert "npm" not in failed.body  # never commands or output through Apple


def test_high_risk_is_open_only_and_danish(engine: Engine) -> None:
    with Session(engine, expire_on_commit=False) as s, s.begin():
        row = notify.approval_needed(
            s, plan_id="pln_x", target="sec-auth", goal="Rotate keys", steps=1, risk="high", lang="da", now=T0
        )
    assert row.category == "OPEN"
    assert row.title == "■ Plan med høj risiko · sec-auth"
    assert row.body == "Rotate keys · 1 trin · ■ Høj risiko"


def test_payload_carries_no_commands(engine: Engine) -> None:
    with Session(engine, expire_on_commit=False) as s, s.begin():
        row = notify.agent_refused(
            s, plan_id="pln_y", target="dev", reason="step 2 · policy_violation: x", lang="en", now=T0
        )
    p = push.payload(row)
    assert p["aps"]["category"] == "OPEN"
    assert p["subject"] == "pln_y"
    assert set(p) == {"aps", "kind", "subject"}


class FakeAPNs:
    def __init__(self, statuses: list[tuple[int, dict[str, Any]]] | None = None) -> None:
        self.statuses = statuses or []
        self.calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

    async def __call__(self, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
        self.calls.append((url, headers, json.loads(body)))
        status, resp = self.statuses.pop(0) if self.statuses else (200, {})
        return status, json.dumps(resp).encode()


@pytest.fixture
def key(tmp_path: Path) -> ec.EllipticCurvePrivateKey:
    k = ec.generate_private_key(ec.SECP256R1())
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700)
    pem = k.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (secrets / "apns.p8").write_bytes(pem)
    (secrets / "apns.p8").chmod(0o600)
    return k


def make(engine: Engine, tmp_path: Path, fake: FakeAPNs, **notifications: bool) -> push.Pusher:
    settings = Settings(
        push=PushSettings(enabled=True, key_id="ABC123DEFG", team_id="TEAM123456"),
        notifications=NotificationSettings(**notifications),
    )
    return push.Pusher(
        engine, lambda: settings, tmp_path / "secrets", transport=fake, clock=lambda: 1_800_000_000.0
    )


def test_delivery_with_a_valid_jwt(engine: Engine, tmp_path: Path, key: ec.EllipticCurvePrivateKey) -> None:
    push.register(engine, credential_id="cred", name="iPhone", token="ab" * 32, now=T0, actor="dashboard:a")
    with Session(engine) as s, s.begin():
        notify.approval_needed(
            s, plan_id="pln_1", target="dev", goal="Deploy", steps=3, risk="low", lang="en", now=T0
        )
    fake = FakeAPNs()
    assert asyncio.run(make(engine, tmp_path, fake).deliver_once()) == 1
    [(url, headers, body)] = fake.calls
    assert url == f"https://api.push.apple.com/3/device/{'ab' * 32}"
    assert headers["apns-topic"] == "dk.schwabejss.warden"
    assert body["aps"]["alert"] == {"title": "Approval needed · dev", "body": "Deploy · 3 steps · ● Low risk"}
    jwt = headers["authorization"].removeprefix("bearer ")
    head, claims, sig = jwt.split(".")

    def pad(x: str) -> bytes:
        return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))

    assert json.loads(pad(head)) == {"alg": "ES256", "kid": "ABC123DEFG"}
    assert json.loads(pad(claims)) == {"iss": "TEAM123456", "iat": 1_800_000_000}
    raw = pad(sig)
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    key.public_key().verify(der, f"{head}.{claims}".encode(), ec.ECDSA(hashes.SHA256()))
    assert asyncio.run(make(engine, tmp_path, fake).deliver_once()) == 0  # delivered once


def test_preferences_dead_tokens_and_retries(
    engine: Engine, tmp_path: Path, key: ec.EllipticCurvePrivateKey
) -> None:
    push.register(engine, credential_id="cred", name="old", token="cd" * 32, now=T0, actor="x")
    push.register(engine, credential_id="cred", name="new", token="ef" * 32, now=T0, actor="x")
    with Session(engine) as s, s.begin():
        notify.plan_failed(
            s, plan_id="pln_2", target="dev", goal="g", failed_at=1, reason=None, lang="en", now=T0
        )
    off = FakeAPNs()
    assert asyncio.run(make(engine, tmp_path, off, plan_failed=False).deliver_once()) == 1
    assert off.calls == []  # switched off: marked done without sending
    with Session(engine) as s, s.begin():
        notify.plan_failed(
            s, plan_id="pln_3", target="dev", goal="g", failed_at=1, reason=None, lang="en", now=T0
        )
    fake = FakeAPNs([(410, {"reason": "Unregistered"}), (500, {"reason": "InternalServerError"})])
    pusher = make(engine, tmp_path, fake)
    assert asyncio.run(pusher.deliver_once()) == 0  # one device failed: retried next pass
    assert [d.name for d in push.devices(engine)] == ["new"]  # the dead token is gone
    fake.statuses = [(500, {})] * 10
    for _ in range(4):
        asyncio.run(pusher.deliver_once())
    assert notify.pending(Session(engine)) == []  # gave up after five passes


def test_disabled_or_unconfigured(engine: Engine, tmp_path: Path) -> None:
    with Session(engine) as s, s.begin():
        notify.plan_failed(
            s, plan_id="pln_4", target="dev", goal="g", failed_at=1, reason=None, lang="en", now=T0
        )
    fake = FakeAPNs()
    p = push.Pusher(engine, Settings, tmp_path / "secrets", transport=fake)
    assert asyncio.run(p.deliver_once()) == 1  # push off: nothing is sent, nothing piles up
    assert fake.calls == []


def test_bad_tokens_refused(engine: Engine) -> None:
    for bad in ("", "zz" * 32, "ab" * 101, "ab cd"):
        with pytest.raises(Exception, match="device token"):
            push.register(engine, credential_id="c", name="x", token=bad, now=T0, actor="x")
