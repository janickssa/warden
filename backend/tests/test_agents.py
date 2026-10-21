from __future__ import annotations

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID
from policyhelp import fixture_targets
from sqlalchemy import Engine
from sqlmodel import Session
from svc import CLAUDE, Clock

from warden import audit
from warden.actors import HumanActor
from warden.agents import EnrollmentRefused, Registry, split_token
from warden.ca import CA, fingerprint
from warden.errors import NotFound
from warden.keys import b64url, raw_public

ALICE = HumanActor("cli", "alice")


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def ca(tmp_path: Path, clock: Clock) -> CA:
    return CA.load_or_create(tmp_path / "ca", now=clock.now)


@pytest.fixture
def reg(engine: Engine, ca: CA, clock: Clock) -> Registry:
    return Registry(engine, ca, targets=fixture_targets, clock=clock)


def agent_key() -> tuple[Ed25519PrivateKey, str]:
    k = Ed25519PrivateKey.generate()
    return k, b64url(raw_public(k.public_key()))


def actions(engine: Engine) -> list[str]:
    with Session(engine) as s:
        return [e.action for e in audit.entries(s)]


def test_ca_files_private_and_reloadable(tmp_path: Path, ca: CA) -> None:
    assert (tmp_path / "ca").stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "ca/ca.key").stat().st_mode & 0o777 == 0o600
    again = CA.load_or_create(tmp_path / "ca")
    assert again.fingerprint == ca.fingerprint


def test_server_cert_names_and_reuse(ca: CA, clock: Clock) -> None:
    cert_path, key_path = ca.server_files(["warden.lan", "10.0.20.5"], now=clock.now)
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert [str(n) for n in san.get_values_for_type(x509.DNSName)] == ["warden.lan"]
    assert key_path.stat().st_mode & 0o777 == 0o600
    first = cert_path.read_bytes()
    ca.server_files(["10.0.20.5", "warden.lan"], now=clock.now)
    assert cert_path.read_bytes() == first  # same names: reused
    ca.server_files(["warden.lan"], now=clock.now)
    assert cert_path.read_bytes() != first  # names changed: re-issued


def test_full_enrollment(reg: Registry, engine: Engine, ca: CA) -> None:
    token = reg.create_token("dev", ALICE)
    assert token.startswith("wdn_enr_")
    assert split_token(token)[1] == ca.fingerprint[:32]
    key, pub = agent_key()
    sub = reg.submit(token, pub, "10.0.20.11", "0.1.0")
    assert sub.fingerprint == fingerprint(key.public_key())
    assert [p.name for p in reg.pending()] == ["dev"]
    agent = reg.confirm("dev", sub.fingerprint.upper(), ALICE)
    assert agent.status == "active"
    row = reg.enrollment(sub.enrollment_id)
    assert row.cert_pem is not None
    cert = x509.load_pem_x509_certificate(row.cert_pem.encode())
    assert cert.subject.rfc4514_string() == f"CN={agent.id}"
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert reg.by_serial(agent.cert_serial) is not None
    assert actions(engine) == ["agent_token_created", "agent_enroll_submitted", "agent_enroll"]


def test_token_is_single_use(reg: Registry) -> None:
    token = reg.create_token("dev", ALICE)
    reg.submit(token, agent_key()[1], "10.0.20.11", "0.1.0")
    with pytest.raises(EnrollmentRefused):
        reg.submit(token, agent_key()[1], "10.0.20.66", "0.1.0")


def test_token_expires_after_15_min(reg: Registry, clock: Clock, engine: Engine) -> None:
    token = reg.create_token("dev", ALICE)
    clock.advance(minutes=15)
    with pytest.raises(EnrollmentRefused):
        reg.submit(token, agent_key()[1], "10.0.20.11", "0.1.0")
    assert "agent_enroll_failed" in actions(engine)


def test_confirm_after_expiry_refused(reg: Registry, clock: Clock) -> None:
    token = reg.create_token("dev", ALICE)
    sub = reg.submit(token, agent_key()[1], "10.0.20.11", "0.1.0")
    clock.advance(minutes=16)
    with pytest.raises(EnrollmentRefused, match="expired"):
        reg.confirm("dev", sub.fingerprint, ALICE)


def test_fingerprint_mismatch_rejects(reg: Registry, engine: Engine) -> None:
    token = reg.create_token("dev", ALICE)
    reg.submit(token, agent_key()[1], "10.0.20.66", "0.1.0")
    with pytest.raises(EnrollmentRefused, match=r"don't match"):
        reg.confirm("dev", "SHA256:00:11", ALICE)
    assert "agent_enroll_mismatch" in actions(engine)
    with pytest.raises(EnrollmentRefused):  # the rejected enrollment can't be confirmed afterwards
        reg.confirm("dev", "anything", ALICE)
    assert reg.list() == []


@pytest.mark.parametrize("bad", ["", "nope", "wdn_enr_x", "wdn_enr_secret.0000"])
def test_bad_tokens(reg: Registry, bad: str) -> None:
    reg.create_token("dev", ALICE)
    with pytest.raises(EnrollmentRefused):
        reg.submit(bad, agent_key()[1], "10.0.20.11", "0.1.0")


def test_wrong_ca_fingerprint_in_token(reg: Registry) -> None:
    secret, _ = split_token(reg.create_token("dev", ALICE))
    with pytest.raises(EnrollmentRefused):
        reg.submit(f"wdn_enr_{secret}.{'0' * 32}", agent_key()[1], "10.0.20.11", "0.1.0")


def test_bad_public_key(reg: Registry) -> None:
    token = reg.create_token("dev", ALICE)
    with pytest.raises(EnrollmentRefused):
        reg.submit(token, "not-a-key", "10.0.20.11", "0.1.0")


def test_unknown_target_and_double_enrollment(reg: Registry) -> None:
    with pytest.raises(EnrollmentRefused, match=r"targets\.yaml"):
        reg.create_token("prod", ALICE)
    token = reg.create_token("dev", ALICE)
    sub = reg.submit(token, agent_key()[1], "10.0.20.11", "0.1.0")
    reg.confirm("dev", sub.fingerprint, ALICE)
    with pytest.raises(EnrollmentRefused, match="revoke"):
        reg.create_token("dev", ALICE)


def test_new_token_supersedes_old(reg: Registry) -> None:
    old = reg.create_token("dev", ALICE)
    reg.create_token("dev", ALICE)
    with pytest.raises(EnrollmentRefused):
        reg.submit(old, agent_key()[1], "10.0.20.11", "0.1.0")


def test_revoke(reg: Registry, engine: Engine) -> None:
    sub = reg.submit(reg.create_token("dev", ALICE), agent_key()[1], "10.0.20.11", "0.1.0")
    agent = reg.confirm("dev", sub.fingerprint, ALICE)
    reg.revoke("dev", ALICE)
    assert reg.by_serial(agent.cert_serial) is None
    with pytest.raises(NotFound):
        reg.revoke("dev", ALICE)
    assert "agent_revoke" in actions(engine)
    reg.create_token("dev", ALICE)  # can enroll a new agent after revoking


def test_only_humans(reg: Registry) -> None:
    for call in (
        lambda: reg.create_token("dev", CLAUDE),  # type: ignore[arg-type]
        lambda: reg.confirm("dev", "x", CLAUDE),  # type: ignore[arg-type]
        lambda: reg.revoke("dev", CLAUDE),  # type: ignore[arg-type]
    ):
        with pytest.raises(EnrollmentRefused):
            call()


def test_seen_updates(reg: Registry, clock: Clock) -> None:
    sub = reg.submit(reg.create_token("dev", ALICE), agent_key()[1], "10.0.20.11", "0.1.0")
    agent = reg.confirm("dev", sub.fingerprint, ALICE)
    clock.advance(seconds=30)
    reg.seen(agent.id, version="0.1.1", policy_version=1, remote_addr="10.0.20.11")
    got = reg.list()[0]
    assert got.agent_version == "0.1.1"
    assert got.policy_version == 1
    assert got.last_seen == (clock.now).isoformat()
