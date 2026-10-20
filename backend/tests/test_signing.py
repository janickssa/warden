from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path

import pytest
from factories import T0

from warden.errors import SigningError
from warden.signing import ApprovalKey, approval_payload


def payload(**kw: object) -> dict[str, object]:
    data: dict[str, object] = {
        "plan_hash": "sha256:" + "a" * 64,
        "plan_id": "pln_01JB7Q3K0000000000000000AA",
        "target": "dev",
        "approved_at": T0,
        "expires_at": T0 + timedelta(minutes=30),
        "by": "cli:alice",
    }
    data.update(kw)
    return approval_payload(**data)  # type: ignore[arg-type]


@pytest.fixture
def key(tmp_path: Path) -> ApprovalKey:
    return ApprovalKey.generate(tmp_path / "approval.key")


def test_sign_and_verify(key: ApprovalKey) -> None:
    sig = key.sign(payload())
    key.verifier().verify(payload(), sig)
    assert sig.key_id.startswith("ed25519:")


@pytest.mark.parametrize(
    "change",
    [
        {"plan_hash": "sha256:" + "b" * 64},
        {"plan_id": "pln_01JB7Q3K0000000000000000BB"},
        {"target": "dev2"},
        {"expires_at": T0 + timedelta(hours=5)},
        {"by": "cli:mallory"},
    ],
)
def test_signature_binds_every_field(key: ApprovalKey, change: dict[str, object]) -> None:
    sig = key.sign(payload())
    with pytest.raises(SigningError):
        key.verifier().verify(payload(**change), sig)


def test_other_key_rejected(key: ApprovalKey, tmp_path: Path) -> None:
    other = ApprovalKey.generate(tmp_path / "other.key")
    with pytest.raises(SigningError):
        key.verifier().verify(payload(), other.sign(payload()))


def test_tampered_signature_rejected(key: ApprovalKey) -> None:
    sig = key.sign(payload())
    flipped = sig.sig[:-2] + ("A" if sig.sig[-2] != "A" else "B") + sig.sig[-1]
    with pytest.raises(SigningError):
        key.verifier().verify(payload(), sig.model_copy(update={"sig": flipped}))


def test_garbage_signature_rejected(key: ApprovalKey) -> None:
    sig = key.sign(payload())
    for bad in ("ed25519:!!!", "rsa:abc", "ed25519:"):
        with pytest.raises(SigningError):
            key.verifier().verify(payload(), sig.model_copy(update={"sig": bad}))


def test_key_file_is_0600_and_loads(tmp_path: Path) -> None:
    path = tmp_path / "k"
    key = ApprovalKey.generate(path)
    assert path.stat().st_mode & 0o777 == 0o600
    assert ApprovalKey.load(path).key_id == key.key_id


def test_group_readable_key_refused(tmp_path: Path) -> None:
    path = tmp_path / "k"
    ApprovalKey.generate(path)
    os.chmod(path, 0o640)
    with pytest.raises(SigningError, match="chmod 600"):
        ApprovalKey.load(path)


def test_generate_never_overwrites(tmp_path: Path) -> None:
    path = tmp_path / "k"
    ApprovalKey.generate(path)
    with pytest.raises(FileExistsError):
        ApprovalKey.generate(path)


def test_missing_or_garbage_key_refused(tmp_path: Path) -> None:
    with pytest.raises(SigningError):
        ApprovalKey.load(tmp_path / "missing")
    bad = tmp_path / "bad"
    bad.write_text("not a key")
    os.chmod(bad, 0o600)
    with pytest.raises(SigningError):
        ApprovalKey.load(bad)
