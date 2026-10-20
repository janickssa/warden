"""Warden's approval key (README 7A, 12): ed25519, separate from the policy keys.

Agents verify this signature before every step (invariant 10). The payload binds the plan hash to the plan
ID, the target and the approval window (DECISIONS D-07). With `approvals.e2e` on (M6), approvals are signed
by the human's passkey instead and agents verify that.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from warden.errors import SigningError
from warden.plans.canonical import canonical_bytes
from warden.plans.models import ApprovalSignature

DOMAIN = b"warden-approval-v1\n"
SIGNER = "warden-approval-key"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id_for(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "ed25519:" + hashlib.sha256(raw).hexdigest()[:16]


def approval_payload(
    *, plan_hash: str, plan_id: str, target: str, approved_at: datetime, expires_at: datetime, by: str
) -> dict[str, object]:
    return {
        "v": 1,
        "plan_hash": plan_hash,
        "plan_id": plan_id,
        "target": target,
        "approved_at": approved_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "by": by,
    }


class ApprovalKey:
    def __init__(self, private: Ed25519PrivateKey) -> None:
        self._private = private
        self.public = private.public_key()
        self.key_id = key_id_for(self.public)

    @classmethod
    def generate(cls, path: Path) -> ApprovalKey:
        private = Ed25519PrivateKey.generate()
        pem = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        return cls(private)

    @classmethod
    def load(cls, path: Path) -> ApprovalKey:
        try:
            st = path.stat()
        except OSError as exc:
            raise SigningError(f"can't read approval key {path}: {exc.strerror}") from exc
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise SigningError(f"approval key {path} must not be readable by group or others (chmod 600)")
        if st.st_uid != os.geteuid():
            raise SigningError(f"approval key {path} must be owned by the user running Warden")
        try:
            private = serialization.load_pem_private_key(path.read_bytes(), password=None)
        except ValueError as exc:
            raise SigningError(f"approval key {path} is not a valid key") from exc
        if not isinstance(private, Ed25519PrivateKey):
            raise SigningError(f"approval key {path} is not an ed25519 key")
        return cls(private)

    def sign(self, payload: Mapping[str, object]) -> ApprovalSignature:
        sig = self._private.sign(DOMAIN + canonical_bytes(dict(payload)))
        return ApprovalSignature(by=SIGNER, key_id=self.key_id, sig="ed25519:" + _b64(sig))

    def verifier(self) -> ApprovalVerifier:
        return ApprovalVerifier(self.public)


class ApprovalVerifier:
    def __init__(self, public: Ed25519PublicKey) -> None:
        self._public = public
        self.key_id = key_id_for(public)

    def verify(self, payload: Mapping[str, object], signature: ApprovalSignature) -> None:
        """Raise SigningError unless `signature` is a valid approval-key signature over `payload`."""
        if signature.by != SIGNER or signature.key_id != self.key_id:
            raise SigningError("approval was signed by an unknown key")
        if not signature.sig.startswith("ed25519:"):
            raise SigningError("unsupported signature algorithm")
        try:
            raw = _unb64(signature.sig.removeprefix("ed25519:"))
            self._public.verify(raw, DOMAIN + canonical_bytes(dict(payload)))
        except (InvalidSignature, ValueError) as exc:
            raise SigningError("approval signature is invalid") from exc
