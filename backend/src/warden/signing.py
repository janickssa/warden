"""Warden's approval key (README 7A, 12): ed25519, separate from the policy keys.

Agents verify this signature before every step (invariant 10). The payload binds the plan hash to the plan
ID, the target and the approval window (DECISIONS D-07). With `approvals.e2e` on (M6), approvals are signed
by the human's passkey instead and agents verify that.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from warden.errors import SigningError
from warden.keys import b64url, generate_key_file, key_id_for, load_key_file, raw_public, unb64url
from warden.plans.canonical import canonical_bytes
from warden.plans.models import ApprovalSignature

DOMAIN = b"warden-approval-v1\n"
SCHEDULE_DOMAIN = (
    b"warden-schedule-v1\n"  # schedule grants (M7): a different domain, so they can't be swapped
)
SIGNER = "warden-approval-key"


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


def approval_message(payload: Mapping[str, object]) -> bytes:
    """What the approval key signs, and what a passkey signs the SHA-256 of (as its WebAuthn challenge)."""
    return DOMAIN + canonical_bytes(dict(payload))


class ApprovalKey:
    def __init__(self, private: Ed25519PrivateKey) -> None:
        self._private = private
        self.public = private.public_key()
        self.key_id = key_id_for(self.public)

    @classmethod
    def generate(cls, path: Path) -> ApprovalKey:
        return cls(generate_key_file(path))

    @classmethod
    def load(cls, path: Path) -> ApprovalKey:
        return cls(load_key_file(path, what="approval key"))

    @property
    def public_b64(self) -> str:
        return b64url(raw_public(self.public))

    def sign(self, payload: Mapping[str, object]) -> ApprovalSignature:
        sig = self._private.sign(approval_message(payload))
        return ApprovalSignature(by=SIGNER, key_id=self.key_id, sig="ed25519:" + b64url(sig))

    def sign_grant(self, payload: Mapping[str, object]) -> ApprovalSignature:
        """Sign a schedule grant (warden.schedules.grant)."""
        sig = self._private.sign(SCHEDULE_DOMAIN + canonical_bytes(dict(payload)))
        return ApprovalSignature(by=SIGNER, key_id=self.key_id, sig="ed25519:" + b64url(sig))

    def verifier(self) -> ApprovalVerifier:
        return ApprovalVerifier(self.public)


class ApprovalVerifier:
    def __init__(self, public: Ed25519PublicKey) -> None:
        self._public = public
        self.key_id = key_id_for(public)

    def verify(
        self, payload: Mapping[str, object], signature: ApprovalSignature, *, domain: bytes = DOMAIN
    ) -> None:
        """Raise SigningError unless `signature` is a valid approval-key signature over `payload`."""
        if signature.by != SIGNER or signature.key_id != self.key_id:
            raise SigningError("approval was signed by an unknown key")
        if not signature.sig.startswith("ed25519:"):
            raise SigningError("unsupported signature algorithm")
        try:
            raw = unb64url(signature.sig.removeprefix("ed25519:"))
            self._public.verify(raw, domain + canonical_bytes(dict(payload)))
        except (InvalidSignature, ValueError) as exc:
            raise SigningError("approval signature is invalid") from exc
