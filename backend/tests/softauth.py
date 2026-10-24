"""A software WebAuthn authenticator for tests (ES256 or Ed25519, user verification on)."""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from webauthn.helpers import bytes_to_base64url, encode_cbor

UP, UV, AT = 0x01, 0x04, 0x40


@dataclass
class SoftAuthenticator:
    origin: str
    rp_id: str
    alg: int = -7
    flags: int = UP | UV
    sign_count: int = 0
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(16))

    def __post_init__(self) -> None:
        self.key: Any = (
            ec.generate_private_key(ec.SECP256R1())
            if self.alg == -7
            else ed25519.Ed25519PrivateKey.generate()
        )

    @property
    def id(self) -> str:
        return bytes_to_base64url(self.credential_id)

    def _cose(self) -> bytes:
        if self.alg == -7:
            nums = self.key.public_key().public_numbers()
            return encode_cbor(
                {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
            )
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return encode_cbor({1: 1, 3: -8, -1: 6, -2: raw})

    def _client_data(self, typ: str, challenge_b64: str, origin: str | None = None) -> bytes:
        return json.dumps(
            {"type": typ, "challenge": challenge_b64, "origin": origin or self.origin, "crossOrigin": False}
        ).encode()

    def _sign(self, data: bytes) -> bytes:
        if self.alg == -7:
            return bytes(self.key.sign(data, ec.ECDSA(hashes.SHA256())))
        return bytes(self.key.sign(data))

    def create(self, options: dict[str, Any]) -> dict[str, Any]:
        rp_hash = hashlib.sha256(self.rp_id.encode()).digest()
        cred = b"\0" * 16 + struct.pack(">H", len(self.credential_id)) + self.credential_id + self._cose()
        auth_data = rp_hash + bytes([self.flags | AT]) + struct.pack(">I", self.sign_count) + cred
        att = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cdj = self._client_data("webauthn.create", options["challenge"])
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(cdj),
                "attestationObject": bytes_to_base64url(att),
            },
            "clientExtensionResults": {},
        }

    def get(
        self, options: dict[str, Any], *, origin: str | None = None, rp_id: str | None = None
    ) -> dict[str, Any]:
        self.sign_count += 1
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        auth_data = rp_hash + bytes([self.flags]) + struct.pack(">I", self.sign_count)
        cdj = self._client_data("webauthn.get", options["challenge"], origin)
        sig = self._sign(auth_data + hashlib.sha256(cdj).digest())
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(cdj),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(sig),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
