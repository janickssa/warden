"""The iPhone's Face ID device key (M8, DECISIONS M8-01), byte for byte as WardenCore builds it.

The app holds a non-exportable P-256 key in the Secure Enclave and builds WebAuthn messages itself:
- credential ID = the first 16 bytes of SHA-256 over the uncompressed public key (0x04 || x || y);
- clientDataJSON = compact JSON in the order type, challenge, origin, crossOrigin (no spaces);
- authenticator data = SHA-256(rp_id) || flags || counter (always 0: the Secure Enclave has none);
  flags UP|UV (0x05), plus AT (0x40) with the attested credential (zero AAGUID) when registering;
- attestation object = CBOR {"fmt": "none", "attStmt": {}, "authData": …} in canonical order;
- signature = DER ECDSA-SHA256 over authData || SHA-256(clientDataJSON).

`policy-fixtures/ios_webauthn_vectors.json` pins these bytes; WardenCore's tests must reproduce them.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import bytes_to_base64url

UP, UV, AT = 0x01, 0x04, 0x40


def cbor_bytes(b: bytes) -> bytes:
    return _head(2, len(b)) + b


def cbor_text(t: str) -> bytes:
    raw = t.encode()
    return _head(3, len(raw)) + raw


def cbor_int(n: int) -> bytes:
    return _head(0, n) if n >= 0 else _head(1, -1 - n)


def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    if n < 256:
        return bytes([major << 5 | 24, n])
    if n < 65536:
        return bytes([major << 5 | 25]) + struct.pack(">H", n)
    return bytes([major << 5 | 26]) + struct.pack(">I", n)


def cbor_map(pairs: list[tuple[bytes, bytes]]) -> bytes:
    """Pairs already encoded, in the order given (callers give canonical order)."""
    return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def client_data(typ: str, challenge: str, origin: str) -> bytes:
    for s in (challenge, origin):
        if any(c in s for c in '"\\') or any(ord(c) < 0x20 for c in s):
            raise ValueError("unexpected character in client data")
    return f'{{"type":"{typ}","challenge":"{challenge}","origin":"{origin}","crossOrigin":false}}'.encode()


@dataclass
class DeviceKey:
    key: ec.EllipticCurvePrivateKey
    rp_id: str
    origin: str

    @property
    def xy(self) -> tuple[bytes, bytes]:
        n = self.key.public_key().public_numbers()
        return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")

    @property
    def credential_id(self) -> bytes:
        x, y = self.xy
        return hashlib.sha256(b"\x04" + x + y).digest()[:16]

    @property
    def id(self) -> str:
        return bytes_to_base64url(self.credential_id)

    def cose(self) -> bytes:
        x, y = self.xy
        return cbor_map(
            [
                (cbor_int(1), cbor_int(2)),
                (cbor_int(3), cbor_int(-7)),
                (cbor_int(-1), cbor_int(1)),
                (cbor_int(-2), cbor_bytes(x)),
                (cbor_int(-3), cbor_bytes(y)),
            ]
        )

    def _rp(self) -> bytes:
        return hashlib.sha256(self.rp_id.encode()).digest()

    def registration(self, challenge: str) -> tuple[bytes, bytes]:
        """(attestationObject, clientDataJSON)."""
        cred = b"\0" * 16 + struct.pack(">H", 16) + self.credential_id + self.cose()
        auth = self._rp() + bytes([UP | UV | AT]) + struct.pack(">I", 0) + cred
        att = cbor_map(
            [
                (cbor_text("fmt"), cbor_text("none")),
                (cbor_text("attStmt"), cbor_map([])),
                (cbor_text("authData"), cbor_bytes(auth)),
            ]
        )
        return att, client_data("webauthn.create", challenge, self.origin)

    def assertion_parts(self, challenge: str) -> tuple[bytes, bytes]:
        """(authenticatorData, clientDataJSON)."""
        return self._rp() + bytes([UP | UV]) + struct.pack(">I", 0), client_data(
            "webauthn.get", challenge, self.origin
        )

    def sign(self, auth: bytes, cdj: bytes) -> bytes:
        return bytes(self.key.sign(auth + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256())))

    # --- in the shape the API takes (as the browser sends it) ---------------------------------------------

    def create(self, options: dict[str, Any]) -> dict[str, Any]:
        att, cdj = self.registration(options["challenge"])
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

    def get(self, options: dict[str, Any]) -> dict[str, Any]:
        auth, cdj = self.assertion_parts(options["challenge"])
        return {
            "id": self.id,
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(cdj),
                "authenticatorData": bytes_to_base64url(auth),
                "signature": bytes_to_base64url(self.sign(auth, cdj)),
                "userHandle": None,
            },
            "clientExtensionResults": {},
        }
