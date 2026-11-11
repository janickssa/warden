"""WebAuthn vectors for the iPhone's Face ID device key (M8, DECISIONS M8-01).

Regenerate with: UPDATE_FIXTURES=1 uv run pytest tests/test_ios_vectors.py
py_webauthn must accept the registration and the assertion; WardenCore (Swift) must rebuild every byte
except the signature from the same key and inputs; the Go agent must verify the assertion
(agent/internal/webauthn).
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from devicekey import DeviceKey
from factories import T0
from policyhelp import FIXTURES
from webauthn import verify_authentication_response, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from warden.passkeys import challenge_for
from warden.signing import approval_message, approval_payload

PATH = FIXTURES / "ios_webauthn_vectors.json"
RP, ORIGIN = "warden.example.dk", "https://warden.example.dk"
SCALAR = int("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318", 16)  # test only


def make() -> dict[str, object]:
    dk = DeviceKey(ec.derive_private_key(SCALAR, ec.SECP256R1()), RP, ORIGIN)
    reg_challenge = bytes_to_base64url(b"warden-registration-challenge-01")
    att, cdj_create = dk.registration(reg_challenge)
    payload = approval_payload(
        plan_hash="sha256:" + "ab" * 32,
        plan_id="pln_01JB7Q3K0000000000000000AA",
        target="dev",
        approved_at=T0,
        expires_at=T0.replace(minute=30),
        by="dashboard:iPhone",
    )
    challenge = bytes_to_base64url(challenge_for(approval_message(payload)))
    auth, cdj_get = dk.assertion_parts(challenge)
    spki = dk.key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    x, y = dk.xy
    return {
        "rp_id": RP,
        "origin": ORIGIN,
        "private_key_hex": f"{SCALAR:064x}",
        "public_x963_hex": (b"\x04" + x + y).hex(),
        "credential_id": dk.id,
        "cose_hex": dk.cose().hex(),
        "registration": {
            "challenge": reg_challenge,
            "client_data_json": cdj_create.decode(),
            "attestation_object_hex": att.hex(),
        },
        "assertion": {
            "payload": payload,
            "message_sha256_hex": hashlib.sha256(approval_message(payload)).hexdigest(),
            "challenge": challenge,
            "client_data_json": cdj_get.decode(),
            "authenticator_data_hex": auth.hex(),
            "signature": bytes_to_base64url(dk.sign(auth, cdj_get)),
        },
        "approver": {"credential_id": dk.id, "alg": -7, "public": bytes_to_base64url(spki), "name": "iPhone"},
    }


def test_vectors_verify_with_py_webauthn() -> None:
    if os.environ.get("UPDATE_FIXTURES") == "1" or not PATH.exists():
        PATH.write_text(json.dumps(make(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    v = json.loads(PATH.read_text(encoding="utf-8"))
    fresh: dict[str, Any] = make()
    for k in ("credential_id", "cose_hex", "registration"):
        assert v[k] == fresh[k], k  # the layout is deterministic
    assert v["assertion"]["authenticator_data_hex"] == fresh["assertion"]["authenticator_data_hex"]
    reg = v["registration"]
    verified = verify_registration_response(
        credential={
            "id": v["credential_id"],
            "rawId": v["credential_id"],
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(reg["client_data_json"].encode()),
                "attestationObject": bytes_to_base64url(bytes.fromhex(reg["attestation_object_hex"])),
            },
        },
        expected_challenge=base64url_to_bytes(reg["challenge"]),
        expected_rp_id=RP,
        expected_origin=ORIGIN,
        require_user_verification=True,
    )
    a = v["assertion"]
    assert a["message_sha256_hex"] == hashlib.sha256(approval_message(a["payload"])).hexdigest()
    verify_authentication_response(
        credential={
            "id": v["credential_id"],
            "rawId": v["credential_id"],
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(a["client_data_json"].encode()),
                "authenticatorData": bytes_to_base64url(bytes.fromhex(a["authenticator_data_hex"])),
                "signature": a["signature"],
                "userHandle": None,
            },
        },
        expected_challenge=base64url_to_bytes(a["challenge"]),
        expected_rp_id=RP,
        expected_origin=ORIGIN,
        credential_public_key=verified.credential_public_key,
        credential_current_sign_count=0,
        require_user_verification=True,
    )
