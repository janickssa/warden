"""Passkey approval vectors for the Go agent (README 10.0 end-to-end signing).

Regenerate with: UPDATE_FIXTURES=1 uv run pytest tests/test_webauthn_vectors.py
The stored vectors must keep verifying with py_webauthn; Go must accept them and refuse every mutation.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta

from factories import T0
from policyhelp import FIXTURES
from softauth import SoftAuthenticator
from webauthn import verify_authentication_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from warden.passkeys import challenge_for
from warden.signing import approval_message, approval_payload

PATH = FIXTURES / "webauthn_vectors.json"
ORIGIN, RP = "https://warden.example.dk", "warden.example.dk"


def _cose_and_spki(auth: SoftAuthenticator) -> tuple[bytes, str]:
    from cryptography.hazmat.primitives import serialization

    spki = auth.key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return auth._cose(), bytes_to_base64url(spki)


def make() -> dict[str, object]:
    payload = approval_payload(
        plan_hash="sha256:" + "ab" * 32,
        plan_id="pln_01JB7Q3K0000000000000000AA",
        target="dev",
        approved_at=T0,
        expires_at=T0 + timedelta(minutes=30),
        by="dashboard:MacBook",
    )
    message = approval_message(payload)
    challenge = bytes_to_base64url(challenge_for(message))
    cases = []
    for alg in (-7, -8):
        auth = SoftAuthenticator(ORIGIN, RP, alg=alg)
        cose, spki = _cose_and_spki(auth)
        cred = auth.get({"challenge": challenge})
        r = cred["response"]
        cases.append(
            {
                "alg": alg,
                "cose": bytes_to_base64url(cose),
                "approver": {"credential_id": auth.id, "alg": alg, "public": spki, "name": f"key{alg}"},
                "assertion": {
                    "credential_id": auth.id,
                    "authenticator_data": r["authenticatorData"],
                    "client_data_json": r["clientDataJSON"],
                    "signature": r["signature"],
                },
            }
        )
    return {
        "payload": payload,
        "message": message.decode(),
        "challenge": challenge,
        "webauthn": {"rp_id": RP, "origins": [ORIGIN]},
        "cases": cases,
    }


def test_vectors_verify_with_py_webauthn() -> None:
    if os.environ.get("UPDATE_FIXTURES") == "1" or not PATH.exists():
        PATH.write_text(json.dumps(make(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    v = json.loads(PATH.read_text(encoding="utf-8"))
    assert v["message"].encode() == approval_message(v["payload"])
    for c in v["cases"]:
        a = c["assertion"]
        cred = {
            "id": a["credential_id"],
            "rawId": a["credential_id"],
            "type": "public-key",
            "response": {
                "authenticatorData": a["authenticator_data"],
                "clientDataJSON": a["client_data_json"],
                "signature": a["signature"],
            },
        }
        verify_authentication_response(
            credential=cred,
            expected_challenge=base64url_to_bytes(v["challenge"]),
            expected_rp_id=RP,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(c["cose"]),
            credential_current_sign_count=0,
            require_user_verification=True,
        )
