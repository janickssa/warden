"""Schedule grant vectors for the Go agent (DECISIONS M7-02).

Regenerate with: UPDATE_FIXTURES=1 uv run pytest tests/schedules/test_grant_vectors.py
Python signs; Go must accept the stored run and refuse every mutation (agent/internal/approval).
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from softauth import SoftAuthenticator
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

from warden.keys import b64url, raw_public, unb64url
from warden.passkeys import challenge_for
from warden.plans.models import Step, StepKind
from warden.schedules import grant
from warden.schedules.cron import Cron
from warden.signing import SCHEDULE_DOMAIN, ApprovalKey

PATH = Path(__file__).resolve().parents[3] / "policy-fixtures" / "schedule_vectors.json"
ORIGIN, RP = "https://warden.example.dk", "warden.example.dk"
SCHEDULE_ID = "sch_01JB7Q3K0000000000000000SC"
RUN_ID = "pln_01JB7Q3K0000000000000000RN"
APPROVED = datetime(2026, 10, 20, 12, 0, tzinfo=UTC)


def make() -> dict[str, object]:
    key = ApprovalKey(Ed25519PrivateKey.generate())
    steps = [
        Step(
            n=1, kind=StepKind.GIT, command="git pull", purpose="Update", cwd="/srv/dev/myapp", timeout_s=120
        ),
        Step(
            n=2, kind=StepKind.SHELL, command="npm test", purpose="Test", cwd="/srv/dev/myapp", timeout_s=300
        ),
    ]
    tpl = grant.template(schedule_id=SCHEDULE_ID, target="dev", goal="Nightly test of myapp", steps=steps)
    h = grant.template_hash(tpl)
    payload = grant.payload(
        schedule_id=SCHEDULE_ID,
        template_hash=h,
        target="dev",
        cron="0 3 * * *",
        approved_at=APPROVED,
        expires_at=APPROVED + timedelta(days=90),
        by="dashboard:MacBook",
    )
    auth = SoftAuthenticator(ORIGIN, RP, alg=-7)
    cred = auth.get({"challenge": bytes_to_base64url(challenge_for(grant.message(payload)))})
    spki = auth.key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    slot = Cron.parse("0 3 * * *").next_after(APPROVED)
    assert slot is not None
    return {
        "approval_key": {"key_id": key.key_id, "public": b64url(raw_public(key.public))},
        "trust": {
            "passkey": False,
            "e2e": False,
            "approvers": [
                {"credential_id": auth.id, "alg": -7, "public": bytes_to_base64url(spki), "name": "MacBook"}
            ],
            "webauthn": {"rp_id": RP, "origins": [ORIGIN]},
        },
        "now": (slot + timedelta(minutes=2)).isoformat(),
        "claim": grant.claim(SCHEDULE_ID, slot),
        "run": {
            "template": tpl,
            "plan_hash": h,
            "schedule": {
                "run_id": RUN_ID,
                "slot": slot.isoformat(),
                "grant": {
                    **{k: v for k, v in payload.items() if k not in ("v", "kind")},
                    "signature": key.sign_grant(payload).model_dump(),
                    "passkey": {
                        "credential_id": auth.id,
                        "authenticator_data": cred["response"]["authenticatorData"],
                        "client_data_json": cred["response"]["clientDataJSON"],
                        "signature": cred["response"]["signature"],
                    },
                },
            },
        },
    }


def test_vectors_verify() -> None:
    if os.environ.get("UPDATE_FIXTURES") == "1" or not PATH.exists():
        PATH.write_text(json.dumps(make(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    v = json.loads(PATH.read_text(encoding="utf-8"))
    run = v["run"]
    assert grant.template_hash(run["template"]) == run["plan_hash"]
    g = run["schedule"]["grant"]
    payload = {"v": 1, "kind": "schedule", **{k: g[k] for k in g if k not in ("signature", "passkey")}}
    pub = Ed25519PublicKey.from_public_bytes(unb64url(v["approval_key"]["public"]))
    pub.verify(unb64url(g["signature"]["sig"].removeprefix("ed25519:")), grant.message(payload))
    assert grant.message(payload).startswith(SCHEDULE_DOMAIN)
    client = json.loads(base64url_to_bytes(g["passkey"]["client_data_json"]))
    assert client["challenge"] == bytes_to_base64url(challenge_for(grant.message(payload)))
    slot = datetime.fromisoformat(run["schedule"]["slot"])
    assert Cron.parse(g["cron"]).is_slot(slot)
    assert v["claim"] == grant.claim(g["schedule_id"], slot)
