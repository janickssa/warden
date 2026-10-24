"""End-to-end approval signing with the real agent (README 10.0, invariant 10).

With approvals.e2e on, the agent itself refuses an approval that carries only Warden's approval-key
signature, as a compromised Warden would send, and accepts one signed by a passkey in its bundle.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harness import HUMAN, World, world
from sqlmodel import Session

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from softauth import SoftAuthenticator

from warden import audit
from warden.actors import HumanActor
from warden.keys import b64url, key_id_for, raw_public
from warden.plans.models import PasskeyAssertion, PlanStatus
from warden.policy_dist import bundle as bundles
from warden.policy_dist import offline_keys
from warden.policy_dist import publish as publishing
from warden.signing import approval_message

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or os.geteuid() != 0, reason="needs Go and root (to run the agent as nobody)"
)
ORIGIN, RP = "https://warden.example.dk", "warden.example.dk"
DASH = HumanActor("dashboard", "MacBook")


def now() -> datetime:
    return datetime.now(UTC)


def sign_pending(w: World, key: Ed25519PrivateKey) -> None:
    pf = publishing.publish_file(w.engine)
    sig = {
        "v": 1,
        "version": pf["version"],
        "key_id": key_id_for(key.public_key()),
        "signatures": [
            {
                "target": it["target"],
                "sig": "ed25519:" + b64url(key.sign(bundles.signing_message(it["bundle"]))),
            }
            for it in pf["items"]
        ],
    }
    publishing.sign_upload(w.engine, json.dumps(sig), now=now(), actor="cli:alice")


def passkey_for(w: World, plan_id: str, auth: SoftAuthenticator) -> tuple[PasskeyAssertion, datetime]:
    plan = w.plans.get(plan_id)
    at = now()
    payload = w.plans.approval_payload_for(plan, DASH, at)
    challenge = b64url(hashlib.sha256(approval_message(payload)).digest())
    r = auth.get({"challenge": challenge})["response"]
    return (
        PasskeyAssertion(
            credential_id=auth.id,
            authenticator_data=r["authenticatorData"],
            client_data_json=r["clientDataJSON"],
            signature=r["signature"],
        ),
        at,
    )


def test_agent_enforces_e2e() -> None:
    async def scenario() -> None:
        async with world() as w:
            offline = Ed25519PrivateKey.generate()
            with Session(w.engine) as s, s.begin():
                offline_keys.register(
                    s, b64url(raw_public(offline.public_key())), role="primary", actor=HUMAN, now=now()
                )
            await w.enroll()
            await w.start_agent()

            auth = SoftAuthenticator(ORIGIN, RP)
            from cryptography.hazmat.primitives import serialization

            spki = auth.key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            trust = {
                "e2e": True,
                "approvers": [
                    {"credential_id": auth.id, "alg": -7, "public": b64url(spki), "name": "MacBook"}
                ],
                "webauthn": {"rp_id": RP, "origins": [ORIGIN]},
            }
            assert (
                publishing.publish_trust(
                    w.engine, trust, online=w.online, approval=w.approval, now=now(), actor="x"
                ).outcome
                == "pending"
            )
            sign_pending(w, offline)
            await w.dispatcher.policy_changed()
            await w.wait_for(lambda: w.dispatcher.sessions["dev"].policy_version == 2)

            # Warden (here: compromised, it thinks e2e is off) sends an approval-key-only approval.
            bare = w.approve(w.propose("echo bare"))
            done = await w.dispatcher.execute(bare.id)
            assert done.status == PlanStatus.FAILED
            with Session(w.engine) as s:
                refusals = [
                    json.loads(e.detail) for e in audit.entries(s) if e.action == "plan_refused_by_agent"
                ]
            assert refusals[-1]["code"] == "passkey_required"

            # The human approves with a passkey: the agent verifies it itself and runs the plan.
            plan = w.propose("echo signed by a passkey")
            passkey, at = passkey_for(w, plan.id, auth)
            w.plans.approve(plan.id, plan.hash, DASH, passkey=passkey, at=at)
            done = await w.dispatcher.execute(plan.id)
            assert done.status == PlanStatus.SUCCEEDED, w.agent_log()

            # A valid passkey assertion for another plan doesn't carry over.
            other = w.propose("echo other")
            passkey2, at2 = passkey_for(w, plan.id, auth)  # signed for the first plan's approval
            with pytest.raises(Exception, match="something else"):
                w.plans.approve(other.id, other.hash, DASH, passkey=passkey2, at=at2)

    asyncio.run(scenario())
