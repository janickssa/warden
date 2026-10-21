"""M3 Done-when with real agents (README 7A): a tightening reaches 5 agents in under 5 s; a loosening without
the offline signature is refused by Warden and by every agent, even when labelled "tighten"; warden-sign's
signature is accepted end to end; lockdown kills, holds and releases after the lift.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from harness import HUMAN, POLICY, World, go_binary, world
from sqlmodel import Session

from warden import audit
from warden.keys import b64url, key_id_for, raw_public
from warden.plans.canonical import canonical_bytes
from warden.plans.models import PlanStatus
from warden.policy_dist import bundle as bundles
from warden.policy_dist import offline_keys
from warden.policy_dist import publish as publishing

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or os.geteuid() != 0, reason="needs Go and root (to run the agent as nobody)"
)

FIVE = ("dev", "dev2", "dev3", "dev4", "dev5")
TIGHTER = POLICY.replace("['echo\\s+forbidden']", "['echo\\s+forbidden', 'cat\\s+.*secret']")
LOOSER = POLICY.replace("deny_paths: [/etc, /root, /home]", "deny_paths: [/etc, /root]")
assert TIGHTER != POLICY
assert LOOSER != POLICY


def run(coro: object) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def now() -> datetime:
    return datetime.now(UTC)


class Laptop:
    def __init__(self) -> None:
        self.private = Ed25519PrivateKey.generate()
        self.public = b64url(raw_public(self.private.public_key()))
        self.key_id = key_id_for(self.private.public_key())

    def sign(self, pf: dict[str, object]) -> str:
        items = pf["items"]
        assert isinstance(items, list)
        sigs = [
            {
                "target": it["target"],
                "sig": "ed25519:" + b64url(self.private.sign(bundles.signing_message(it["bundle"]))),
            }
            for it in items
        ]
        return json.dumps({"v": 1, "version": pf["version"], "key_id": self.key_id, "signatures": sigs})


def register(w: World, public: str) -> None:
    with Session(w.engine) as s, s.begin():
        offline_keys.register(s, public, role="primary", actor=HUMAN, now=now())


async def enroll_all(w: World, names: tuple[str, ...]) -> None:
    for n in names:
        await w.enroll(n)
        await w.start_agent(n)


def versions(w: World, names: tuple[str, ...]) -> list[int]:
    return [w.dispatcher.sessions[n].policy_version if n in w.dispatcher.sessions else -1 for n in names]


def rejections(w: World) -> list[tuple[str, str]]:
    with Session(w.engine) as s:
        return [
            (e.subject, json.loads(e.detail)["code"])
            for e in audit.entries(s)
            if e.action == "bundle_rejected"
        ]


def test_tightening_reaches_five_agents_in_under_5_s() -> None:
    async def scenario() -> None:
        async with world(FIVE) as w:
            await enroll_all(w, FIVE)
            assert versions(w, FIVE) == [1] * 5
            r = w.publish(TIGHTER)
            assert r.outcome == "published"
            assert r.version == 2
            start = time.monotonic()
            pushed, _ = await w.dispatcher.policy_changed()
            assert sorted(pushed) == sorted(FIVE)
            await w.wait_for(lambda: versions(w, FIVE) == [2] * 5, timeout=5)
            elapsed = time.monotonic() - start
            assert elapsed < 5, elapsed
            # Every agent enforces the new rule.
            assert not w.propose("cat secret.txt").policy_result.ok

    run(scenario())


def test_loosening_without_offline_signature_refused_by_warden_and_agents() -> None:
    async def scenario() -> None:
        async with world(FIVE[:3]) as w:
            laptop = Laptop()
            register(w, laptop.public)
            await enroll_all(w, FIVE[:3])

            # Warden: a loosening is held, and only a valid offline signature publishes it.
            r = w.publish(LOOSER)
            assert r.outcome == "pending"
            with pytest.raises(publishing.PublishRefused):
                publishing.sign_upload(
                    w.engine, Laptop().sign(publishing.publish_file(w.engine)), now=now(), actor="x"
                )
            publishing.discard(w.engine, now=now(), actor="x")

            # A compromised Warden (online key, database) labels the loosening "tighten" and pushes it.
            with Session(w.engine) as s, s.begin():
                for name in FIVE[:3]:
                    prev = bundles.latest(s, name)
                    assert prev is not None
                    rules = bundles.compiled_for(w.cfg.policy, w.cfg.targets, name)
                    rules = {**rules, "deny_paths": [p for p in rules["deny_paths"] if p != "/home"]}
                    forged = bundles.sign_bundle(
                        bundles.build_bundle(
                            version=3,
                            target=name,
                            rules=rules,
                            change="tighten",
                            approval_keys=prev["approval_keys"],
                            issued_at=now(),
                        ),
                        w.online,
                    )
                    s.add(
                        bundles.BundleRow(
                            target=name,
                            version=3,
                            sha256=bundles.bundle_sha256(forged),
                            body=canonical_bytes(forged).decode(),
                            created_at=now().isoformat(),
                        )
                    )
            await w.dispatcher.policy_changed()
            await w.wait_for(lambda: len(rejections(w)) == 3)
            assert {code for _, code in rejections(w)} == {"needs_offline_signature"}
            assert versions(w, FIVE[:3]) == [1] * 3

    run(scenario())


def test_warden_sign_loosening_end_to_end() -> None:
    """The real warden-sign binary signs Warden's publish file; Warden and every agent accept it."""

    async def scenario() -> None:
        async with world(FIVE[:2]) as w:
            sign = go_binary("warden-sign")
            keyfile, passfile = w.root / "offline.key", w.root / "pass"
            passfile.write_text("correct horse battery staple\n")
            subprocess.run(
                [
                    str(sign),
                    "keygen",
                    "--out",
                    str(keyfile),
                    "--passphrase-file",
                    str(passfile),
                    "--scrypt-n",
                    "16384",
                ],
                check=True,
                capture_output=True,
            )
            out = subprocess.run(
                [str(sign), "pubkey", "--key", str(keyfile)], check=True, capture_output=True, text=True
            )
            public = out.stdout.split("public: ")[1].strip()
            register(w, public)
            await enroll_all(w, FIVE[:2])
            assert "Trusts offline key ed25519:" in w.enroll_output

            assert w.publish(LOOSER).outcome == "pending"
            pf = w.root / "bundle-v2.json"
            pf.write_text(json.dumps(publishing.publish_file(w.engine)))
            res = subprocess.run(
                [
                    str(sign),
                    "sign",
                    str(pf),
                    "--key",
                    str(keyfile),
                    "--passphrase-file",
                    str(passfile),
                    "--yes",
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            assert "dev · loosen" in res.stdout
            assert "deny_paths remove /home" in res.stdout
            done = publishing.sign_upload(
                w.engine, (w.root / "bundle-v2.sig.json").read_text(), now=now(), actor="cli:alice"
            )
            assert done.outcome == "published"
            await w.dispatcher.policy_changed()
            await w.wait_for(lambda: versions(w, FIVE[:2]) == [2, 2])
            assert rejections(w) == []

    run(scenario())


def test_lockdown_kills_holds_and_lift_releases() -> None:
    async def scenario() -> None:
        async with world() as w:
            laptop = Laptop()
            register(w, laptop.public)
            await w.enroll()
            await w.start_agent()

            long = w.approve(w.propose("sleep 30"))
            waiting = w.approve(w.propose("echo after lockdown"))
            await w.dispatcher.execute(long.id, wait=False)
            await w.wait_for(
                lambda: w.dispatcher.runs.get(long.id) is not None and w.dispatcher.runs[long.id].current == 1
            )

            # What `warden lockdown` does.
            r = publishing.lockdown(
                w.engine, online=w.online, approval=w.approval, now=now(), actor="cli:alice"
            )
            assert r.outcome == "published"
            w.plans.hold(waiting.id, "lockdown")
            _, killed = await w.dispatcher.policy_changed()
            assert killed == [long.id]
            await w.wait_for(lambda: w.plans.get(long.id).status not in (PlanStatus.RUNNING,))
            await w.wait_for(lambda: versions(w, ("dev",)) == [2])

            # Proposals and approvals still work; nothing runs.
            more = w.approve(w.propose("echo also waits"))
            assert (await w.dispatcher.execute(more.id)).status == PlanStatus.HELD
            # Read-only still works.
            ro = await w.dispatcher.read_only("dev", f"ls {w.ws}", "cli:alice")
            assert ro.ok

            # Lift: a loosening, so pending until the offline key signs it.
            lifted = publishing.lift(
                w.engine, online=w.online, approval=w.approval, now=now(), actor="cli:alice"
            )
            assert lifted.outcome == "pending"
            await w.dispatcher.policy_changed()
            assert w.plans.get(waiting.id).status == PlanStatus.HELD
            publishing.sign_upload(
                w.engine, laptop.sign(publishing.publish_file(w.engine)), now=now(), actor="x"
            )
            await w.dispatcher.policy_changed()
            await w.wait_for(lambda: w.plans.get(waiting.id).status == PlanStatus.SUCCEEDED, timeout=20)
            await w.wait_for(lambda: w.plans.get(more.id).status == PlanStatus.SUCCEEDED, timeout=20)

    run(scenario())
