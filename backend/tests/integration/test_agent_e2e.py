"""M2 Done-when, end to end with the real agent: a plan runs, fails and revises; a tampered plan is refused.

Also: kill switch, disconnect, held plans, read-only through the agent, symlink refusal on the agent,
replay protection and revocation.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil

import pytest
from harness import HUMAN, World, world
from sqlmodel import Session

from warden import audit
from warden.dispatch import outputs, protocol
from warden.dispatch.server import ActiveRun
from warden.plans.models import PlanStatus, StepStatus

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or os.geteuid() != 0, reason="needs Go and root (to run the agent as nobody)"
)

S = PlanStatus


def run(coro: object) -> None:
    asyncio.run(coro)  # type: ignore[arg-type]


def output_of(w: World, plan_id: str, n: int) -> str:
    with Session(w.engine) as s:
        return "".join(r.data for r in outputs.read(s, plan_id, n))


def actions(w: World) -> list[str]:
    with Session(w.engine) as s:
        return [e.action for e in audit.entries(s)]


def test_enroll_run_fail_revise() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            assert w.dispatcher.sessions["dev"].policy_version == 1

            ok = w.approve(w.propose("echo hello warden", "true"))
            done = await w.dispatcher.execute(ok.id)
            assert done.status == S.SUCCEEDED, w.agent_log()
            assert "hello warden" in output_of(w, ok.id, 1)

            first = w.approve(w.propose("echo one", "false", "echo never"))
            failed = await w.dispatcher.execute(first.id)
            assert failed.status == S.FAILED
            assert failed.failed_at == 2
            assert failed.fail_reason == "exit_code"
            assert [r.status for r in failed.step_results] == [
                StepStatus.SUCCEEDED,
                StepStatus.FAILED,
                StepStatus.SKIPPED,
            ]
            assert output_of(w, first.id, 3) == ""

            revised = w.approve(w.propose("echo one", "true", "echo fixed", revises=first.id))
            assert (await w.dispatcher.execute(revised.id)).status == S.SUCCEEDED
            assert "fixed" in output_of(w, revised.id, 3)
            assert "step_output" in actions(w)

    run(scenario())


def test_tampered_run_message_refused_by_agent() -> None:
    """A compromised dispatcher edits a step after approval. The agent refuses before running anything."""

    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            plan = w.approve(w.propose("echo safe"))
            plan = w.plans.start_run(plan.id)
            assert plan.approval is not None
            run_ = ActiveRun(plan=plan, agent="dev")
            w.dispatcher.runs[plan.id] = run_
            template = plan.template()
            template["steps"][0]["command"] = "echo tampered"  # type: ignore[index]
            a = plan.approval
            await w.dispatcher.sessions["dev"].ws.send(
                protocol.encode(
                    "run",
                    template=template,
                    plan_hash=plan.hash,
                    approval={
                        "by": a.by,
                        "at": a.at.isoformat(),
                        "expires_at": plan.expires_at.isoformat(),
                        "hash": a.hash,
                        "signature": a.signature.model_dump(),
                    },
                )
            )
            done = await asyncio.wait_for(run_.done, 15)
            assert done.status == S.FAILED
            assert done.fail_reason == "hash_mismatch"
            assert output_of(w, plan.id, 1) == ""
            assert "plan_refused_by_agent" in actions(w)

    run(scenario())


def test_replayed_plan_refused_by_agent() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            plan = w.approve(w.propose("echo once"))
            assert (await w.dispatcher.execute(plan.id)).status == S.SUCCEEDED
            # Resend the identical, validly signed run message.
            replay = w.plans.get(plan.id)
            assert replay.approval is not None
            run_ = ActiveRun(plan=replay, agent="dev")
            w.dispatcher.runs[plan.id] = run_
            a = replay.approval
            await w.dispatcher.sessions["dev"].ws.send(
                protocol.encode(
                    "run",
                    template=replay.template(),
                    plan_hash=replay.hash,
                    approval={
                        "by": a.by,
                        "at": a.at.isoformat(),
                        "expires_at": replay.expires_at.isoformat(),
                        "hash": a.hash,
                        "signature": a.signature.model_dump(),
                    },
                )
            )
            await w.wait_for(lambda: "plan_refused_by_agent" in actions(w))
            with Session(w.engine) as s:
                entry = next(e for e in audit.entries(s) if e.action == "plan_refused_by_agent")
            assert json.loads(entry.detail)["code"] == "replayed_plan"

    run(scenario())


def test_symlink_escape_refused_on_agent() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            os.symlink("/etc/hostname", w.ws / "link")
            plan = w.approve(w.propose("cat link"))  # lexically inside the workspace: Warden can't tell
            done = await w.dispatcher.execute(plan.id)
            assert done.status == S.FAILED
            assert done.fail_reason == "policy_violation"
            assert done.step_results[0].exit_code == 126
            assert "step_refused" in actions(w)

    run(scenario())


def test_kill_switch() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            plan = w.approve(w.propose("sleep 60", "echo after"))
            await w.dispatcher.execute(plan.id, wait=False)
            await w.wait_for(
                lambda: w.dispatcher.runs.get(plan.id) is not None and w.dispatcher.runs[plan.id].current == 1
            )
            run_ = w.dispatcher.runs[plan.id]
            await w.dispatcher.kill(plan.id, "cli:alice")
            done = await asyncio.wait_for(run_.done, 20)
            assert done.status == S.CANCELLED
            assert [r.status for r in done.step_results] == [StepStatus.CANCELLED, StepStatus.SKIPPED]

    run(scenario())


def test_disconnect_fails_plan_and_agent_reconnects() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            plan = w.approve(w.propose("sleep 2", "echo after"))
            await w.dispatcher.execute(plan.id, wait=False)
            await w.wait_for(
                lambda: w.dispatcher.runs.get(plan.id) is not None and w.dispatcher.runs[plan.id].current == 1
            )
            run_ = w.dispatcher.runs[plan.id]
            await w.dispatcher.sessions["dev"].ws.close(1001, "network drop")
            done = await asyncio.wait_for(run_.done, 10)
            assert done.status == S.FAILED
            assert done.fail_reason == "agent_disconnected"
            await w.wait_for(lambda: "dev" in w.dispatcher.sessions, timeout=20)  # reconnects
            await asyncio.sleep(3)
            assert "after" not in output_of(w, plan.id, 2)

    run(scenario())


def test_held_until_agent_connects() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            plan = w.approve(w.propose("echo released"))
            held = await w.dispatcher.execute(plan.id)
            assert held.status == S.HELD
            assert held.held_reason == "dev is offline"
            await w.start_agent()
            await w.wait_for(lambda: w.plans.get(plan.id).status == S.SUCCEEDED)
            assert "held_released" in actions(w)

    run(scenario())


def test_read_only_through_agent() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            (w.ws / "notes.txt").write_text("hej verden\n")
            os.chmod(w.ws / "notes.txt", 0o644)
            res = await w.dispatcher.read_only("dev", f"cat {w.ws}/notes.txt", "claude-code")
            assert res.ok
            assert res.output == "hej verden\n"
            refused = await w.dispatcher.read_only("dev", "cat /etc/passwd", "claude-code")
            assert not refused.ok  # refused centrally
            os.symlink("/etc/hostname", w.ws / "link")
            agent_refused = await w.dispatcher.read_only("dev", f"cat {w.ws}/link", "claude-code")
            assert not agent_refused.ok  # passes Warden's lexical check, refused by the agent's realpath
            assert agent_refused.refused[0]["code"] == "denied_path"
            assert actions(w).count("read_only") == 1
            assert actions(w).count("read_only_refused") == 2

    run(scenario())


def test_revoked_agent_is_cut_off() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            await w.start_agent()
            w.registry.revoke("dev", HUMAN)
            await w.dispatcher.revoke("dev")
            await asyncio.sleep(4)  # the agent keeps retrying; every attempt is refused
            assert "dev" not in w.dispatcher.sessions
            assert "agent_refused" in actions(w)

    run(scenario())


def test_token_cannot_be_reused() -> None:
    async def scenario() -> None:
        async with world() as w:
            await w.enroll()
            assert [a.status for a in w.registry.list()] == ["active"]

    run(scenario())
