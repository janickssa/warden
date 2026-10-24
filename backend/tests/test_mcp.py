"""MCP tools (README 6, D-14) through an in-process MCP client. The real agent path is in integration/."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC
from pathlib import Path
from typing import Any

import pytest
from mcp import Client
from mcp.types import CallToolResult, ElicitResult
from sqlalchemy import Engine
from sqlmodel import Session
from svc import ALICE, World

from warden import audit
from warden.actors import ClaudeActor
from warden.dispatch.server import ReadOnlyOutcome
from warden.mcp.server import TOOL_NAMES, WardenMcp, build_server
from warden.plans.models import Plan, PlanStatus
from warden.plans.runs import StepOutcome
from warden.signing import ApprovalKey

S = PlanStatus


@dataclass
class FakeDispatcher:
    """Stands in for the agent side: read_only writes a real audit entry, execute fails or succeeds."""

    world: World
    exit_codes: list[int] = field(default_factory=lambda: [0])
    sessions: dict[str, Any] = field(default_factory=dict)
    _tasks: set[asyncio.Task[Any]] = field(default_factory=set)

    async def read_only(self, target: str, command: str, actor: str) -> ReadOnlyOutcome:
        if command.startswith("cat /etc"):
            with Session(self.world.engine) as s, s.begin():
                row = audit.append(
                    s,
                    ts=self.world.clock(),
                    actor=actor,
                    action="read_only_refused",
                    subject=f"{target} · {command}",
                    detail={"target": target, "command": command},
                )
                seq = row.seq
            return ReadOnlyOutcome(False, None, "", False, [{"code": "denied_path", "message": "no"}], seq)
        with Session(self.world.engine) as s, s.begin():
            row = audit.append(
                s,
                ts=self.world.clock(),
                actor=actor,
                action="read_only",
                subject=f"{target} · {command}",
                detail={
                    "target": target,
                    "command": command,
                    "exit_code": 0,
                    "output": "package.json\n",
                    "truncated": False,
                },
            )
            seq = row.seq
        return ReadOnlyOutcome(True, 0, "package.json\n", False, [], seq)

    async def _run(self, plan_id: str) -> Plan:
        plan = self.world.svc.start_run(plan_id)
        outcomes = [
            StepOutcome(n=i, exit_code=c) for i, c in enumerate(self.exit_codes[: len(plan.steps)], 1)
        ]
        return self.world.svc.finish_run(plan_id, outcomes)

    def execute_in_background(self, plan_id: str) -> asyncio.Task[Plan]:
        t = asyncio.get_running_loop().create_task(self._run(plan_id))
        self._tasks.add(t)
        return t

    def run_progress(self, plan_id: str) -> tuple[int, int] | None:
        return None


@pytest.fixture
def world(engine: Engine, tmp_path: Path) -> World:
    return World(engine=engine, key=ApprovalKey.generate(tmp_path / "approval.key"))


def make(world: World, client: str | None = "claude-code", **kw: Any) -> tuple[WardenMcp, FakeDispatcher]:
    disp = FakeDispatcher(world, **kw)
    w = WardenMcp(
        engine=world.engine,
        plans=world.svc,
        dispatcher=disp,  # type: ignore[arg-type]
        config=world.config,
        identify=lambda ctx: client,
        clock=world.clock,
    )
    return w, disp


def data(r: CallToolResult) -> dict[str, Any]:
    assert not r.is_error, r.content
    if r.structured_content is not None:
        sc = r.structured_content
        return sc.get("result", sc) if set(sc) == {"result"} else sc
    return json.loads(r.content[0].text)  # type: ignore[union-attr]


def error(r: CallToolResult) -> str:
    assert r.is_error
    return r.content[0].text  # type: ignore[union-attr]


STEP = {
    "n": 1,
    "kind": "shell",
    "command": "npm ci",
    "purpose": "Install",
    "cwd": "/srv/dev/myapp",
    "timeout_s": 60,
}


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_exactly_the_readme_tools(world: World) -> None:
    async def go() -> None:
        w, _ = make(world)
        async with Client(build_server(w)) as c:
            tools = (await c.list_tools()).tools
        assert sorted(t.name for t in tools) == sorted(TOOL_NAMES)
        forbidden = (
            "approve",
            "reject",
            "force",
            "override",
            "policy",
            "setting",
            "edit",
            "publish",
            "lockdown",
        )
        for t in tools:
            assert not any(f in t.name for f in forbidden), t.name
            props = json.dumps(t.input_schema).lower()
            for f in ("approve", "approval", "edited", "signature", "status"):
                assert f'"{f}"' not in props, (t.name, f)
        assert all(t.description for t in tools)

    run(go())


def test_propose_get_and_wait(world: World) -> None:
    async def go() -> None:
        w, _ = make(world)
        async with Client(build_server(w)) as c:
            p = data(
                await c.call_tool("propose_plan", {"goal": "Install deps", "target": "dev", "steps": [STEP]})
            )
            assert p["status"] == "awaiting_approval"
            assert p["requested_by"] == "claude-code"
            assert "warden approve" in p["next"]
            got = data(await c.call_tool("get_plan", {"plan_id": p["plan_id"]}))
            assert got["hash"] == p["hash"]

            waited = data(await c.call_tool("wait_for_approval", {"plan_id": p["plan_id"], "timeout_s": 1}))
            assert waited["decided"] is False

            async def approve_soon() -> None:
                await asyncio.sleep(0.3)
                world.svc.approve(p["plan_id"], p["hash"], ALICE)

            task = asyncio.create_task(approve_soon())
            waited = data(await c.call_tool("wait_for_approval", {"plan_id": p["plan_id"], "timeout_s": 10}))
            await task
            assert waited["decided"] is True
            assert waited["status"] == "approved"

    run(go())


def test_policy_deny_is_reported(world: World) -> None:
    async def go() -> None:
        w, _ = make(world)
        async with Client(build_server(w)) as c:
            bad = {**STEP, "command": "rm -rf /"}
            p = data(await c.call_tool("propose_plan", {"goal": "Oops", "target": "dev", "steps": [bad]}))
        assert p["status"] == "rejected"
        assert p["policy"]["ok"] is False
        assert "final" in p["next"]

    run(go())


@pytest.mark.parametrize(
    "args",
    [
        {"goal": "x", "target": "dev", "steps": [{**STEP, "edited": True}]},
        {"goal": "x", "target": "dev", "steps": [{**STEP, "kind": "sudo"}]},
        {"goal": "x", "target": "Prod!", "steps": [STEP]},
        {"goal": "x", "target": "nope", "steps": [STEP]},
    ],
)
def test_bad_proposals_refused(world: World, args: dict[str, Any]) -> None:
    async def go() -> None:
        w, _ = make(world)
        async with Client(build_server(w)) as c:
            r = await c.call_tool("propose_plan", args)
        assert r.is_error

    run(go())


def test_unauthenticated_client_refused(world: World) -> None:
    async def go() -> None:
        w, _ = make(world, client=None)
        async with Client(build_server(w)) as c:
            r = await c.call_tool("list_resources", {})
        assert "unauthenticated" in error(r)

    run(go())


def test_execute_needs_approval_then_fails_then_diagnosis(world: World) -> None:
    async def go() -> None:
        w, _ = make(world, exit_codes=[1])
        async with Client(build_server(w)) as c:
            p = data(
                await c.call_tool("propose_plan", {"goal": "Install deps", "target": "dev", "steps": [STEP]})
            )
            assert "not_approved" in error(await c.call_tool("execute_plan", {"plan_id": p["plan_id"]}))
            world.svc.approve(p["plan_id"], p["hash"], ALICE)
            done = data(await c.call_tool("execute_plan", {"plan_id": p["plan_id"]}))
            assert done["status"] == "failed"
            assert done["failed_at"] == 1
            assert "post_diagnosis" in done["next"]

            ro = data(await c.call_tool("read_only", {"target": "dev", "command": "ls /srv/dev/myapp"}))
            assert ro["ok"] is True
            d = data(
                await c.call_tool(
                    "post_diagnosis",
                    {
                        "plan_id": p["plan_id"],
                        "note": "No lockfile; generate one first.",
                        "read_only_audit_ids": [ro["audit_id"]],
                    },
                )
            )
            assert d["evidence"][0]["command"] == "ls /srv/dev/myapp"
            assert d["evidence"][0]["output_untrusted"] == "package.json\n"
            got = data(await c.call_tool("get_plan", {"plan_id": p["plan_id"]}))
            assert got["diagnoses"][0]["note"] == "No lockfile; generate one first."
            assert got["status"] == "failed"  # posting changes nothing

            fix = [{**STEP, "command": "npm install --package-lock-only"}, {**STEP, "n": 2}]
            r = data(
                await c.call_tool(
                    "propose_plan",
                    {"goal": "Install deps", "target": "dev", "steps": fix, "revises": p["plan_id"]},
                )
            )
            diff = data(await c.call_tool("diff_plans", {"old_id": p["plan_id"], "new_id": r["plan_id"]}))
            assert [row["op"] for row in diff["rows"]] == ["added", "same"]

    run(go())


def _failed_plan(world: World) -> Plan:
    p = world.propose("npm ci")
    world.svc.approve(p.id, p.hash, ALICE)
    world.svc.start_run(p.id)
    return world.svc.finish_run(p.id, [StepOutcome(n=1, exit_code=1)])


def _ro(world: World, actor: str = "claude-code", target: str = "dev", action: str = "read_only") -> int:
    with Session(world.engine) as s, s.begin():
        return audit.append(
            s,
            ts=world.clock(),
            actor=actor,
            action=action,
            subject=f"{target} · ls",
            detail={"target": target, "command": "ls", "exit_code": 0, "output": "x"},
        ).seq


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("not_failed", "not_failed"),
        ("before_failure", "bad_evidence"),
        ("other_client", "bad_evidence"),
        ("other_target", "bad_evidence"),
        ("refused_command", "bad_evidence"),
        ("not_read_only", "bad_evidence"),
        ("duplicate", "duplicate_ids"),
        ("too_many", "too_many_ids"),
        ("invisible_note", "bad_note"),
        ("long_note", "bad_note"),
        ("unknown_id", "bad_evidence"),
    ],
)
def test_post_diagnosis_refusals(world: World, case: str, code: str) -> None:
    from warden.plans import diagnosis

    note, ids = "Lockfile missing.", []
    if case == "not_failed":
        plan_id = world.propose("npm ci").id
    else:
        early = _ro(world)
        plan_id = _failed_plan(world).id
        ids = {
            "before_failure": [early],
            "other_client": [_ro(world, actor="claude-desktop")],
            "other_target": [_ro(world, target="dev2")],
            "refused_command": [_ro(world, action="read_only_refused")],
            "not_read_only": [_ro(world, action="approve")],
            "duplicate": [_ro(world)] * 2,
            "too_many": [_ro(world) for _ in range(21)],
            "unknown_id": [99999],
        }.get(case, [])
        if case == "invisible_note":
            note = "Looks fine\u200b"
        if case == "long_note":
            note = "x" * 4001
    with pytest.raises(diagnosis.DiagnosisRefused) as exc:
        diagnosis.post(
            world.engine,
            plan_id=plan_id,
            note=note,
            audit_ids=ids,
            actor=ClaudeActor("claude-code"),
            now=world.clock(),
        )
    assert exc.value.code == code


def test_read_only_refusal_and_list_resources(world: World) -> None:
    async def go() -> None:
        w, _ = make(world)
        async with Client(build_server(w)) as c:
            ro = data(await c.call_tool("read_only", {"target": "dev", "command": "cat /etc/shadow"}))
            assert ro["ok"] is False
            assert ro["refused"][0]["code"] == "denied_path"
            res = data(await c.call_tool("list_resources", {}))
            names = [t["target"] for t in res["targets"]]
            assert names == ["dev", "dev2", "sec-auth"]
            sec = data(await c.call_tool("list_resources", {"target": "sec-auth"}))["targets"][0]
            assert sec["read_only"]["mode"] == "restricted"
            assert "high-security" in sec["groups"]
            assert "settings" not in json.dumps(res).lower()
            assert "refused (unknown_target)" in error(
                await c.call_tool("list_resources", {"target": "prod"})
            )

    run(go())


def test_auto_answering_client_cant_approve(world: World) -> None:
    """A client that would accept any elicitation gets none, and waiting never decides (invariant 3)."""
    seen: list[str] = []

    async def auto_accept(context: Any, params: Any) -> ElicitResult:
        seen.append(params.message)
        return ElicitResult(action="accept", content={})

    async def go() -> None:
        w, _ = make(world)
        for mode in ("auto", "legacy"):
            async with Client(build_server(w), elicitation_callback=auto_accept, mode=mode) as c:
                p = data(
                    await c.call_tool(
                        "propose_plan", {"goal": "Install deps", "target": "dev", "steps": [STEP]}
                    )
                )
                waited = data(
                    await c.call_tool("wait_for_approval", {"plan_id": p["plan_id"], "timeout_s": 1})
                )
            assert waited["decided"] is False
            assert world.svc.get(p["plan_id"]).status == S.AWAITING_APPROVAL
        assert seen == []

    run(go())


def test_wait_expires(world: World) -> None:
    async def go() -> None:
        w, _ = make(world)
        async with Client(build_server(w)) as c:
            p = data(
                await c.call_tool("propose_plan", {"goal": "Install deps", "target": "dev", "steps": [STEP]})
            )
            world.clock.advance(minutes=31)
            waited = data(await c.call_tool("wait_for_approval", {"plan_id": p["plan_id"], "timeout_s": 3}))
        assert waited["status"] == "expired"
        assert waited["decided"] is True

    run(go())


def test_clock_is_aware(world: World) -> None:
    assert world.clock().tzinfo is UTC


def test_mcp_code_never_reaches_human_only_paths() -> None:
    """Source guard for invariant 3: nothing under warden/mcp calls approve/reject/edit/publish/settings."""
    import re
    from pathlib import Path

    import warden.mcp

    forbidden = re.compile(
        r"\.(approve|approve_with_edits|reject|hold|release|publish|lockdown|lift|sign_upload|discard|register)\(|"
        r"HumanActor|offline_keys|load_settings|settings\.yaml|admin_request"
    )
    for path in Path(warden.mcp.__file__).parent.glob("*.py"):
        for i, line in enumerate(path.read_text().splitlines(), 1):
            assert not forbidden.search(line) or "clients.py" in path.name, f"{path.name}:{i}: {line.strip()}"
