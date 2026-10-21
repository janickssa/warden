"""Warden dispatcher + the real Go agent binary, running as an unprivileged user (README 7A).

Each World gets its own temp tree under /tmp (readable by the agent's user), its own CA, keys, database,
policy and agent state. The agent runs as `nobody`, like it would run as `warden` on a target.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import pwd
import shutil
import subprocess
import tempfile
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path

from sqlmodel import Session

from warden.actors import ClaudeActor, HumanActor
from warden.agents import Registry
from warden.ca import CA
from warden.config import Settings, parse_policy, parse_targets
from warden.db import make_engine
from warden.dispatch.server import Dispatcher
from warden.keys import OnlineKey
from warden.plans.models import Plan, ProposeRequest, Step, StepKind
from warden.plans.service import Config, PlanService
from warden.policy_dist import bundle as bundles
from warden.signing import ApprovalKey

REPO = Path(__file__).resolve().parents[3]
HUMAN = HumanActor("cli", "alice")
CLAUDE = ClaudeActor("claude-code")
_BINARY: Path | None = None


def agent_binary() -> Path:
    """Build warden-agent once per test session into a directory the agent user can read."""
    global _BINARY
    if _BINARY is None:
        out = Path(tempfile.mkdtemp(prefix="warden-agent-bin-"))
        os.chmod(out, 0o755)
        subprocess.run(
            ["go", "build", "-o", str(out / "warden-agent"), "./cmd/warden-agent"],
            cwd=REPO / "agent",
            check=True,
            env={**os.environ, "CGO_ENABLED": "0"},
        )
        os.chmod(out / "warden-agent", 0o755)
        _BINARY = out / "warden-agent"
    return _BINARY


POLICY = """
deny_paths: [/etc, /root, /home]
commands:
  allow:
    echo: {}
    sleep: {}
    cat: {}
    ls: {}
    "true": {}
    "false": {}
  deny_patterns: ['echo\\s+forbidden']
limits: {step_timeout_s: 120, plan_max_steps: 10, output_cap_mb: 1}
"""


@dataclass
class World:
    root: Path
    ws: Path
    state: Path
    engine: object
    plans: PlanService
    registry: Registry
    dispatcher: Dispatcher
    port: int
    agent_user: pwd.struct_passwd
    procs: list[asyncio.subprocess.Process] = field(default_factory=list)
    agent: asyncio.subprocess.Process | None = None

    @property
    def server(self) -> str:
        return f"wss://127.0.0.1:{self.port}"

    def _spawn_kwargs(self) -> dict[str, object]:
        return {
            "user": self.agent_user.pw_uid,
            "group": self.agent_user.pw_gid,
            "env": {"HOME": str(self.state), "PATH": "/usr/local/bin:/usr/bin:/bin"},
        }

    async def enroll(self) -> str:
        token = self.registry.create_token("dev", HUMAN)
        proc = await asyncio.create_subprocess_exec(
            str(agent_binary()),
            "enroll",
            "--server",
            self.server,
            "--token",
            token,
            "--state",
            str(self.state),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **self._spawn_kwargs(),  # type: ignore[arg-type]
        )
        assert proc.stdout is not None
        line = (await asyncio.wait_for(proc.stdout.readline(), 20)).decode()
        assert "fingerprint" in line, line
        fp = line.split(": ", 1)[1].strip()
        await asyncio.sleep(0.3)
        assert [p.fingerprint for p in self.registry.pending()] == [fp]
        self.registry.confirm("dev", fp, HUMAN)
        out = (await asyncio.wait_for(proc.stdout.read(), 20)).decode()
        assert await proc.wait() == 0, out
        return fp

    async def start_agent(self) -> None:
        log = open(self.root / "agent.log", "ab")  # noqa: SIM115 - closed with the process
        self.agent = await asyncio.create_subprocess_exec(
            str(agent_binary()),
            "run",
            "--state",
            str(self.state),
            stdout=log,
            stderr=log,
            **self._spawn_kwargs(),  # type: ignore[arg-type]
        )
        self.procs.append(self.agent)
        await self.wait_for(lambda: "dev" in self.dispatcher.sessions)

    async def stop_agent(self) -> None:
        if self.agent is not None and self.agent.returncode is None:
            self.agent.terminate()
            await self.agent.wait()
        await self.wait_for(lambda: "dev" not in self.dispatcher.sessions)

    async def wait_for(self, cond: object, timeout: float = 15) -> None:
        async def loop() -> None:
            while not cond():  # type: ignore[operator]
                await asyncio.sleep(0.05)

        try:
            await asyncio.wait_for(loop(), timeout)
        except TimeoutError:
            log = (
                (self.root / "agent.log").read_text(errors="replace")
                if (self.root / "agent.log").exists()
                else ""
            )
            raise AssertionError(f"condition not met in {timeout} s; agent log:\n{log}") from None

    def propose(self, *commands: str, revises: str | None = None, timeout_s: int = 30) -> Plan:
        steps = tuple(
            Step(
                n=i,
                kind=StepKind.SHELL,
                command=c,
                purpose=f"Step {i}",
                cwd=str(self.ws),
                timeout_s=timeout_s,
            )
            for i, c in enumerate(commands, 1)
        )
        return self.plans.propose(
            ProposeRequest(goal="Integration test", target="dev", steps=steps, revises=revises), CLAUDE
        )

    def approve(self, plan: Plan) -> Plan:
        return self.plans.approve(plan.id, plan.hash, HUMAN)

    def agent_log(self) -> str:
        p = self.root / "agent.log"
        return p.read_text(errors="replace") if p.exists() else ""


@contextlib.asynccontextmanager
async def world() -> AsyncIterator[World]:
    user = pwd.getpwnam("nobody")
    root = Path(tempfile.mkdtemp(prefix="warden-it-"))
    os.chmod(root, 0o755)
    ws, state, home = root / "ws", root / "agent-state", root / "home"
    ws.mkdir()
    os.chown(ws, user.pw_uid, user.pw_gid)
    state.mkdir(mode=0o700)
    os.chown(state, user.pw_uid, user.pw_gid)
    home.mkdir(mode=0o700)
    (home / "keys").mkdir(mode=0o700)

    policy = parse_policy(POLICY)
    targets = parse_targets(f"- {{name: dev, workspace_roots: [{ws}]}}\n")
    settings = Settings.model_validate({"agents": {"server_names": ["127.0.0.1", "localhost"]}})
    cfg = Config(policy=policy, targets=targets, settings=settings, policy_version=1)
    engine = make_engine(home / "warden.db")
    approval = ApprovalKey.generate(home / "keys/approval.key")
    online = OnlineKey.generate(home / "keys/online.key")
    ca = CA.load_or_create(home / "ca")
    with Session(engine) as s, s.begin():
        from datetime import UTC, datetime

        bundles.publish_initial(
            s,
            policy=policy,
            targets=targets,
            online=online,
            approval=approval,
            now=datetime.now(UTC),
            actor="cli:alice",
        )
    plans = PlanService(engine, config=lambda: cfg, approval_key=approval)
    registry = Registry(engine, ca, targets=lambda: targets)
    dispatcher = Dispatcher(
        engine=engine, plans=plans, registry=registry, ca=ca, online=online, config=lambda: cfg
    )
    port = await dispatcher.start(host="127.0.0.1", port=0)
    w = World(
        root=root,
        ws=ws,
        state=state,
        engine=engine,
        plans=plans,
        registry=registry,
        dispatcher=dispatcher,
        port=port,
        agent_user=user,
    )
    try:
        yield w
    finally:
        for p in w.procs:
            if p.returncode is None:
                p.kill()
                await p.wait()
        await dispatcher.stop()
        engine.dispose()
        shutil.rmtree(root, ignore_errors=True)
