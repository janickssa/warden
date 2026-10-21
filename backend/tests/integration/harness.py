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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from warden.actors import ClaudeActor, HumanActor
from warden.agents import Registry
from warden.ca import CA
from warden.config import Settings, parse_policy, parse_targets
from warden.db import make_engine
from warden.dispatch.server import Dispatcher
from warden.keys import OnlineKey
from warden.plans.models import Plan, ProposeRequest, Step, StepKind
from warden.plans.service import Config, PlanService
from warden.policy_dist import publish as publishing
from warden.signing import ApprovalKey

REPO = Path(__file__).resolve().parents[3]
HUMAN = HumanActor("cli", "alice")
CLAUDE = ClaudeActor("claude-code")
_BINARIES: dict[str, Path] = {}


def go_binary(name: str) -> Path:
    """Build a Go command once per test session into a directory the agent user can read."""
    if name not in _BINARIES:
        out = Path(tempfile.mkdtemp(prefix=f"{name}-bin-"))
        os.chmod(out, 0o755)
        subprocess.run(
            ["go", "build", "-o", str(out / name), f"./cmd/{name}"],
            cwd=REPO / "agent",
            check=True,
            env={**os.environ, "CGO_ENABLED": "0"},
        )
        os.chmod(out / name, 0o755)
        _BINARIES[name] = out / name
    return _BINARIES[name]


def agent_binary() -> Path:
    return go_binary("warden-agent")


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
    engine: Any
    plans: PlanService
    registry: Registry
    dispatcher: Dispatcher
    port: int
    agent_user: pwd.struct_passwd
    online: OnlineKey
    approval: ApprovalKey
    cfg: Config
    procs: list[asyncio.subprocess.Process] = field(default_factory=list)
    agents: dict[str, asyncio.subprocess.Process] = field(default_factory=dict)
    enroll_output: str = ""

    @property
    def agent(self) -> asyncio.subprocess.Process | None:
        return self.agents.get("dev")

    @property
    def server(self) -> str:
        return f"wss://127.0.0.1:{self.port}"

    def state_for(self, name: str) -> Path:
        if name == "dev":
            return self.state
        path = self.root / f"agent-state-{name}"
        if not path.exists():
            path.mkdir(mode=0o700)
            os.chown(path, self.agent_user.pw_uid, self.agent_user.pw_gid)
        return path

    def _spawn_kwargs(self, name: str = "dev") -> dict[str, object]:
        return {
            "user": self.agent_user.pw_uid,
            "group": self.agent_user.pw_gid,
            "env": {"HOME": str(self.state_for(name)), "PATH": "/usr/local/bin:/usr/bin:/bin"},
        }

    async def enroll(self, name: str = "dev") -> str:
        token = self.registry.create_token(name, HUMAN)
        proc = await asyncio.create_subprocess_exec(
            str(agent_binary()),
            "enroll",
            "--server",
            self.server,
            "--token",
            token,
            "--state",
            str(self.state_for(name)),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **self._spawn_kwargs(name),  # type: ignore[arg-type]
        )
        assert proc.stdout is not None
        line = (await asyncio.wait_for(proc.stdout.readline(), 20)).decode()
        assert "fingerprint" in line, line
        fp = line.split(": ", 1)[1].strip()
        await self.wait_for(lambda: fp in [p.fingerprint for p in self.registry.pending()])
        self.registry.confirm(name, fp, HUMAN)
        out = (await asyncio.wait_for(proc.stdout.read(), 20)).decode()
        assert await proc.wait() == 0, out
        self.enroll_output = out
        return fp

    async def start_agent(self, name: str = "dev") -> None:
        log = open(self.root / f"agent-{name}.log" if name != "dev" else self.root / "agent.log", "ab")  # noqa: SIM115
        proc = await asyncio.create_subprocess_exec(
            str(agent_binary()),
            "run",
            "--state",
            str(self.state_for(name)),
            stdout=log,
            stderr=log,
            **self._spawn_kwargs(name),  # type: ignore[arg-type]
        )
        self.agents[name] = proc
        self.procs.append(proc)
        await self.wait_for(lambda: name in self.dispatcher.sessions)

    async def stop_agent(self, name: str = "dev") -> None:
        proc = self.agents.get(name)
        if proc is not None and proc.returncode is None:
            proc.terminate()
            await proc.wait()
        await self.wait_for(lambda: name not in self.dispatcher.sessions)

    def publish(self, policy_yaml: str) -> publishing.PublishResult:
        """What `warden policy publish` does: publish, then the daemon re-reads config and pushes."""
        self.cfg = Config(
            policy=parse_policy(policy_yaml),
            targets=self.cfg.targets,
            settings=self.cfg.settings,
            policy_version=self.cfg.policy_version,
        )
        return publishing.publish(
            self.engine,
            policy=self.cfg.policy,
            targets=self.cfg.targets,
            online=self.online,
            approval=self.approval,
            now=datetime.now(UTC),
            actor="cli:alice",
        )

    async def wait_for(self, cond: object, timeout: float = 15) -> None:
        async def loop() -> None:
            while not cond():  # type: ignore[operator]
                await asyncio.sleep(0.02)

        try:
            await asyncio.wait_for(loop(), timeout)
        except TimeoutError:
            raise AssertionError(
                f"condition not met in {timeout} s; agent log:\n{self.agent_log()}"
            ) from None

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
        return "".join(
            f"--- {p.name}\n" + p.read_text(errors="replace") for p in sorted(self.root.glob("agent*.log"))
        )


@contextlib.asynccontextmanager
async def world(names: tuple[str, ...] = ("dev",)) -> AsyncIterator[World]:
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
    targets = parse_targets("".join(f"- {{name: {n}, workspace_roots: [{ws}]}}\n" for n in names))
    settings = Settings.model_validate({"agents": {"server_names": ["127.0.0.1", "localhost"]}})
    cfg = Config(policy=policy, targets=targets, settings=settings, policy_version=1)
    engine = make_engine(home / "warden.db")
    approval = ApprovalKey.generate(home / "keys/approval.key")
    online = OnlineKey.generate(home / "keys/online.key")
    ca = CA.load_or_create(home / "ca")
    publishing.publish(
        engine,
        policy=policy,
        targets=targets,
        online=online,
        approval=approval,
        now=datetime.now(UTC),
        actor="cli:alice",
    )
    holder: list[World] = []

    def current() -> Config:
        return holder[0].cfg if holder else cfg

    plans = PlanService(engine, config=current, approval_key=approval)
    registry = Registry(engine, ca, targets=lambda: targets)
    dispatcher = Dispatcher(
        engine=engine, plans=plans, registry=registry, ca=ca, online=online, config=current
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
        online=online,
        approval=approval,
        cfg=cfg,
    )
    holder.append(w)
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
