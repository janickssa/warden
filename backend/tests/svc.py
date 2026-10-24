"""A PlanService wired to a temp DB, the fixture policy and a controllable clock."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from factories import T0
from policyhelp import fixture_policy, fixture_targets
from sqlalchemy import Engine

from warden.actors import ClaudeActor, HumanActor
from warden.config import Settings
from warden.gatekeeper.panel import Panel
from warden.plans.models import Plan, ProposeRequest, Step, StepKind
from warden.plans.service import Config, PlanService
from warden.policy.schema import Policy
from warden.signing import ApprovalKey

CLAUDE = ClaudeActor("claude-code")
ALICE = HumanActor("cli", "alice")
DASH = HumanActor("dashboard", "alice")


@dataclass
class Clock:
    now: datetime = T0

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw: float) -> None:
        self.now += timedelta(**kw)


@dataclass
class World:
    engine: Engine
    key: ApprovalKey
    clock: Clock = field(default_factory=Clock)
    policy: Policy = field(default_factory=fixture_policy)
    version: int = 1
    lockdown: bool = False
    e2e: bool = False
    panel: Panel | None = None
    _svc: PlanService | None = None

    def config(self) -> Config:
        return Config(
            policy=self.policy,
            targets=fixture_targets(),
            settings=Settings(),
            policy_version=self.version,
            lockdown=self.lockdown,
            e2e=self.e2e,
        )

    @property
    def svc(self) -> PlanService:
        if self._svc is None:
            self._svc = PlanService(
                self.engine, config=self.config, approval_key=self.key, panel=self.panel, clock=self.clock
            )
        return self._svc

    def propose(
        self,
        *commands: str | tuple[str, str],
        target: str = "dev",
        revises: str | None = None,
        goal: str = "Deploy myapp on dev and verify HTTP health",
        cwd: str = "/srv/dev/myapp",
    ) -> Plan:
        steps = []
        for i, c in enumerate(commands, 1):
            kind, cmd = ("shell", c) if isinstance(c, str) else c
            steps.append(
                Step(n=i, kind=StepKind(kind), command=cmd, purpose=f"Step {i}", cwd=cwd, timeout_s=60)
            )
        req = ProposeRequest(goal=goal, target=target, steps=tuple(steps), revises=revises)
        return self.svc.propose(req, CLAUDE)

    def approve(self, plan: Plan, actor: HumanActor = ALICE) -> Plan:
        return self.svc.approve(plan.id, plan.hash[7:19], actor)


def make_world(engine: Engine, tmp_path: Path, **kw: Any) -> World:
    return World(engine=engine, key=ApprovalKey.generate(tmp_path / "approval.key"), **kw)
