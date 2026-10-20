"""Builders for plans and steps used across tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from ulid import ULID

from warden.plans.hashing import plan_hash
from warden.plans.models import Plan, PlanStatus, PolicyResult, Step, StepKind

T0 = datetime(2026, 10, 20, 12, 0, 0, tzinfo=UTC)


def step(n: int = 1, command: str = "npm ci", **kw: Any) -> Step:
    data: dict[str, Any] = {
        "n": n,
        "kind": StepKind.SHELL,
        "command": command,
        "purpose": "Install dependencies",
        "cwd": "/srv/dev/myapp",
        "timeout_s": 300,
    }
    data.update(kw)
    data["kind"] = StepKind(data["kind"])
    return Step(**data)


def plan(steps: list[Step] | None = None, **kw: Any) -> Plan:
    data: dict[str, Any] = {
        "id": f"pln_{ULID()}",
        "revises": None,
        "goal": "Deploy myapp on dev and verify HTTP health",
        "target": "dev",
        "requested_by": "claude-code",
        "steps": tuple(steps or [step()]),
        "hash": "",
        "status": PlanStatus.AWAITING_APPROVAL,
        "policy_result": PolicyResult.passed(),
        "created_at": T0,
        "expires_at": T0 + timedelta(minutes=30),
    }
    data.update(kw)
    data["status"] = PlanStatus(data["status"])
    p = Plan(**data)
    return p.model_copy(update={"hash": plan_hash(p)})
