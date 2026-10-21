"""Shared helpers for policy tests: rules built from the shared fixture policy."""

from __future__ import annotations

from functools import cache
from pathlib import Path

from warden.config import load_policy, load_targets
from warden.plans.models import Step, StepKind
from warden.policy.effective import EffectiveRules, effective_rules
from warden.policy.schema import Policy, Targets

FIXTURES = Path(__file__).resolve().parents[2] / "policy-fixtures"


@cache
def fixture_policy() -> Policy:
    return load_policy(FIXTURES / "policy.yaml")


@cache
def fixture_targets() -> Targets:
    return load_targets(FIXTURES / "targets.yaml")


def rules_for(target: str = "dev", *, lockdown: bool = False) -> EffectiveRules:
    t = fixture_targets().get(target)
    assert t is not None, target
    return effective_rules(fixture_policy(), t, version=1, lockdown=lockdown)


def mkstep(
    command: str,
    kind: str = "shell",
    cwd: str = "/srv/dev/myapp",
    n: int = 1,
    timeout_s: int = 60,
    **kw: object,
) -> Step:
    return Step(n=n, kind=StepKind(kind), command=command, purpose="test", cwd=cwd, timeout_s=timeout_s, **kw)  # type: ignore[arg-type]
