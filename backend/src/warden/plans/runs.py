"""Turning per-step outcomes into step and plan results (invariant 4: stop on first failure).

Pure functions, so the rules are tested here once and reused by the M2 dispatcher.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from warden.errors import WardenError
from warden.plans.models import PlanStatus, Step, StepResult, StepStatus

FailReason = Literal["exit_code", "timeout", "policy_violation", "agent_disconnected", "killed", "error"]


@dataclass(frozen=True, slots=True)
class StepOutcome:
    n: int
    exit_code: int | None
    timed_out: bool = False
    refused: str | None = None  # agent refusal code, e.g. "policy_violation"
    killed: bool = False  # kill switch
    disconnected: bool = False
    duration_s: float | None = None
    output_truncated: bool = False


@dataclass(frozen=True, slots=True)
class RunResult:
    status: PlanStatus
    steps: tuple[StepResult, ...]
    failed_at: int | None
    fail_reason: str | None


class BadRunReport(WardenError):
    code = "bad_run_report"


def _failure(outcome: StepOutcome, step: Step) -> str | None:
    if outcome.killed:
        return "killed"
    if outcome.refused is not None:
        return outcome.refused
    if outcome.disconnected:
        return "agent_disconnected"
    if outcome.timed_out:
        return "timeout"
    if outcome.exit_code is None:
        return "error"
    if outcome.exit_code != step.expect_exit:
        return "exit_code"
    return None


def reduce_run(steps: Sequence[Step], outcomes: Sequence[StepOutcome]) -> RunResult:
    """Apply stop-on-first-failure. Reports that don't fit the plan are refused (fail closed)."""
    if [o.n for o in outcomes] != [s.n for s in steps[: len(outcomes)]]:
        raise BadRunReport("step outcomes don't match the plan's steps in order")
    results: list[StepResult] = []
    failed_at: int | None = None
    reason: str | None = None
    for step, outcome in zip(steps, outcomes, strict=False):
        if failed_at is not None:
            raise BadRunReport(f"step {outcome.n} reported after step {failed_at} failed")
        why = _failure(outcome, step)
        if why is None:
            status = StepStatus.SUCCEEDED
        elif why == "killed":
            status = StepStatus.CANCELLED
        else:
            status = StepStatus.FAILED
        results.append(
            StepResult(
                n=step.n,
                status=status,
                exit_code=outcome.exit_code,
                reason=why,
                duration_s=outcome.duration_s,
                output_truncated=outcome.output_truncated,
            )
        )
        if why is not None:
            failed_at, reason = step.n, why
    if failed_at is None and len(outcomes) < len(steps):
        # The run ended without reporting every step: treat it as a failure at the first missing step.
        failed_at, reason = steps[len(outcomes)].n, "incomplete"
        results.append(StepResult(n=failed_at, status=StepStatus.FAILED, reason=reason))
    done = {r.n for r in results}
    results += [StepResult(n=s.n, status=StepStatus.SKIPPED) for s in steps if s.n not in done]
    if failed_at is None:
        status_ = PlanStatus.SUCCEEDED
    elif reason == "killed":
        status_ = PlanStatus.CANCELLED
    else:
        status_ = PlanStatus.FAILED
    return RunResult(status=status_, steps=tuple(results), failed_at=failed_at, fail_reason=reason)
