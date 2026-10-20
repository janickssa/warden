from __future__ import annotations

import pytest
from factories import step

from warden.plans.diff import changed_steps, diff_steps
from warden.plans.models import PlanStatus, StepStatus
from warden.plans.runs import BadRunReport, StepOutcome, reduce_run

STEPS = [step(1, "npm ci"), step(2, "npm test"), step(3, "npm run build")]
OK, FAIL, SKIP, CANC = StepStatus.SUCCEEDED, StepStatus.FAILED, StepStatus.SKIPPED, StepStatus.CANCELLED


def statuses(outcomes: list[StepOutcome]) -> tuple[PlanStatus, list[StepStatus], int | None, str | None]:
    r = reduce_run(STEPS, outcomes)
    return r.status, [s.status for s in r.steps], r.failed_at, r.fail_reason


def test_all_succeed() -> None:
    assert statuses([StepOutcome(n, 0) for n in (1, 2, 3)]) == (
        PlanStatus.SUCCEEDED,
        [OK, OK, OK],
        None,
        None,
    )


@pytest.mark.parametrize(
    ("outcome", "reason"),
    [
        (StepOutcome(2, 1), "exit_code"),
        (StepOutcome(2, None, timed_out=True), "timeout"),
        (StepOutcome(2, 126, refused="policy_violation"), "policy_violation"),
        (StepOutcome(2, 137, disconnected=True), "agent_disconnected"),
        (StepOutcome(2, None), "error"),
    ],
)
def test_stop_on_first_failure(outcome: StepOutcome, reason: str) -> None:
    assert statuses([StepOutcome(1, 0), outcome]) == (PlanStatus.FAILED, [OK, FAIL, SKIP], 2, reason)


def test_expect_exit_is_respected() -> None:
    steps = [step(1, "npm test", expect_exit=1)]
    assert reduce_run(steps, [StepOutcome(1, 1)]).status == PlanStatus.SUCCEEDED
    assert reduce_run(steps, [StepOutcome(1, 0)]).status == PlanStatus.FAILED


def test_kill_cancels_and_skips_rest() -> None:
    assert statuses([StepOutcome(1, None, killed=True)]) == (
        PlanStatus.CANCELLED,
        [CANC, SKIP, SKIP],
        1,
        "killed",
    )


def test_incomplete_report_is_a_failure() -> None:
    assert statuses([StepOutcome(1, 0)]) == (PlanStatus.FAILED, [OK, FAIL, SKIP], 2, "incomplete")


@pytest.mark.parametrize(
    "outcomes",
    [
        [StepOutcome(2, 0)],
        [StepOutcome(1, 0), StepOutcome(1, 0)],
        [StepOutcome(1, 1), StepOutcome(2, 0)],
        [StepOutcome(1, 0), StepOutcome(2, 0), StepOutcome(3, 0), StepOutcome(4, 0)],
    ],
)
def test_reports_that_dont_fit_are_refused(outcomes: list[StepOutcome]) -> None:
    with pytest.raises(BadRunReport):
        reduce_run(STEPS, outcomes)


def test_truncated_output_still_counts_exit_code() -> None:
    r = reduce_run(STEPS[:1], [StepOutcome(1, 0, output_truncated=True)])
    assert r.status == PlanStatus.SUCCEEDED
    assert r.steps[0].output_truncated


def test_diff_matches_prototype() -> None:
    old = [
        step(1, "git clone https://github.com/you/myapp /srv/dev/myapp"),
        step(2, "git -C /srv/dev/myapp checkout v1.4.2"),
        step(3, "npm ci"),
        step(4, "docker compose -p dev-myapp up -d --build"),
        step(5, "curl -I http://localhost:8080/health"),
    ]
    new = [
        step(1, "git -C /srv/dev/myapp checkout v1.4.2"),
        step(2, "npm install --package-lock-only"),
        step(3, "npm ci"),
        step(4, "docker compose -p dev-myapp up -d --build"),
        step(5, "curl -I http://localhost:8080/health"),
    ]
    rows = diff_steps(old, new)
    assert [(r.old_n, r.new_n, r.op) for r in rows] == [
        (1, None, "removed"),
        (2, 1, "same"),
        (None, 2, "added"),
        (3, 3, "same"),
        (4, 4, "same"),
        (5, 5, "same"),
    ]
    assert changed_steps(rows) == 2


def test_diff_changed_cwd_counts() -> None:
    assert changed_steps(diff_steps([step(1, "npm ci")], [step(1, "npm ci", cwd="/srv/dev/other")])) == 2


def test_diff_empty() -> None:
    assert diff_steps([], [step(1)])[0].op == "added"
    assert diff_steps([step(1)], [])[0].op == "removed"
