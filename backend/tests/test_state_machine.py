from __future__ import annotations

import itertools

import pytest

from warden.errors import IllegalTransition
from warden.plans.models import PlanStatus as S
from warden.plans.state import TERMINAL, TRANSITIONS, can_transition, check_transition

# Exactly README section 4, plus approved/held -> expired (DECISIONS X-16).
EXPECTED = {
    (S.PROPOSED, S.REJECTED),
    (S.PROPOSED, S.AWAITING_APPROVAL),
    (S.AWAITING_APPROVAL, S.APPROVED),
    (S.AWAITING_APPROVAL, S.REVIEWING),
    (S.AWAITING_APPROVAL, S.REJECTED),
    (S.AWAITING_APPROVAL, S.EXPIRED),
    (S.AWAITING_APPROVAL, S.INVALIDATED),
    (S.REVIEWING, S.AWAITING_APPROVAL),
    (S.REVIEWING, S.REJECTED),
    (S.APPROVED, S.RUNNING),
    (S.APPROVED, S.HELD),
    (S.APPROVED, S.INVALIDATED),
    (S.APPROVED, S.EXPIRED),
    (S.HELD, S.APPROVED),
    (S.HELD, S.INVALIDATED),
    (S.HELD, S.EXPIRED),
    (S.RUNNING, S.SUCCEEDED),
    (S.RUNNING, S.FAILED),
    (S.RUNNING, S.CANCELLED),
}


def test_every_status_has_an_entry() -> None:
    assert set(TRANSITIONS) == set(S)


@pytest.mark.parametrize(("src", "dst"), sorted(EXPECTED))
def test_legal_transitions(src: S, dst: S) -> None:
    check_transition(src, dst)


ILLEGAL = sorted(set(itertools.product(S, S)) - EXPECTED)


@pytest.mark.parametrize(("src", "dst"), ILLEGAL)
def test_every_other_pair_is_illegal(src: S, dst: S) -> None:
    assert not can_transition(src, dst)
    with pytest.raises(IllegalTransition):
        check_transition(src, dst)


def test_terminal_states() -> None:
    assert {S.SUCCEEDED, S.FAILED, S.REJECTED, S.EXPIRED, S.CANCELLED, S.INVALIDATED} == TERMINAL


def test_failed_plan_can_never_resume() -> None:
    for dst in S:
        assert not can_transition(S.FAILED, dst)


def test_nothing_reaches_running_except_from_approved() -> None:
    assert {src for src, dst in EXPECTED if dst == S.RUNNING} == {S.APPROVED}


def test_approval_only_from_awaiting_or_released_hold() -> None:
    assert {src for src, dst in EXPECTED if dst == S.APPROVED} == {S.AWAITING_APPROVAL, S.HELD}
