"""Plan lifecycle (README section 4).

The diagram's `reviewed` box isn't a stored status (section 5 doesn't list it): it's the moment inside
`proposed -> awaiting_approval` when policy and gatekeepers have finished. `approved`/`held -> expired`
come from the section 4 text ("unless it has expired"), so an approval can't stay valid forever.
"""

from __future__ import annotations

from collections.abc import Mapping

from warden.errors import IllegalTransition
from warden.plans.models import PlanStatus as S

TRANSITIONS: Mapping[S, frozenset[S]] = {
    S.PROPOSED: frozenset({S.REJECTED, S.AWAITING_APPROVAL}),
    S.AWAITING_APPROVAL: frozenset({S.APPROVED, S.REVIEWING, S.REJECTED, S.EXPIRED, S.INVALIDATED}),
    S.REVIEWING: frozenset({S.AWAITING_APPROVAL, S.REJECTED}),
    S.APPROVED: frozenset({S.RUNNING, S.HELD, S.INVALIDATED, S.EXPIRED}),
    S.HELD: frozenset({S.APPROVED, S.INVALIDATED, S.EXPIRED}),
    S.RUNNING: frozenset({S.SUCCEEDED, S.FAILED, S.CANCELLED}),
    S.SUCCEEDED: frozenset(),
    S.FAILED: frozenset(),
    S.REJECTED: frozenset(),
    S.EXPIRED: frozenset(),
    S.CANCELLED: frozenset(),
    S.INVALIDATED: frozenset(),
}

TERMINAL: frozenset[S] = frozenset(s for s, nxt in TRANSITIONS.items() if not nxt)
# Statuses a revision may point back to with `revises`.
REVISABLE: frozenset[S] = frozenset({S.FAILED, S.INVALIDATED, S.REJECTED, S.EXPIRED, S.CANCELLED})


def can_transition(src: S, dst: S) -> bool:
    return dst in TRANSITIONS[src]


def check_transition(src: S, dst: S) -> None:
    if not can_transition(src, dst):
        raise IllegalTransition(f"a plan can't go from {src.value} to {dst.value}")
