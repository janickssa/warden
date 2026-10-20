"""Gatekeeper panel interface (README section 9). Real adapters arrive in M5.

Until then `NullPanel` reviews nothing, and `final_verdict` turns "no reviewers" into `escalate`
(DECISIONS D-19), so nothing ever looks auto-allowed.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from warden.plans.models import GatekeeperVerdict, Plan, Risk, Verdict
from warden.policy.effective import EffectiveRules

_RANK = {Verdict.ALLOW: 0, Verdict.ESCALATE: 1, Verdict.DENY: 2}
_RISK_RANK = {Risk.LOW: 0, Risk.MEDIUM: 1, Risk.HIGH: 2}


class Panel(Protocol):
    def review(
        self, plan: Plan, rules: EffectiveRules, previous: Plan | None
    ) -> tuple[GatekeeperVerdict, ...]: ...


class NullPanel:
    def review(
        self, plan: Plan, rules: EffectiveRules, previous: Plan | None
    ) -> tuple[GatekeeperVerdict, ...]:
        return ()


def final_verdict(verdicts: Sequence[GatekeeperVerdict]) -> Verdict:
    """Strictest wins. No reviewers, or an unavailable one, means at least escalate.

    A group's `gatekeepers.unanimous` doesn't change this verdict (strictest already escalates when any
    reviewer isn't `allow`); it gates the Approve button instead, which arrives with M5/M6.
    """
    if not verdicts:
        return Verdict.ESCALATE
    worst = Verdict.ALLOW
    for v in verdicts:
        effective = Verdict.ESCALATE if v.unavailable and v.verdict == Verdict.ALLOW else v.verdict
        if _RANK[effective] > _RANK[worst]:
            worst = effective
    return worst


def plan_risk(verdicts: Sequence[GatekeeperVerdict]) -> Risk | None:
    if not verdicts:
        return None
    return max((v.risk for v in verdicts), key=lambda r: _RISK_RANK[r])


def safe_review(
    panel: Panel, plan: Plan, rules: EffectiveRules, previous: Plan | None
) -> tuple[GatekeeperVerdict, ...]:
    """A panel that crashes counts as one unavailable reviewer (escalate), never as approval."""
    try:
        return tuple(panel.review(plan, rules, previous))
    except Exception as exc:
        return (
            GatekeeperVerdict(
                name="panel",
                model="-",
                verdict=Verdict.ESCALATE,
                risk=Risk.HIGH,
                summary=f"Gatekeeper panel failed ({type(exc).__name__}) · counted as escalate",
                unavailable=True,
            ),
        )
