"""Gatekeeper panel (README section 9).

`ReviewPanel` runs the built-in `injection-scan` and every configured model reviewer in parallel threads
under one overall timeout. Strictest wins. A reviewer that errors, hangs or answers badly is unavailable and
counts as escalate. No model reviewers at all is itself an escalate row (D-19), so the scan alone can never
make a plan look allowed. `NullPanel` (tests, or no panel wired) reviews nothing, which also escalates.
"""

from __future__ import annotations

import concurrent.futures as cf
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx2
from sqlalchemy import Engine
from sqlmodel import Session

from warden.dispatch import outputs
from warden.gatekeeper import scan as injection
from warden.gatekeeper.adapters import Reviewer, make_reviewer
from warden.gatekeeper.config import GatekeeperConfig, Secrets, load_gatekeeper
from warden.gatekeeper.prompt import Evidence, PreviousContext, all_untrusted, build_request
from warden.gatekeeper.verdict import unavailable
from warden.plans import diagnosis
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


NO_REVIEWERS = "gatekeepers"


@dataclass
class ReviewPanel:
    config: GatekeeperConfig
    secrets: Secrets
    context: Callable[[Plan], PreviousContext] | None = None
    transport: httpx2.BaseTransport | None = None  # tests
    grace_s: float = 5.0  # on top of timeout_s, for the adapters' own timeouts to fire first

    def reviewers(self) -> list[Reviewer]:
        return [
            make_reviewer(r, self.secrets, timeout_s=self.config.timeout_s, transport=self.transport)
            for r in self.config.reviewers
        ]

    def review(
        self, plan: Plan, rules: EffectiveRules, previous: Plan | None
    ) -> tuple[GatekeeperVerdict, ...]:
        prev = (
            self.context(previous)
            if (previous is not None and self.context is not None)
            else (PreviousContext(previous) if previous is not None else None)
        )
        steps = tuple(st.n for st in plan.steps)
        out: list[GatekeeperVerdict] = []
        if self.config.injection_scan:
            out.append(injection.scan(all_untrusted(prev, plan), steps))
        reviewers = self.reviewers()
        if not reviewers:
            out.append(unavailable(NO_REVIEWERS, "-", "no gatekeepers configured", risk=Risk.MEDIUM))
            return tuple(out)
        secret_values = self.secrets.values()
        pool = cf.ThreadPoolExecutor(max_workers=len(reviewers), thread_name_prefix="gatekeeper")
        try:
            futures = {
                pool.submit(
                    r.review,
                    build_request(plan, rules, prev, secrets=secret_values, send_untrusted=r.sends_untrusted),
                ): r
                for r in reviewers
            }
            done, _ = cf.wait(futures, timeout=self.config.timeout_s + self.grace_s)
            for fut, r in futures.items():
                if fut in done and fut.exception() is None:
                    out.append(fut.result())
                elif fut in done:
                    out.append(
                        unavailable(r.name, r.model, f"reviewer crashed ({type(fut.exception()).__name__})")
                    )
                else:
                    out.append(unavailable(r.name, r.model, "timed out"))
        finally:
            pool.shutdown(wait=False, cancel_futures=True)
        return tuple(out)


def previous_context(engine: Engine) -> Callable[[Plan], PreviousContext]:
    """For a revision: Claude's diagnosis notes plus the real output of the failed plan and cited commands."""

    def load(prev: Plan) -> PreviousContext:
        evidence: list[Evidence] = []
        with Session(engine) as s:
            for r in prev.step_results:
                if r.status.value in ("failed", "succeeded") and (
                    prev.failed_at is None or r.n >= prev.failed_at - 1
                ):
                    text = "".join(row.data for row in outputs.read(s, prev.id, r.n))
                    if text:
                        evidence.append(Evidence(f"{prev.id} step {r.n} output", text))
        notes = []
        for d in diagnosis.for_plan(engine, prev.id):
            notes.append(d.note)
            evidence += [Evidence(f"read_only: {e.command}", e.output) for e in d.evidence if e.output]
        return PreviousContext(prev, tuple(notes), tuple(evidence))

    return load


class SwitchPanel:
    """The panel `warden serve` uses: `reload` swaps in a panel built from the re-read gatekeeper.yaml."""

    def __init__(self, inner: Panel) -> None:
        self.inner = inner

    def review(
        self, plan: Plan, rules: EffectiveRules, previous: Plan | None
    ) -> tuple[GatekeeperVerdict, ...]:
        return self.inner.review(plan, rules, previous)


def build_panel(config_dir: Path, engine: Engine) -> ReviewPanel:
    """gatekeeper.yaml and the secrets directory next to it (README 9, 12)."""
    return ReviewPanel(
        load_gatekeeper(config_dir / "gatekeeper.yaml"),
        Secrets(config_dir / "secrets"),
        context=previous_context(engine),
    )
