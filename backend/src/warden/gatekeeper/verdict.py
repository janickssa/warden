"""Parsing a reviewer's answer (README 9). Anything but a clean, complete answer is `escalate`."""

from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from warden.gatekeeper.prompt import visible
from warden.plans.models import GatekeeperVerdict, Risk, StepVerdictNote, Verdict

MAX_RAW = 64 * 1024


class _Step(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    n: int
    matches_goal: bool
    note: Annotated[str, Field(max_length=2000)] = ""


class _Answer(BaseModel):
    model_config = ConfigDict(extra="ignore", strict=True)
    verdict: Literal["allow", "escalate", "deny"]
    risk: Literal["low", "medium", "high"]
    per_step: list[_Step]
    summary: Annotated[str, Field(min_length=1, max_length=2000)]


def _clean(text: str, limit: int) -> str:
    text = " ".join(visible(text).split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def unavailable(name: str, model: str, why: str, *, risk: Risk = Risk.HIGH) -> GatekeeperVerdict:
    """A reviewer that couldn't judge the plan. Risk stays high (passkey to approve): a plan could be
    crafted to make a model fail. Only "no gatekeepers configured", the owner's own choice, passes medium."""
    return GatekeeperVerdict(
        name=name,
        model=model,
        verdict=Verdict.ESCALATE,
        risk=risk,
        summary=_clean(f"Unavailable · counted as escalate ({why})", 300),
        unavailable=True,
    )


def parse(
    raw: str | dict[str, object], *, name: str, model: str, steps: tuple[int, ...]
) -> GatekeeperVerdict:
    """Validate one answer. Malformed, incomplete or inconsistent answers never come out as `allow`."""
    try:
        if isinstance(raw, str):
            if len(raw) > MAX_RAW:
                return unavailable(name, model, "answer too long")
            data = json.loads(raw.strip())
        else:
            data = raw
        ans = _Answer.model_validate(data)
    except (ValueError, ValidationError, TypeError):
        return unavailable(name, model, "answer wasn't the required JSON")
    numbers = [s.n for s in ans.per_step]
    if sorted(numbers) != sorted(steps) or len(set(numbers)) != len(numbers):
        return unavailable(name, model, "answer didn't cover every step exactly once")
    verdict, risk = Verdict(ans.verdict), Risk(ans.risk)
    why = ""
    if verdict == Verdict.ALLOW and (risk == Risk.HIGH or not all(s.matches_goal for s in ans.per_step)):
        verdict, why = Verdict.ESCALATE, " (raised to escalate: answer was inconsistent)"
    return GatekeeperVerdict(
        name=name,
        model=model,
        verdict=verdict,
        risk=risk,
        summary=_clean(ans.summary, 280) + why,
        per_step=tuple(
            StepVerdictNote(n=s.n, matches_goal=s.matches_goal, note=_clean(s.note, 300))
            for s in sorted(ans.per_step, key=lambda s: s.n)
        ),
    )
