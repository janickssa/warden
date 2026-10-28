"""Schedule grants (DECISIONS M7-02): what the human approves once, and what agents check on every run.

A plan approval binds one plan ID for minutes; a schedule needs a standing approval the agent can check
itself (invariant 10). The grant binds the template hash to the schedule, target, cron, time zone and an
approval window of at most 180 days. The approval key signs it under its own domain, and the human's
passkey signs the SHA-256 of the same message (always: a schedule is a standing approval). Each run sends
the template and the grant plus an unsigned slot and run ID; agents refuse a slot that isn't the cron's,
isn't current, falls outside the window or was already used (`agent/internal/approval/schedule.go`).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from warden.plans.canonical import canonical_bytes, sha256_tagged
from warden.plans.models import Step
from warden.schedules.cron import TZ_NAME
from warden.signing import SCHEDULE_DOMAIN

MAX_DAYS = 180
LATE = timedelta(minutes=15)  # a slot may start up to 15 min late (agent and scheduler agree)
EARLY = timedelta(minutes=1)  # clock skew allowance before the slot


def template(*, schedule_id: str, target: str, goal: str, steps: Sequence[Step]) -> dict[str, object]:
    """The hashed template: the source plan's steps, bound to the schedule instead of a plan ID."""
    return {
        "v": 1,
        "schedule_id": schedule_id,
        "target": target,
        "goal": goal,
        "steps": [s.template() for s in steps],
    }


def template_hash(tpl: dict[str, object]) -> str:
    return sha256_tagged(canonical_bytes(tpl))


def payload(
    *,
    schedule_id: str,
    template_hash: str,
    target: str,
    cron: str,
    approved_at: datetime,
    expires_at: datetime,
    by: str,
) -> dict[str, object]:
    return {
        "v": 1,
        "kind": "schedule",
        "schedule_id": schedule_id,
        "template_hash": template_hash,
        "target": target,
        "cron": cron,
        "tz": TZ_NAME,
        "approved_at": approved_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "by": by,
    }


def message(p: dict[str, object]) -> bytes:
    """What the approval key signs, and what the passkey signs the SHA-256 of (its WebAuthn challenge)."""
    return SCHEDULE_DOMAIN + canonical_bytes(p)


def claim(schedule_id: str, slot: datetime) -> str:
    """The one-time key agents record per run (`executed.log`)."""
    return f"{schedule_id}@{slot.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}"
