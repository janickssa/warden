"""Plan hashing (invariant 2, DECISIONS D-07)."""

from __future__ import annotations

import hmac
from typing import Protocol

from warden.plans.canonical import canonical_bytes, sha256_tagged


class HasTemplate(Protocol):
    def template(self) -> dict[str, object]: ...


def plan_hash(plan: HasTemplate) -> str:
    """SHA-256 over the canonical JSON of {v, plan_id, target, goal, revises, steps}."""
    return sha256_tagged(canonical_bytes(plan.template()))


def hash_matches(stored: str, recomputed: str) -> bool:
    return hmac.compare_digest(stored.encode(), recomputed.encode())
