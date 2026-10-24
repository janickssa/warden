"""Plan data model (README section 5)."""

from __future__ import annotations

import re
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    """Every Warden model rejects unknown fields (fail closed) and is immutable."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class StepKind(StrEnum):
    SHELL = "shell"
    DOCKER = "docker"
    GIT = "git"
    HTTP_CHECK = "http_check"


class PlanStatus(StrEnum):
    PROPOSED = "proposed"
    REVIEWING = "reviewing"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    HELD = "held"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"
    INVALIDATED = "invalidated"


class Verdict(StrEnum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"


class Risk(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class StepStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


CAPTURE_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
TARGET_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
PLAN_ID = re.compile(r"^pln_[0-9A-HJKMNP-TV-Z]{26}$")

CaptureSource = Literal["stdout_trimmed"]
TargetName = Annotated[str, Field(pattern=TARGET_NAME.pattern)]


class Step(Strict):
    n: Annotated[int, Field(ge=1, le=1000)]
    kind: StepKind
    command: Annotated[str, Field(min_length=1, max_length=4096)]
    purpose: Annotated[str, Field(min_length=1, max_length=300)]
    cwd: Annotated[str, Field(min_length=1, max_length=1024)]
    timeout_s: Annotated[int, Field(ge=1)]
    expect_exit: Annotated[int, Field(ge=0, le=255)] = 0
    captures: dict[str, CaptureSource] = Field(default_factory=dict)
    edited: bool = False

    def template(self) -> dict[str, object]:
        """The hashed part of a step. `edited` is metadata about the step, not part of what runs."""
        return {
            "n": self.n,
            "kind": self.kind.value,
            "command": self.command,
            "purpose": self.purpose,
            "cwd": self.cwd,
            "timeout_s": self.timeout_s,
            "expect_exit": self.expect_exit,
            "captures": dict(sorted(self.captures.items())),
        }


class Violation(Strict):
    code: str
    message: str
    step: int | None = None
    group: str | None = None


class PolicyResult(Strict):
    ok: bool
    violations: tuple[Violation, ...] = ()
    policy_version: int = 0

    @staticmethod
    def passed(version: int = 0) -> PolicyResult:
        return PolicyResult(ok=True, violations=(), policy_version=version)


class StepVerdictNote(Strict):
    n: int
    matches_goal: bool
    note: str = ""


class GatekeeperVerdict(Strict):
    name: str
    model: str
    verdict: Verdict
    risk: Risk
    summary: str
    per_step: tuple[StepVerdictNote, ...] = ()
    unavailable: bool = False


class ApprovalSignature(Strict):
    by: str  # "warden-approval-key" or "passkey:<name>"
    key_id: str
    sig: str


class PasskeyAssertion(Strict):
    """A WebAuthn assertion over the approval message (README 10.0 end-to-end signing). Base64url parts."""

    credential_id: Annotated[str, Field(max_length=1024)]
    authenticator_data: Annotated[str, Field(max_length=4096)]
    client_data_json: Annotated[str, Field(max_length=4096)]
    signature: Annotated[str, Field(max_length=1024)]


class Approval(Strict):
    by: str
    at: datetime
    hash: str
    signature: ApprovalSignature
    passkey: PasskeyAssertion | None = None


class StepResult(Strict):
    n: int
    status: StepStatus
    exit_code: int | None = None
    reason: str | None = None  # e.g. "timeout", "policy_violation", "agent_disconnected", "killed"
    duration_s: float | None = Field(default=None, strict=False)
    output_truncated: bool = False


class StepEdit(Strict):
    n: int
    command: Annotated[str, Field(min_length=1, max_length=4096)]


class ProposeRequest(Strict):
    goal: Annotated[str, Field(min_length=1, max_length=500)]
    target: TargetName
    steps: tuple[Step, ...]
    revises: str | None = None


class Plan(Strict):
    id: str
    revises: str | None
    goal: str
    target: str
    requested_by: str
    steps: tuple[Step, ...]
    hash: str
    status: PlanStatus
    policy_result: PolicyResult
    gatekeepers: tuple[GatekeeperVerdict, ...] = ()
    final_verdict: Verdict = Verdict.ESCALATE
    approval: Approval | None = None
    created_at: datetime
    expires_at: datetime
    invalidated_by: int | None = None
    invalid_reason: str | None = None
    held_reason: str | None = None
    reject_reason: str | None = None
    step_results: tuple[StepResult, ...] = ()
    failed_at: int | None = None
    fail_reason: str | None = None
    version: int = 0  # optimistic-concurrency counter in the store

    def template(self) -> dict[str, object]:
        """Everything that is hashed and approved (DECISIONS D-07)."""
        return {
            "v": 1,
            "plan_id": self.id,
            "target": self.target,
            "goal": self.goal,
            "revises": self.revises,
            "steps": [s.template() for s in self.steps],
        }
