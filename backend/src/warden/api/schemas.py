"""Response and request shapes of the dashboard API (`openapi-typescript` → web/src/api-types.ts)."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Problem(BaseModel):
    code: str
    message: str


class Violation(BaseModel):
    code: str
    message: str
    step: int | None = None
    group: str | None = None


class Reviewer(BaseModel):
    name: str
    model: str
    verdict: Literal["allow", "escalate", "deny"]
    risk: Literal["low", "medium", "high"]
    summary: str
    unavailable: bool
    notes: dict[int, str] = {}  # step number → note, for steps a reviewer flagged


class StepView(BaseModel):
    n: int
    kind: str
    command: str
    purpose: str
    cwd: str
    timeout_s: int
    expect_exit: int
    edited: bool
    status: str | None = None
    exit_code: int | None = None
    reason: str | None = None
    duration_s: float | None = None
    output_truncated: bool = False


class ApprovalView(BaseModel):
    by: str
    at: str
    hash: str
    key_id: str
    passkey: str | None = None  # credential ID when a passkey signed it


class AgentState(BaseModel):
    state: Literal["current", "behind", "offline", "revoked", "missing", "lockdown"]
    warning: str | None = None
    policy_version: int | None = None
    latest_version: int = 0


class DiffRowView(BaseModel):
    op: Literal["same", "added", "removed"]
    old_n: int | None
    new_n: int | None
    old_command: str | None
    new_command: str | None
    old_status: str | None = None


class Evidence(BaseModel):
    audit_id: int
    command: str
    exit_code: int | None
    output: str


class DiagnosisView(BaseModel):
    id: str
    by: str
    note: str
    created_at: str
    evidence: list[Evidence]


class PlanSummary(BaseModel):
    id: str
    status: str
    goal: str
    target: str
    revises: str | None
    requested_by: str
    steps: int
    created_at: str
    expires_at: str
    risk: Literal["low", "medium", "high"] | None
    final_verdict: Literal["allow", "escalate", "deny"]
    gatekeeper_unavailable: bool
    held_reason: str | None
    failed_at: int | None
    fail_reason: str | None
    invalidated_by: int | None
    changed_steps: int | None = None
    decided_at: str | None = None
    agent: AgentState | None = None


class PlanList(BaseModel):
    plans: list[PlanSummary]
    counts: dict[str, int]


class PreviousPlan(BaseModel):
    id: str
    status: str
    failed_at: int | None
    fail_reason: str | None
    error_output: str | None


class PlanDetail(PlanSummary):
    hash: str
    policy_ok: bool
    policy_version: int
    violations: list[Violation]
    reviewers: list[Reviewer]
    reviewers_disagree: bool
    step_list: list[StepView]
    approval: ApprovalView | None
    invalid_reason: str | None
    reject_reason: str | None
    previous: PreviousPlan | None
    diff: list[DiffRowView]
    diagnoses: list[DiagnosisView]
    revisions: list[str]
    passkey_reasons: list[str]
    passkeys_registered: int
    e2e: bool
    human_note: str | None = None


class OutputChunk(BaseModel):
    n: int
    seq: int
    stream: str
    data: str


class OutputView(BaseModel):
    plan_id: str
    chunks: list[OutputChunk]
    cap_bytes: int


class ApproveOptions(BaseModel):
    needs_passkey: bool
    reasons: list[str]
    challenge_id: str | None = None
    options: dict[str, Any] | None = None


class ApproveIn(In):
    hash: str = Field(max_length=80)
    challenge_id: str | None = Field(default=None, max_length=64)
    credential: dict[str, Any] | None = None


class EditIn(In):
    n: int
    command: str = Field(min_length=1, max_length=4096)


class EditsIn(In):
    edits: list[EditIn] = Field(min_length=1, max_length=100)


class RejectIn(In):
    reason: str | None = Field(default=None, max_length=500)


class Ok(BaseModel):
    ok: bool = True
    message: str | None = None


class AgentView(BaseModel):
    name: str
    id: str | None
    kind: str
    status: Literal["online", "behind", "offline", "revoked", "not_enrolled"]
    online: bool
    remote_addr: str | None
    last_seen: str | None
    agent_version: str | None
    policy_version: int | None
    latest_version: int
    workspace_roots: list[str]
    groups: list[str]
    enrolled_at: str | None
    revoked_at: str | None
    fingerprint: str | None


class AgentList(BaseModel):
    agents: list[AgentView]
    latest_version: int


class AddAgentIn(In):
    name: str = Field(max_length=63)


class AgentToken(BaseModel):
    name: str
    token: str
    command: str
    expires_at: str


class EnrollmentView(BaseModel):
    name: str
    status: str
    fingerprint: str | None
    source_ip: str | None
    agent_version: str | None
    expires_at: str


class ConfirmAgentIn(In):
    fingerprint: str = Field(max_length=200)


class TargetChangeView(BaseModel):
    target: str
    cls: str
    changes: list[dict[str, str]]


class PolicyPreview(BaseModel):
    preview_id: str | None
    ok: bool
    errors: list[str]
    cls: Literal["none", "tighten", "loosen", "initial"] | None
    targets: list[TargetChangeView]
    gate_failures: list[str]
    gate_cases: int
    yaml_diff: list[str]
    note: str | None = None


class PolicyIn(In):
    yaml: str = Field(max_length=200_000)


class PublishIn(In):
    preview_id: str = Field(max_length=64)
    challenge_id: str = Field(max_length=64)
    credential: dict[str, Any]


class PublishResultView(BaseModel):
    outcome: Literal["published", "pending", "unchanged"]
    version: int
    loosens: list[str]
    pushed: list[str] = []
    invalidated: list[str] = []


class RolloutRow(BaseModel):
    agent: str
    version: int | None
    online: bool
    current: bool


class PendingView(BaseModel):
    version: int
    reason: str
    created_at: str
    created_by: str
    targets: list[TargetChangeView]


class HistoryRow(BaseModel):
    version: int
    at: str
    by: str
    cls: str
    signed_with: str
    targets: int


class PolicyView(BaseModel):
    yaml: str
    version: int
    lockdown: bool
    e2e: bool
    rollout: list[RolloutRow]
    pending: PendingView | None
    history: list[HistoryRow]
    compiled: dict[str, Any]
    unpublished_changes: bool
    writable: bool


class SignatureIn(In):
    content: str = Field(max_length=200_000)


class GroupMember(BaseModel):
    name: str
    kind: str
    known: bool


class GroupView(BaseModel):
    name: str
    desc: str
    members: list[GroupMember]
    tags: list[str]
    rules: dict[str, Any]


class GroupEditIn(In):
    name: str = Field(max_length=64)
    group: dict[str, Any] | None  # None deletes the group
    rename_from: str | None = Field(default=None, max_length=64)


class AuditEntry(BaseModel):
    seq: int
    ts: str
    actor: str
    action: str
    subject: str
    detail: dict[str, Any]


class AuditPage(BaseModel):
    entries: list[AuditEntry]
    chain_ok: bool
    chain_count: int
    chain_bad_seq: int | None


class FeedItem(BaseModel):
    seq: int
    ts: str
    type: str
    actor: str
    action: str
    subject: str
    target: str | None
    plan_id: str | None


class Feed(BaseModel):
    items: list[FeedItem]


class KeyView(BaseModel):
    name: str
    key_id: str
    public: str
    role: str | None = None


class PasskeyView(BaseModel):
    credential_id: str
    name: str
    alg: int
    created_at: str
    last_used_at: str | None


class SessionView(BaseModel):
    id: str
    name: str
    created_at: str
    expires_at: str
    last_seen_at: str
    ip: str
    user_agent: str
    current: bool


class SettingsView(BaseModel):
    values: dict[str, Any]
    editable: list[str]
    gatekeepers: dict[str, Any]
    limits: dict[str, Any]
    keys: list[KeyView]
    ca: dict[str, Any]
    e2e: bool
    time: dict[str, str]


class ConfirmIn(In):
    challenge_id: str = Field(max_length=64)
    credential: dict[str, Any]


class SettingsIn(In):
    changes: dict[str, Any]


class GatekeeperStatus(BaseModel):
    name: str
    model: str
    state: Literal["up", "unavailable", "unknown"]
    why: str | None = None


class StatusView(BaseModel):
    me: str
    policy_version: int
    lockdown: bool
    e2e: bool
    agents: list[AgentView]
    gatekeepers: list[GatekeeperStatus]
    running: list[str]
    awaiting: int
    pending_publish: int | None
    language: str
    passkeys: int
