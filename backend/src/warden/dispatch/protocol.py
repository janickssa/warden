"""Messages between Warden and agents (JSON text frames, `type` field). Unknown fields are refused."""

from __future__ import annotations

import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from warden.errors import WardenError

MAX_FRAME = 4 * 1024 * 1024


class ProtocolError(WardenError):
    code = "protocol_error"


class _Msg(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Refusal(_Msg):
    code: Annotated[str, Field(max_length=64)]
    message: Annotated[str, Field(max_length=2000)]


class Hello(_Msg):
    type: Literal["hello"]
    agent_version: Annotated[str, Field(max_length=32)]
    policy_version: int


class Heartbeat(_Msg):
    type: Literal["heartbeat"]
    agent_version: Annotated[str, Field(max_length=32)]
    policy_version: int
    disk_free_mb: int
    load1: Annotated[float, Field(ge=0)]


class PlanRefused(_Msg):
    type: Literal["refused"]
    plan_id: str
    code: Annotated[str, Field(max_length=64)]
    message: Annotated[str, Field(max_length=2000)]


class StepStarted(_Msg):
    type: Literal["step_started"]
    plan_id: str
    n: int


class Output(_Msg):
    type: Literal["output"]
    plan_id: str
    n: int
    stream: Literal["stdout", "stderr"]
    data: Annotated[str, Field(max_length=64 * 1024)]
    truncated: bool


class StepFinished(_Msg):
    type: Literal["step_finished"]
    plan_id: str
    n: int
    exit_code: int | None
    timed_out: bool
    killed: bool
    refused: Refusal | None
    duration_ms: int
    truncated: bool


class RunFinished(_Msg):
    type: Literal["run_finished"]
    plan_id: str


class BundleAck(_Msg):
    type: Literal["bundle_ack"]
    version: int
    sha256: str


class BundleRejected(_Msg):
    type: Literal["bundle_rejected"]
    version: int
    code: str
    message: str


class ReadOnlyResult(_Msg):
    type: Literal["read_only_result"]
    id: str
    exit_code: int | None
    output: Annotated[str, Field(max_length=MAX_FRAME)]
    truncated: bool
    refused: Refusal | None
    duration_ms: int


class Enroll(_Msg):
    type: Literal["enroll"]
    token: Annotated[str, Field(max_length=200)]
    public_key: Annotated[str, Field(max_length=100)]
    agent_version: Annotated[str, Field(max_length=32)]


AgentMessage = Annotated[
    Hello
    | Heartbeat
    | PlanRefused
    | StepStarted
    | Output
    | StepFinished
    | RunFinished
    | BundleAck
    | BundleRejected
    | ReadOnlyResult,
    Field(discriminator="type"),
]
_agent = TypeAdapter(AgentMessage)
_enroll = TypeAdapter(Enroll)


def parse_agent(frame: str | bytes) -> AgentMessage:
    if isinstance(frame, bytes) or len(frame) > MAX_FRAME:
        raise ProtocolError("frames must be JSON text up to 4 MB")
    try:
        return _agent.validate_json(frame)
    except ValidationError as exc:
        raise ProtocolError(f"bad message from agent: {exc.errors()[0]['msg']}") from exc


def parse_enroll(frame: str | bytes) -> Enroll:
    if isinstance(frame, bytes) or len(frame) > 64 * 1024:
        raise ProtocolError("bad enrollment frame")
    try:
        return _enroll.validate_json(frame)
    except ValidationError as exc:
        raise ProtocolError("bad enrollment message") from exc


def encode(type_: str, **body: object) -> str:
    return json.dumps({"type": type_, **body}, ensure_ascii=False, separators=(",", ":"))
