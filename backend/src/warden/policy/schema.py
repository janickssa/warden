"""policy.yaml and targets.yaml models (README sections 2, 7 and 7B).

Every model forbids unknown fields. Groups have no `allow` fields at all, so a group can't widen the
global policy by construction (section 16 rule 16); limits in a group must not exceed the global ones.
"""

from __future__ import annotations

import posixpath
import re
from enum import IntEnum
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from warden.text import is_ascii_printable

BINARY_NAME = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")
SUBCOMMAND = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
FLAG = re.compile(r"^--?[A-Za-z0-9][A-Za-z0-9-]*$")
HOST_PATTERN = re.compile(r"^(\*\.)?[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$")
NAME_GLOB = re.compile(r"^[A-Za-z0-9*?._-]{1,128}$")
GROUP_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
TARGET_NAME = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _abs_path(value: str) -> str:
    if not value.startswith("/") or not all(is_ascii_printable(c) for c in value):
        raise ValueError(f"{value!r} must be an absolute ASCII path")
    norm = posixpath.normpath(value)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    if norm != value.rstrip("/") and value != "/":
        raise ValueError(f"{value!r} must be written in normalised form ({norm!r})")
    return norm


# Agents use Go's RE2, which has no lookaround, backreferences, atomic groups or possessive quantifiers.
# Refusing them here keeps Warden and every agent agreeing on what a pattern means.
_NOT_RE2 = re.compile(r"\(\?(?:[=!]|<[=!]|>|P=|\(|[aiLmsux-]+[:)])|\\[1-9]|[*+?}][+]")


def _check_regex(pattern: str) -> str:
    try:
        re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"invalid regex {pattern!r}: {exc}") from exc
    if _NOT_RE2.search(pattern) or not all(0x20 <= ord(c) <= 0x7E for c in pattern):
        raise ValueError(
            f"regex {pattern!r} uses syntax agents can't run (lookaround, backreferences, inline flags, "
            "possessive quantifiers or non-ASCII)"
        )
    return pattern


AbsPath = Annotated[str, Field(min_length=1, max_length=1024)]


class BinaryRule(_Strict):
    subcommands: tuple[str, ...] | None = None
    flags_deny: tuple[str, ...] = ()

    @field_validator("subcommands")
    @classmethod
    def _subs(cls, v: tuple[str, ...] | None) -> tuple[str, ...] | None:
        for s in v or ():
            if not SUBCOMMAND.match(s):
                raise ValueError(f"invalid subcommand {s!r}")
        return v

    @field_validator("flags_deny")
    @classmethod
    def _flags(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for f in v:
            if not FLAG.match(f):
                raise ValueError(f"invalid flag {f!r}")
        return v


class Commands(_Strict):
    allow: dict[str, BinaryRule] = Field(default_factory=dict)
    deny_patterns: tuple[str, ...] = ()

    @field_validator("allow")
    @classmethod
    def _bins(cls, v: dict[str, BinaryRule]) -> dict[str, BinaryRule]:
        for name in v:
            if not BINARY_NAME.match(name):
                raise ValueError(f"invalid binary name {name!r}")
        return v

    @field_validator("deny_patterns")
    @classmethod
    def _patterns(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_check_regex(p) for p in v)


class Docker(_Strict):
    allowed_projects: tuple[str, ...] = ()
    denied_containers: tuple[str, ...] = ()

    @field_validator("allowed_projects", "denied_containers")
    @classmethod
    def _globs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for g in v:
            if not NAME_GLOB.match(g):
                raise ValueError(f"invalid name pattern {g!r}")
        return v


class Network(_Strict):
    git_hosts: tuple[str, ...] = ()
    http_check_hosts: tuple[str, ...] = ()

    @field_validator("git_hosts", "http_check_hosts")
    @classmethod
    def _hosts(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for h in v:
            if not HOST_PATTERN.match(h):
                raise ValueError(f"invalid host pattern {h!r}")
        return v


class Limits(_Strict):
    step_timeout_s: Annotated[int, Field(ge=1, le=86_400)] = 600
    plan_max_steps: Annotated[int, Field(ge=1, le=1000)] = 25
    output_cap_mb: Annotated[int, Field(ge=1, le=1024)] = 1


class ReadOnlyMode(IntEnum):
    """Ordered from most to least permissive; a higher value is stricter (README 7B)."""

    ALLOWED = 0
    RESTRICTED = 1
    OFF = 2

    @classmethod
    def parse(cls, name: str) -> ReadOnlyMode:
        return {"allowed": cls.ALLOWED, "restricted": cls.RESTRICTED, "off": cls.OFF}[name]

    @property
    def label(self) -> str:
        return self.name.lower()


class GroupReadOnly(_Strict):
    mode: Literal["allowed", "restricted", "off"] = "allowed"
    deny_paths: tuple[AbsPath, ...] = ()

    @field_validator("deny_paths")
    @classmethod
    def _paths(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_abs_path(p) for p in v)


class GroupCommands(_Strict):
    deny_patterns: tuple[str, ...] = ()

    @field_validator("deny_patterns")
    @classmethod
    def _patterns(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_check_regex(p) for p in v)


class GroupLimits(_Strict):
    plan_max_steps: Annotated[int, Field(ge=1, le=1000)] | None = None
    step_timeout_s: Annotated[int, Field(ge=1, le=86_400)] | None = None
    output_cap_mb: Annotated[int, Field(ge=1, le=1024)] | None = None


class GroupApprovals(_Strict):
    passkey: bool = False


class GroupGatekeepers(_Strict):
    unanimous: bool = False


class Group(_Strict):
    desc: str = ""
    members: tuple[str, ...] = ()
    read_only: GroupReadOnly = GroupReadOnly()
    commands: GroupCommands = GroupCommands()
    limits: GroupLimits = GroupLimits()
    approvals: GroupApprovals = GroupApprovals()
    gatekeepers: GroupGatekeepers = GroupGatekeepers()

    @field_validator("members")
    @classmethod
    def _members(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        for m in v:
            if not TARGET_NAME.match(m):
                raise ValueError(f"invalid member name {m!r}")
        if len(set(v)) != len(v):
            raise ValueError("duplicate group member")
        return v


class Policy(_Strict):
    deny_paths: tuple[AbsPath, ...] = ()
    commands: Commands = Commands()
    docker: Docker = Docker()
    network: Network = Network()
    limits: Limits = Limits()
    groups: dict[str, Group] = Field(default_factory=dict)

    @field_validator("deny_paths")
    @classmethod
    def _paths(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_abs_path(p) for p in v)

    @field_validator("groups")
    @classmethod
    def _group_names(cls, v: dict[str, Group]) -> dict[str, Group]:
        for name in v:
            if not GROUP_NAME.match(name):
                raise ValueError(f"invalid group name {name!r}")
        return v

    @model_validator(mode="after")
    def _groups_never_raise_limits(self) -> Self:
        for name, g in self.groups.items():
            for field in ("plan_max_steps", "step_timeout_s", "output_cap_mb"):
                gv = getattr(g.limits, field)
                if gv is not None and gv > getattr(self.limits, field):
                    raise ValueError(f"group {name}: limits.{field} must be <= the global value")
        return self


# Never valid as a workspace root (baseline protected trees, see policy/baseline.py).
_FORBIDDEN_ROOTS = (
    "/",
    "/etc",
    "/usr",
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/run",
    "/var/lib/docker",
    "/var/lib/warden-agent",
)


class Target(_Strict):
    name: str
    agent_id: str | None = None
    kind: str = "VM"
    workspace_roots: tuple[AbsPath, ...]
    docker_socket: AbsPath | None = None

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        if not TARGET_NAME.match(v):
            raise ValueError(f"invalid target name {v!r}")
        return v

    @field_validator("workspace_roots")
    @classmethod
    def _roots(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("a target needs at least one workspace root")
        out = []
        for p in v:
            norm = _abs_path(p)
            for bad in _FORBIDDEN_ROOTS:
                if norm == bad or (bad != "/" and norm.startswith(bad + "/")):
                    raise ValueError(f"workspace root {norm!r} is inside a protected tree ({bad})")
            out.append(norm)
        return tuple(out)


class Targets(_Strict):
    targets: tuple[Target, ...]

    @model_validator(mode="after")
    def _unique(self) -> Self:
        names = [t.name for t in self.targets]
        if len(set(names)) != len(names):
            raise ValueError("duplicate target name")
        return self

    def get(self, name: str) -> Target | None:
        return next((t for t in self.targets if t.name == name), None)
