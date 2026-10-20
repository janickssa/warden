"""Who is acting. Approve, reject and edit only accept a HumanActor (invariant 3).

MCP code paths only ever construct ClaudeActor, and the plan service checks the type at runtime as well as
in the signatures, so a mistake in wiring can't turn Claude into an approver.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

HumanChannel = Literal["cli", "dashboard", "iphone", "chat"]

_ID = re.compile(r"^[A-Za-z0-9._@:-]{1,64}$")


@dataclass(frozen=True, slots=True)
class HumanActor:
    channel: HumanChannel
    id: str

    def __post_init__(self) -> None:
        if not _ID.match(self.id):
            raise ValueError("invalid human actor id")

    @property
    def label(self) -> str:
        return f"{self.channel}:{self.id}"


@dataclass(frozen=True, slots=True)
class ClaudeActor:
    client: str  # e.g. "claude-code", "claude-desktop"

    def __post_init__(self) -> None:
        if not _ID.match(self.client):
            raise ValueError("invalid client name")

    @property
    def label(self) -> str:
        return self.client


@dataclass(frozen=True, slots=True)
class SystemActor:
    name: Literal["warden", "scheduler"] = "warden"

    @property
    def label(self) -> str:
        return self.name


Actor = HumanActor | ClaudeActor | SystemActor
