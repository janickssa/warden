"""Everything the API handlers need, built once by `warden serve` (or a test)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine

from warden.agents import Registry
from warden.dispatch.server import Dispatcher
from warden.keys import OnlineKey
from warden.passkeys import Passkeys
from warden.plans.service import Config, PlanService
from warden.signing import ApprovalKey


@dataclass
class ApiContext:
    engine: Engine
    plans: PlanService
    dispatcher: Dispatcher
    registry: Registry
    passkeys: Passkeys
    config: Callable[[], Config]
    online: OnlineKey
    approval: ApprovalKey
    config_dir: Path
    reload: Callable[[], Awaitable[dict[str, Any]]]
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(UTC))

    def now(self) -> datetime:
        return self.clock()
