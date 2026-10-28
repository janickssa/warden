"""The scheduler loop (README 11): fire each active schedule's due slot once, through the normal dispatcher.

Every 20 s: expire what's past its window; for each due slot (at most 15 min old), record a miss if the run
can't start now (lockdown, agent offline or behind; a slot never waits), invalidate if the current policy
denies the steps, else create the run plan and dispatch it. The agent checks the grant and the slot itself.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import UTC, datetime

from warden.dispatch.server import Dispatcher
from warden.errors import WardenError
from warden.plans.models import Plan
from warden.schedules.service import Schedule, ScheduleService

log = logging.getLogger("warden.scheduler")
TICK_S = 20


class Scheduler:
    def __init__(
        self,
        schedules: ScheduleService,
        dispatcher: Dispatcher,
        *,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.schedules = schedules
        self.dispatcher = dispatcher
        self._clock = clock
        self._tasks: set[asyncio.Task[None]] = set()

    async def run(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:
                log.exception("scheduler pass failed")
            await asyncio.sleep(TICK_S)

    async def tick(self) -> list[str]:
        """One pass. Returns the run plan IDs it started (tests drive this with a fake clock)."""
        started = []
        for sch, slot in self.schedules.due(self._clock()):
            run_id = await self.fire(sch, slot)
            if run_id:
                started.append(run_id)
        return started

    async def fire(self, sch: Schedule, slot: datetime) -> str | None:
        why = self.dispatcher.cannot_run(sch.row.target)
        if why is not None:
            self.schedules.missed(sch, slot, why)
            return None
        try:
            run = self.schedules.create_run(sch, slot)
        except WardenError as exc:
            log.warning("schedule %s not run: %s", sch.id, exc.message)
            self.schedules.missed(sch, slot, exc.message)
            if exc.code == "policy_violation":
                self.schedules.recheck_policy()
            return None
        self.schedules.mark_fired(sch, slot, run.id)
        task = asyncio.get_running_loop().create_task(self._execute(run))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return run.id

    async def _execute(self, run: Plan) -> None:
        try:
            done = await self.dispatcher.execute(run.id)
        except WardenError as exc:
            log.warning("scheduled run %s refused: %s", run.id, exc.message)
            self.schedules.run_missed(run, exc.message)
            return
        if done.status.value == "expired":
            self.schedules.run_missed(done, done.held_reason or "missed")
            return
        self.schedules.record_result(done)

    async def wait(self) -> None:
        """Let started runs finish (tests)."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)
