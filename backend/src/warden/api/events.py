"""Live events for `/ws` (README 17.1 "live by default").

One task tails the append-only audit log and step output. Anything any channel does (CLI, iPhone, another
browser, an agent) shows up for every connected dashboard within a second. Clients get small notices and
refetch; plan output is only sent to clients that asked for that plan.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import Engine
from sqlmodel import Session, col, select

from warden.audit import AuditRow
from warden.dispatch.outputs import StepOutputRow

log = logging.getLogger("warden.events")
POLL_S = 0.3
MAX_QUEUE = 1000


@dataclass(eq=False)
class Subscriber:
    queue: asyncio.Queue[dict[str, Any]] = field(default_factory=lambda: asyncio.Queue(MAX_QUEUE))
    plans: set[str] = field(default_factory=set)


class EventBus:
    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.subscribers: set[Subscriber] = set()
        self._audit_seq = 0
        self._output_id = 0
        self._task: asyncio.Task[None] | None = None

    def _start_positions(self) -> None:
        with Session(self.engine) as s:
            a = s.exec(select(AuditRow.seq).order_by(col(AuditRow.seq).desc()).limit(1)).first()
            o = s.exec(select(StepOutputRow.id).order_by(col(StepOutputRow.id).desc()).limit(1)).first()
        self._audit_seq, self._output_id = a or 0, o or 0

    def start(self) -> None:
        self._start_positions()
        self._task = asyncio.get_running_loop().create_task(self._run())

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    def poll_once(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        with Session(self.engine) as s:
            for row in s.exec(
                select(AuditRow)
                .where(col(AuditRow.seq) > self._audit_seq)
                .order_by(col(AuditRow.seq))
                .limit(500)
            ):
                self._audit_seq = row.seq
                events.append(
                    {
                        "type": "audit",
                        "seq": row.seq,
                        "ts": row.ts,
                        "actor": row.actor,
                        "action": row.action,
                        "subject": row.subject,
                    }
                )
            for o in s.exec(
                select(StepOutputRow)
                .where(col(StepOutputRow.id) > self._output_id)
                .order_by(col(StepOutputRow.id))
                .limit(2000)
            ):
                self._output_id = o.id or self._output_id
                events.append(
                    {
                        "type": "output",
                        "plan_id": o.plan_id,
                        "n": o.n,
                        "seq": o.seq,
                        "stream": o.stream,
                        "data": o.data,
                    }
                )
        return events

    def publish(self, events: list[dict[str, Any]]) -> None:
        for sub in list(self.subscribers):
            for e in events:
                if e["type"] == "output" and e["plan_id"] not in sub.plans:
                    continue
                try:
                    sub.queue.put_nowait(e)
                except asyncio.QueueFull:
                    sub.queue = asyncio.Queue(MAX_QUEUE)  # a stuck client resyncs by refetching
                    sub.queue.put_nowait({"type": "resync"})
                    break

    async def _run(self) -> None:
        while True:
            try:
                events = self.poll_once()
                if events:
                    self.publish(events)
            except Exception:
                log.exception("event poll failed")
            await asyncio.sleep(POLL_S)
