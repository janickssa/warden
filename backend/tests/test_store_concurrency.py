"""Two channels deciding the same plan at once: exactly one wins (README 17.6 'decided elsewhere')."""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlmodel import Session
from svc import World, make_world

from warden.actors import HumanActor
from warden.errors import DecidedElsewhere
from warden.plans import store
from warden.plans.models import PlanStatus


@pytest.fixture
def w(engine: Engine, tmp_path: Path) -> World:
    return make_world(engine, tmp_path)


def test_stale_version_loses(w: World) -> None:
    p = w.svc.get(w.propose("npm ci").id)
    with Session(w.engine) as s, s.begin():
        store.save(s, p, p.model_copy(update={"status": PlanStatus.REJECTED}))
    with Session(w.engine) as s, s.begin(), pytest.raises(DecidedElsewhere):
        store.save(s, p, p.model_copy(update={"status": PlanStatus.APPROVED}))


def test_parallel_approve_and_reject(w: World) -> None:
    for _ in range(10):
        p = w.propose("npm ci")
        results: list[str] = []
        barrier = threading.Barrier(2)

        def approve(
            plan_id: str = p.id,
            plan_hash: str = p.hash,
            barrier: threading.Barrier = barrier,
            results: list[str] = results,
        ) -> None:
            barrier.wait()
            try:
                w.svc.approve(plan_id, plan_hash[7:19], HumanActor("iphone", "alice"))
                results.append("approved")
            except DecidedElsewhere:
                results.append("lost")

        def reject(
            plan_id: str = p.id, barrier: threading.Barrier = barrier, results: list[str] = results
        ) -> None:
            barrier.wait()
            try:
                w.svc.reject(plan_id, HumanActor("dashboard", "alice"))
                results.append("rejected")
            except DecidedElsewhere:
                results.append("lost")

        threads = [threading.Thread(target=approve), threading.Thread(target=reject)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sorted(results) in (["approved", "lost"], ["lost", "rejected"])
        assert w.svc.get(p.id).status in (PlanStatus.APPROVED, PlanStatus.REJECTED)
