"""Live events (README 17.1): the audit/output tail and `/ws` access rules."""

from __future__ import annotations

from pathlib import Path

import pytest
from apihelp import ORIGIN, Api, make_api
from factories import T0
from sqlalchemy import Engine
from sqlmodel import Session
from starlette.websockets import WebSocketDisconnect
from svc import World

from warden import audit
from warden.api.events import EventBus, Subscriber
from warden.dispatch import outputs
from warden.signing import ApprovalKey


@pytest.fixture
def api(engine: Engine, tmp_path: Path) -> Api:
    return make_api(World(engine=engine, key=ApprovalKey.generate(tmp_path / "k")), tmp_path)


def test_bus_tails_audit_and_filters_output(engine: Engine) -> None:
    bus = EventBus(engine)
    bus._start_positions()
    watching, other = Subscriber(), Subscriber()
    watching.plans.add("pln_A")
    bus.subscribers |= {watching, other}
    with Session(engine) as s, s.begin():
        audit.append(s, ts=T0, actor="cli:alice", action="approve", subject="pln_A", detail={"secret": "x"})
        outputs.append(s, plan_id="pln_A", n=1, seq=1, stream="stdout", data="hello\n")
        outputs.append(s, plan_id="pln_B", n=1, seq=1, stream="stdout", data="other\n")
    bus.publish(bus.poll_once())
    got = [watching.queue.get_nowait() for _ in range(watching.queue.qsize())]
    assert [e["type"] for e in got] == ["audit", "output"]
    assert got[0]["action"] == "approve"
    assert "detail" not in got[0]  # notices only; clients refetch through the API
    assert got[1]["data"] == "hello\n"
    assert [e["type"] for e in [other.queue.get_nowait() for _ in range(other.queue.qsize())]] == ["audit"]
    assert bus.poll_once() == []


def test_ws_needs_session_and_origin(api: Api) -> None:
    with (
        pytest.raises(WebSocketDisconnect) as exc,
        api.client.websocket_connect("wss://testserver/ws", headers={"origin": ORIGIN}) as ws,
    ):
        ws.receive_json()
    assert exc.value.code == 4401
    api.register()
    api.login()
    with (
        pytest.raises(WebSocketDisconnect),
        api.client.websocket_connect(
            "wss://testserver/ws", headers={"origin": "https://evil.example.com"}
        ) as ws,
    ):
        ws.receive_json()
    with api.client.websocket_connect("wss://testserver/ws", headers={"origin": ORIGIN}) as ws:
        assert ws.receive_json() == {"type": "hello"}
