from __future__ import annotations

import json
from datetime import timedelta

import pytest
from factories import T0
from sqlalchemy import Engine
from sqlalchemy.exc import DatabaseError
from sqlmodel import Session, text

from warden import audit


def _fill(engine: Engine, n: int = 5) -> None:
    with Session(engine) as s, s.begin():
        for i in range(n):
            audit.append(
                s,
                ts=T0 + timedelta(seconds=i),
                actor="claude-code",
                action="read_only",
                subject=f"dev · ls /srv/dev/{i}",
                detail={"argv": ["ls", f"/srv/dev/{i}"], "exit": 0},
            )


def test_chain_verifies(engine: Engine) -> None:
    _fill(engine)
    with Session(engine) as s:
        res = audit.verify(s)
    assert res.ok
    assert res.count == 5


def test_empty_log_verifies(engine: Engine) -> None:
    with Session(engine) as s:
        assert audit.verify(s).ok


def test_first_entry_links_to_genesis(engine: Engine) -> None:
    _fill(engine, 1)
    with Session(engine) as s:
        assert audit.entries(s)[0].prev == audit.GENESIS


@pytest.mark.parametrize(
    "stmt", ["UPDATE audit SET subject='x' WHERE seq=2", "DELETE FROM audit WHERE seq=5"]
)
def test_triggers_refuse_update_and_delete(engine: Engine, stmt: str) -> None:
    _fill(engine)
    with Session(engine) as s, pytest.raises(DatabaseError, match="append-only"), s.begin():
        s.exec(text(stmt))  # type: ignore[call-overload]


def _tamper(engine: Engine, *stmts: str) -> audit.VerifyResult:
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER audit_no_update")
        conn.exec_driver_sql("DROP TRIGGER audit_no_delete")
        for st in stmts:
            conn.exec_driver_sql(st)
    with Session(engine) as s:
        return audit.verify(s)


def test_edited_subject_is_detected(engine: Engine) -> None:
    _fill(engine)
    res = _tamper(engine, "UPDATE audit SET subject='dev · ls /srv/dev/hidden' WHERE seq=3")
    assert not res.ok
    assert res.bad_seq == 3


def test_edited_detail_is_detected(engine: Engine) -> None:
    _fill(engine)
    detail = json.dumps({"argv": ["ls", "/"], "exit": 0}, separators=(",", ":"), sort_keys=True)
    res = _tamper(engine, f"UPDATE audit SET detail='{detail}' WHERE seq=2")
    assert not res.ok
    assert res.bad_seq == 2


def test_deleted_row_is_detected(engine: Engine) -> None:
    _fill(engine)
    res = _tamper(engine, "DELETE FROM audit WHERE seq=3")
    assert not res.ok
    assert res.bad_seq == 4


def test_rehashed_row_still_breaks_next_link(engine: Engine) -> None:
    """Recomputing one row's hash after an edit still breaks the next link."""
    _fill(engine)
    with Session(engine) as s:
        row = audit.entries(s)[1]
        new_hash = audit._row_hash(
            seq=row.seq,
            ts=row.ts,
            actor=row.actor,
            action=row.action,
            subject="forged",
            detail=json.loads(row.detail),
            prev=row.prev,
        )
    res = _tamper(engine, f"UPDATE audit SET subject='forged', hash='{new_hash}' WHERE seq=2")
    assert not res.ok
    assert res.bad_seq == 3


def test_export_round_trips(engine: Engine) -> None:
    _fill(engine, 3)
    with Session(engine) as s:
        lines = list(audit.export_jsonl(s))
    assert len(lines) == 3
    first = json.loads(lines[0])
    assert first["detail"]["argv"] == ["ls", "/srv/dev/0"]
    assert first["hash"].startswith("sha256:")


def test_naive_timestamp_refused(engine: Engine) -> None:
    from warden.errors import AuditError

    with Session(engine) as s, pytest.raises(AuditError), s.begin():
        audit.append(s, ts=T0.replace(tzinfo=None), actor="x", action="y", subject="z")


def test_rollback_drops_entry(engine: Engine) -> None:
    def write_then_fail() -> None:
        with Session(engine) as s, s.begin():
            audit.append(s, ts=T0, actor="a", action="b", subject="c")
            raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        write_then_fail()
    with Session(engine) as s:
        assert audit.entries(s) == []
