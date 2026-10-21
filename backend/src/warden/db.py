"""SQLite (WAL) engine. Every transaction starts with BEGIN IMMEDIATE, so writers are serialised."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, event
from sqlmodel import SQLModel, create_engine

import warden.agents
import warden.audit
import warden.dispatch.outputs
import warden.plans.store
import warden.policy_dist.bundle
import warden.policy_dist.offline_keys
import warden.policy_dist.publish  # noqa: F401  (registers tables)

_TRIGGERS = (
    "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit "
    "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
    "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit "
    "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
)


def make_engine(path: Path | str) -> Engine:
    engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _on_connect(dbapi_conn: sqlite3.Connection, _record: Any) -> None:
        # Let SQLAlchemy's begin event (below) control transactions explicitly.
        dbapi_conn.isolation_level = None
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=FULL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA busy_timeout=5000")
        cur.close()

    @event.listens_for(engine, "begin")
    def _on_begin(conn: Any) -> None:
        conn.exec_driver_sql("BEGIN IMMEDIATE")

    SQLModel.metadata.create_all(engine)
    with engine.begin() as conn:
        for ddl in _TRIGGERS:
            conn.exec_driver_sql(ddl)
    return engine
