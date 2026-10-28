"""Cron (DECISIONS M7-01): parsing, Copenhagen slots across DST, and the vectors the agent also runs."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from warden.schedules.cron import Cron, CronError, describe

PATH = Path(__file__).resolve().parents[3] / "policy-fixtures" / "cron_vectors.json"


def utc(y: int, mo: int, d: int, h: int = 0, mi: int = 0, *, s: int = 0) -> datetime:
    return datetime(y, mo, d, h, mi, s, tzinfo=UTC)


@pytest.mark.parametrize(
    "expr",
    [
        "",
        "* * * *",
        "* * * * * *",
        "*  * * * *",
        " * * * * *",
        "60 * * * *",
        "* 24 * * *",
        "* * 0 * *",
        "* * 32 * *",
        "* * * 13 *",
        "* * * * 8",
        "5-1 * * * *",
        "*/0 * * * *",
        "MON * * * *",
        "0 3 * * MON",
        "@daily",
        "0 3 ? * *",
        "0 3 L * *",
        "0 3 * * 1#2",
        "0 3 * * ５",
        "1,,2 * * * *",
        "-1 * * * *",
        "+1 * * * *",
        "0x1 * * * *",
        "001 * * * *",
        "0\t3 * * *",
    ],
)
def test_refuses_everything_outside_the_subset(expr: str) -> None:
    with pytest.raises(CronError):
        Cron.parse(expr)


def test_fields() -> None:
    c = Cron.parse("*/15 1-3,22 1 1,6 0")
    assert c.minutes == {0, 15, 30, 45}
    assert c.hours == {1, 2, 3, 22}
    assert Cron.parse("5/20 * * * *").minutes == {5, 25, 45}
    assert Cron.parse("0 0 * * 7").weekdays == {0}  # 7 is Sunday too


def test_or_rule_when_both_days_restricted() -> None:
    c = Cron.parse("0 12 1 * 1")  # the 1st of the month, or any Monday
    assert c.is_slot(utc(2026, 11, 1, 11))  # Sunday 1 November, 12:00 CET
    assert c.is_slot(utc(2026, 11, 2, 11))  # Monday 2 November
    assert not c.is_slot(utc(2026, 11, 3, 11))
    d = Cron.parse("0 12 * * 1")
    assert not d.is_slot(utc(2026, 11, 1, 11))


def test_copenhagen_wall_time_and_dst() -> None:
    c = Cron.parse("30 2 * * *")
    # 29 March 2026: 02:00 → 03:00, so 02:30 doesn't exist and is skipped.
    assert c.next_after(utc(2026, 3, 28, 12)) == utc(2026, 3, 30, 0, 30)
    # 25 October 2026: 03:00 → 02:00, so 02:30 happens twice and fires once (the first, CEST).
    first = c.next_after(utc(2026, 10, 24, 12))
    assert first == utc(2026, 10, 25, 0, 30)
    assert not c.is_slot(utc(2026, 10, 25, 1, 30))
    assert c.next_after(first) == utc(2026, 10, 26, 1, 30)
    assert not c.is_slot(utc(2026, 10, 26, 1, 30, s=1))  # whole minutes only


def test_latest_at_or_before() -> None:
    c = Cron.parse("0 3 * * *")
    now = utc(2026, 10, 28, 2, 10)  # 03:10 CET
    assert c.latest_at_or_before(now, not_before=now - timedelta(minutes=15)) == utc(2026, 10, 28, 2)
    assert c.latest_at_or_before(now, not_before=now - timedelta(minutes=5)) is None


def test_describe() -> None:
    assert describe(Cron.parse("0 3 * * *")) == "Every day at 03:00"
    assert describe(Cron.parse("0 6 * * 1")) == "Every Monday at 06:00"
    assert describe(Cron.parse("15 4 1 * *")) == "On day 1 of every month at 04:15"
    assert describe(Cron.parse("*/10 * * * *")) == "*/10 * * * *"


EXPRS = [
    "0 3 * * *",
    "30 2 * * *",
    "*/15 1-3,22 1 1,6 0",
    "0 12 1 * 1",
    "5/20 9-17 * * 1-5",
    "0 0 29 2 *",
    "* * * * *",
]
INVALID = [
    "60 * * * *",
    "* * * * 8",
    "@daily",
    "0 3 * * MON",
    "5-1 * * * *",
    "*/0 * * * *",
    "* * * *",
    "001 * * * *",
]


def make() -> dict[str, object]:
    cases = []
    for expr in EXPRS:
        c = Cron.parse(expr)
        slots: list[datetime] = []
        t = utc(2026, 3, 27)
        while len(slots) < 12:
            nxt = c.next_after(t)
            assert nxt is not None
            slots.append(nxt)
            t = nxt
        autumn: list[datetime] = []
        t = utc(2026, 10, 24, 22)
        while (nxt := c.next_after(t)) is not None and nxt < utc(2026, 10, 25, 3) and len(autumn) < 12:
            autumn.append(nxt)
            t = nxt
        not_slots = [s + timedelta(seconds=1) for s in slots[:3]] + [utc(2026, 10, 25, 1, 30)]
        not_slots = [x for x in not_slots if not c.is_slot(x)]
        cases.append(
            {
                "expr": expr,
                "slots": [s.isoformat() for s in slots + autumn],
                "not_slots": [s.isoformat() for s in not_slots],
            }
        )
    return {"tz": "Europe/Copenhagen", "valid": cases, "invalid": INVALID}


def test_vectors() -> None:
    if os.environ.get("UPDATE_FIXTURES") == "1" or not PATH.exists():
        PATH.write_text(json.dumps(make(), indent=1, sort_keys=True) + "\n", encoding="utf-8")
    v = json.loads(PATH.read_text(encoding="utf-8"))
    assert v == json.loads(json.dumps(make()))
    for case in v["valid"]:
        c = Cron.parse(case["expr"])
        assert all(c.is_slot(datetime.fromisoformat(s)) for s in case["slots"])
        assert not any(c.is_slot(datetime.fromisoformat(s)) for s in case["not_slots"])
    for expr in v["invalid"]:
        with pytest.raises(CronError):
            Cron.parse(expr)
