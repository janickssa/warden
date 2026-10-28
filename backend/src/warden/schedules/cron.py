"""Five-field cron in Europe/Copenhagen, the same in Warden and in every agent (DECISIONS M7-01).

Agents check that a scheduled run's slot matches the approved cron, so both sides must agree on every slot.
That's why this is a small evaluator of our own with shared vectors (`policy-fixtures/schedule_vectors.json`,
`agent/internal/cron`), not a scheduling library.

- Fields: minute hour day-of-month month day-of-week. `*`, numbers, `a-b`, lists with `,`, steps with `/`
  (`*/15`, `1-30/2`, `5/10` meaning `5-max/10`). Day of week 0–7, where 0 and 7 are Sunday. No names, no
  `?`, `L`, `W`, `#` or `@daily`: anything else is refused.
- When both day of month and day of week are restricted, a day matches if either does (classic cron).
- A slot is a whole minute whose wall time in Copenhagen matches. A wall time that doesn't exist (the hour
  skipped in spring) never fires; one that happens twice (autumn) fires only the first time.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from zoneinfo import ZoneInfo

from warden.errors import InputRefused

TZ_NAME = "Europe/Copenhagen"
TZ = ZoneInfo(TZ_NAME)
MAX_LEN = 100
SEARCH_DAYS = 5 * 366  # far enough for "29 February"

_FIELDS = (
    ("minute", 0, 59),
    ("hour", 0, 23),
    ("day of month", 1, 31),
    ("month", 1, 12),
    ("day of week", 0, 7),
)


class CronError(InputRefused):
    code = "bad_cron"


def _number(text: str, name: str, lo: int, hi: int) -> int:
    if not text.isascii() or not text.isdigit() or len(text) > 2:
        raise CronError(f"cron {name}: {text!r} isn't a number")
    n = int(text)
    if not lo <= n <= hi:
        raise CronError(f"cron {name}: {n} is outside {lo}–{hi}")
    return n


def _field(text: str, name: str, lo: int, hi: int) -> frozenset[int]:
    if not text:
        raise CronError(f"cron {name} is empty")
    out: set[int] = set()
    for item in text.split(","):
        base, slash, step_text = item.partition("/")
        step = 1
        if slash:
            step = _number(step_text, name, 1, hi)
        if base == "*":
            a, b = lo, hi
        elif "-" in base:
            left, _, right = base.partition("-")
            a, b = _number(left, name, lo, hi), _number(right, name, lo, hi)
            if a > b:
                raise CronError(f"cron {name}: range {a}-{b} runs backwards")
        else:
            a = _number(base, name, lo, hi)
            b = hi if slash else a
        out.update(range(a, b + 1, step))
    return frozenset(out)


@dataclass(frozen=True)
class Cron:
    expr: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]  # 0 = Sunday … 6 = Saturday
    days_any: bool
    weekdays_any: bool

    @classmethod
    def parse(cls, expr: str) -> Cron:
        if not isinstance(expr, str) or len(expr) > MAX_LEN or not expr.isascii():
            raise CronError("cron must be at most 100 plain characters")
        parts = expr.split(" ")
        if len(parts) != 5 or any(p == "" for p in parts):
            raise CronError("cron needs exactly five fields separated by single spaces")
        sets = [_field(p, *spec) for p, spec in zip(parts, _FIELDS, strict=True)]
        weekdays = frozenset(d % 7 for d in sets[4])
        return cls(
            expr=expr,
            minutes=sets[0],
            hours=sets[1],
            days=sets[2],
            months=sets[3],
            weekdays=weekdays,
            days_any=parts[2].startswith("*"),
            weekdays_any=parts[4].startswith("*"),
        )

    def day_matches(self, d: date) -> bool:
        if d.month not in self.months:
            return False
        dom = d.day in self.days
        dow = (d.isoweekday() % 7) in self.weekdays
        if self.days_any or self.weekdays_any:
            return dom and dow
        return dom or dow

    def is_slot(self, instant: datetime) -> bool:
        """Is this UTC instant one of the cron's slots (see the module docstring)?"""
        if instant.tzinfo is None:
            raise ValueError("instant must be timezone-aware")
        if instant.second or instant.microsecond:
            return False
        local = instant.astimezone(TZ)
        if (
            local.minute not in self.minutes
            or local.hour not in self.hours
            or not self.day_matches(local.date())
        ):
            return False
        earlier = (instant - timedelta(hours=1)).astimezone(TZ)
        return earlier.replace(tzinfo=None) != local.replace(tzinfo=None)  # the repeated autumn hour

    def _slots_on(self, d: date) -> list[datetime]:
        out = []
        for h in sorted(self.hours):
            for m in sorted(self.minutes):
                wall = datetime.combine(d, time(h, m), tzinfo=TZ)  # fold=0: the first occurrence
                instant = wall.astimezone(UTC)
                if instant.astimezone(TZ).replace(tzinfo=None) == wall.replace(tzinfo=None):
                    out.append(instant)  # skipped wall times don't round-trip
        return out

    def next_after(self, instant: datetime) -> datetime | None:
        """The first slot strictly after `instant`, or None within five years."""
        start = instant.astimezone(TZ).date()
        for i in range(SEARCH_DAYS):
            d = start + timedelta(days=i)
            if self.day_matches(d):
                for slot in self._slots_on(d):
                    if slot > instant:
                        return slot
        return None

    def latest_at_or_before(self, instant: datetime, *, not_before: datetime) -> datetime | None:
        """The newest slot in [not_before, instant], or None."""
        d = instant.astimezone(TZ).date()
        stop = not_before.astimezone(TZ).date()
        while d >= stop:
            if self.day_matches(d):
                for slot in reversed(self._slots_on(d)):
                    if not_before <= slot <= instant:
                        return slot
            d -= timedelta(days=1)
        return None


def describe(cron: Cron) -> str:
    """Plain English for the common shapes ("Every day at 03:00"); the raw expression otherwise."""
    simple_time = len(cron.minutes) == 1 and len(cron.hours) == 1
    every_day = cron.days_any and cron.weekdays_any and len(cron.months) == 12
    at = f"{min(cron.hours):02d}:{min(cron.minutes):02d}" if simple_time else ""
    if simple_time and every_day:
        return f"Every day at {at}"
    names = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    if simple_time and cron.days_any and len(cron.months) == 12 and len(cron.weekdays) == 1:
        return f"Every {names[min(cron.weekdays)]} at {at}"
    if simple_time and cron.weekdays_any and len(cron.months) == 12 and len(cron.days) == 1:
        return f"On day {min(cron.days)} of every month at {at}"
    return cron.expr
