"""User-facing time formats (README 17.2): 24-hour, Europe/Copenhagen, dates as 20.10.2026."""

from __future__ import annotations

from datetime import datetime
from zoneinfo import ZoneInfo

CPH = ZoneInfo("Europe/Copenhagen")


def fmt_datetime(dt: datetime) -> str:
    return dt.astimezone(CPH).strftime("%d.%m.%Y %H:%M")


def fmt_time(dt: datetime) -> str:
    return dt.astimezone(CPH).strftime("%H:%M")


def fmt_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{round(seconds)} s"
    return f"{int(seconds // 60)} min {round(seconds % 60)} s"
