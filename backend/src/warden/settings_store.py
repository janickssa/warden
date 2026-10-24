"""Settings changed from the dashboard (README 17.3 Settings), layered over `settings.yaml`.

Only the human-facing keys below can be changed this way. Listener addresses, the public URL and anything
that affects how agents connect stay in `settings.yaml`. `approvals.e2e` isn't here: it ships in signed
bundles and changes through the publish flow (D-12). Every change is audited with its before and after value.
Claude can neither read nor change settings: no MCP tool touches this module.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from pydantic import ValidationError
from sqlalchemy import Engine
from sqlmodel import Field, Session, SQLModel, select

from warden import audit
from warden.actors import HumanActor
from warden.config import Settings
from warden.errors import WardenError

EDITABLE = (
    "approvals.expiry_min",
    "approvals.passkey_medium",
    "approvals.chat",
    "approvals.chat_max_steps",
    "retention.audit_days",
    "retention.output_days",
    "retention.export",
    "retention.export_dir",
    "schedules.default_expiry_days",
    "ui.language",
    "notifications.approval_needed",
    "notifications.plan_failed",
    "notifications.agent_refused",
    "notifications.scheduled_done",
)


class SettingRefused(WardenError):
    code = "setting_refused"


class SettingRow(SQLModel, table=True):
    __tablename__ = "settings_overrides"

    key: str = Field(primary_key=True)
    value: str  # JSON
    updated_at: str
    updated_by: str


def _overrides(engine: Engine) -> dict[str, Any]:
    with Session(engine) as s:
        return {r.key: json.loads(r.value) for r in s.exec(select(SettingRow)) if r.key in EDITABLE}


def _get(data: dict[str, Any], key: str) -> Any:
    section, name = key.split(".")
    return data[section][name]


def _merge(base: Settings, overrides: dict[str, Any]) -> Settings:
    data = base.model_dump()
    for key, value in overrides.items():
        section, name = key.split(".")
        data[section][name] = value
    try:
        return Settings.model_validate(data)
    except ValidationError as exc:
        raise SettingRefused(f"invalid setting: {exc.errors()[0]['loc']} {exc.errors()[0]['msg']}") from exc


def effective(base: Settings, engine: Engine) -> Settings:
    """settings.yaml plus the dashboard's changes. A stored value that no longer validates is ignored."""
    merged = base
    for key, value in _overrides(engine).items():
        try:
            merged = _merge(merged, {key: value})
        except SettingRefused:
            continue
    return merged


def change(
    engine: Engine, base: Settings, changes: dict[str, Any], *, actor: HumanActor, now: datetime
) -> Settings:
    if not isinstance(actor, HumanActor):
        raise SettingRefused("only a human can change settings")
    unknown = sorted(set(changes) - set(EDITABLE))
    if unknown:
        raise SettingRefused(f"these can't be changed from the dashboard: {', '.join(unknown)}")
    before = effective(base, engine)
    after = _merge(before, changes)
    with Session(engine) as s, s.begin():
        for key, value in changes.items():
            old = _get(before.model_dump(), key)
            if old == _get(after.model_dump(), key):
                continue
            row = s.get(SettingRow, key) or SettingRow(key=key, value="null", updated_at="", updated_by="")
            row.value, row.updated_at, row.updated_by = json.dumps(value), now.isoformat(), actor.label
            s.add(row)
            audit.append(
                s,
                ts=now,
                actor=actor.label,
                action="setting_changed",
                subject=key,
                detail={"before": old, "after": value},
            )
    return after
