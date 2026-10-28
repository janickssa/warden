"""Dashboard API routes, one module per area."""

from __future__ import annotations

from fastapi import APIRouter

from warden.api.routes import agents, audit, auth, plans, policy, schedules, settings, status

ROUTERS: list[APIRouter] = [
    auth.router,
    status.router,
    plans.router,
    schedules.router,
    agents.router,
    policy.router,
    audit.router,
    settings.router,
]
