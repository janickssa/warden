"""Dashboard API routes, one module per area."""

from __future__ import annotations

from fastapi import APIRouter

from warden.api.routes import auth

ROUTERS: list[APIRouter] = [auth.router]
