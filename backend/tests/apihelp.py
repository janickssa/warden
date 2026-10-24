"""A dashboard API wired to a temp Warden, plus a signed-in client."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from policyhelp import FIXTURES
from softauth import SoftAuthenticator
from svc import World

from warden.actors import HumanActor
from warden.agents import Registry
from warden.api.app import create_api
from warden.api.context import ApiContext
from warden.api.events import EventBus
from warden.ca import CA
from warden.dispatch.server import Dispatcher
from warden.keys import OnlineKey
from warden.passkeys import Passkeys, RelyingParty
from warden.signing import ApprovalKey

ORIGIN = "http://localhost:3000"
H = {"origin": ORIGIN, "x-warden": "1"}
ALICE_CLI = HumanActor("cli", "alice")


@dataclass
class Api:
    world: World
    ctx: ApiContext
    client: TestClient
    auth: SoftAuthenticator
    reloads: list[int]

    def post(self, path: str, json: Any = None, **kw: Any) -> Any:
        return self.client.post(path, json=json, headers={**H, **kw.pop("headers", {})}, **kw)

    def get(self, path: str, **kw: Any) -> Any:
        return self.client.get(path, **kw)

    def register(self, name: str = "MacBook", auth: SoftAuthenticator | None = None) -> SoftAuthenticator:
        auth = auth or self.auth
        token = self.ctx.passkeys.create_enrollment(name, actor=ALICE_CLI, now=self.ctx.now())
        r = self.post("/api/passkeys/register/options", {"token": token})
        assert r.status_code == 200, r.text
        o = r.json()
        r = self.post(
            "/api/passkeys/register",
            {"challenge_id": o["challenge_id"], "credential": auth.create(o["options"])},
        )
        assert r.status_code == 200, r.text
        return auth

    def login(self, auth: SoftAuthenticator | None = None) -> Any:
        auth = auth or self.auth
        o = self.post("/api/auth/options").json()
        return self.post(
            "/api/auth/login", {"challenge_id": o["challenge_id"], "credential": auth.get(o["options"])}
        )

    def confirm(self, purpose: str, subject: str = "") -> dict[str, Any]:
        o = self.post("/api/confirm/options", {"purpose": purpose, "subject": subject}).json()
        return {"challenge_id": o["challenge_id"], "credential": self.auth.get(o["options"])}


def make_api(world: World, tmp: Path) -> Api:
    online = OnlineKey.generate(tmp / "online.key")
    ca = CA.load_or_create(tmp / "ca")
    registry = Registry(world.engine, ca, targets=lambda: world.config().targets)
    dispatcher = Dispatcher(
        engine=world.engine, plans=world.svc, registry=registry, ca=ca, online=online, config=world.config
    )
    cfg_dir = tmp / "config"
    cfg_dir.mkdir(exist_ok=True)
    for f in ("policy.yaml", "targets.yaml"):
        (cfg_dir / f).write_text((FIXTURES / f).read_text())
    reloads: list[int] = []

    async def reload() -> dict[str, Any]:
        reloads.append(1)
        return {"pushed": [], "killed": [], "invalidated": []}

    ctx = ApiContext(
        engine=world.engine,
        plans=world.svc,
        dispatcher=dispatcher,
        registry=registry,
        passkeys=Passkeys(world.engine, RelyingParty.from_url(ORIGIN)),
        config=world.config,
        online=online,
        approval=world.key if isinstance(world.key, ApprovalKey) else ApprovalKey.generate(tmp / "a.key"),
        config_dir=cfg_dir,
        reload=reload,
        clock=world.clock,
    )
    app = create_api(ctx, EventBus(world.engine))
    client = TestClient(app, base_url="https://testserver")
    return Api(world, ctx, client, SoftAuthenticator(ORIGIN, "localhost"), reloads)
