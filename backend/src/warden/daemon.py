"""`warden serve`: the agent listener plus a private admin socket for the CLI.

The admin socket lives in the Warden home (0700) with mode 0600, and every connection must come from the
same Unix user (SO_PEERCRED). It can execute an approved plan, kill a run, run a read-only command, show
agent status, drop a revoked agent, and re-read config after a human published policy with the CLI
(`reload`, which pushes bundles that are already signed and stored). It can't approve, publish or edit policy,
or change settings.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import pwd
import socket
import struct
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import uvicorn
from sqlmodel import Session

from warden.agents import Registry
from warden.api.app import Root, create_api
from warden.api.context import ApiContext
from warden.api.events import EventBus
from warden.ca import CA
from warden.db import make_engine
from warden.dispatch.server import Dispatcher
from warden.errors import WardenError
from warden.gatekeeper.panel import SwitchPanel, build_panel
from warden.keys import OnlineKey
from warden.mcp.http import build_app, identify_from_headers
from warden.mcp.server import WardenMcp, build_server
from warden.passkeys import Passkeys, RelyingParty
from warden.plans.service import Config, PlanService
from warden.policy_dist import bundle as bundles
from warden.schedules.scheduler import Scheduler
from warden.schedules.service import ScheduleService
from warden.signing import ApprovalKey

log = logging.getLogger("warden.daemon")
SOCKET = "admin.sock"
EXPIRE_EVERY_S = 30


def _peer_uid(writer: asyncio.StreamWriter) -> int | None:
    sock = writer.get_extra_info("socket")
    if sock is None:
        return None
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    _pid, uid, _gid = struct.unpack("3i", creds)
    return int(uid)


class Daemon:
    def __init__(self, home: Path, load: Callable[[], Config], *, config_dir: Path | None = None) -> None:
        self.home = home
        self._load = load
        self._config_dir = config_dir or home / "config"
        self.engine = make_engine(home / "warden.db")
        self.config = self._fresh_config()
        self.panel = SwitchPanel(build_panel(self._config_dir, self.engine))
        approval = ApprovalKey.load(home / "keys/approval.key")
        online = OnlineKey.load(home / "keys/online.key")
        ca = CA.load_or_create(home / "ca")
        self.plans = PlanService(
            self.engine, config=lambda: self.config, approval_key=approval, panel=self.panel
        )
        self.registry = Registry(self.engine, ca, targets=lambda: self.config.targets)
        self.dispatcher = Dispatcher(
            engine=self.engine,
            plans=self.plans,
            registry=self.registry,
            ca=ca,
            online=online,
            config=lambda: self.config,
        )
        self.schedules = ScheduleService(
            self.engine,
            self.plans,
            approval_key=approval,
            default_days=lambda: self.config.settings.schedules.default_expiry_days,
        )
        self.scheduler = Scheduler(self.schedules, self.dispatcher)
        self.bus = EventBus(self.engine)
        self.api_ctx = ApiContext(
            engine=self.engine,
            plans=self.plans,
            dispatcher=self.dispatcher,
            registry=self.registry,
            passkeys=Passkeys(self.engine, RelyingParty.from_url(self.config.settings.server.public_url)),
            config=lambda: self.config,
            online=online,
            approval=approval,
            config_dir=self._config_dir,
            reload=self.reload,
            schedules=self.schedules,
        )
        self.mcp = WardenMcp(
            engine=self.engine,
            plans=self.plans,
            dispatcher=self.dispatcher,
            config=lambda: self.config,
            identify=identify_from_headers(self.engine),
        )

    def _fresh_config(self) -> Config:
        cfg = self._load()
        with Session(self.engine) as s:
            version = bundles.published_version(s)
        return Config(
            policy=cfg.policy,
            targets=cfg.targets,
            settings=cfg.settings,
            policy_version=version,
            e2e=cfg.e2e,
        )

    async def reload(self) -> dict[str, Any]:
        """After a publish: re-read config, push the latest bundles, apply lockdown, re-check plans."""
        self.config = self._fresh_config()
        self.panel.inner = build_panel(self._config_dir, self.engine)
        pushed, killed = await self.dispatcher.policy_changed()
        invalidated = [p.id for p in self.plans.invalidate_against_current_policy()]
        invalidated += self.schedules.recheck_policy()
        log.info("policy v%s: pushed to %s", self.config.policy_version, ", ".join(pushed) or "nobody")
        return {
            "version": self.config.policy_version,
            "pushed": pushed,
            "killed": killed,
            "invalidated": invalidated,
        }

    async def _expire_loop(self) -> None:
        while True:
            await asyncio.sleep(EXPIRE_EVERY_S)
            try:
                self.plans.expire_due()
            except Exception:
                log.exception("expiry pass failed")

    async def _admin(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            uid = _peer_uid(writer)
            if uid != os.geteuid():
                writer.write(json.dumps({"ok": False, "error": "not allowed"}).encode() + b"\n")
                return
            user = pwd.getpwuid(uid).pw_name
            line = await asyncio.wait_for(reader.readline(), 10)
            req = json.loads(line)
            result = await self.handle(req, actor=f"cli:{user}")
            writer.write(json.dumps({"ok": True, "result": result}, default=str).encode() + b"\n")
        except WardenError as exc:
            writer.write(json.dumps({"ok": False, "code": exc.code, "error": exc.message}).encode() + b"\n")
        except Exception as exc:
            log.exception("admin request failed")
            writer.write(json.dumps({"ok": False, "error": type(exc).__name__}).encode() + b"\n")
        finally:
            with contextlib.suppress(Exception):
                await writer.drain()
                writer.close()

    async def handle(self, req: dict[str, Any], *, actor: str) -> Any:
        op = req.get("op")
        if op == "execute":
            plan = await self.dispatcher.execute(str(req["plan_id"]))
            return {
                "plan_id": plan.id,
                "status": plan.status.value,
                "failed_at": plan.failed_at,
                "fail_reason": plan.fail_reason,
                "held_reason": plan.held_reason,
            }
        if op == "kill":
            await self.dispatcher.kill(str(req["plan_id"]), actor)
            return {"killed": req["plan_id"]}
        if op == "read_only":
            res = await self.dispatcher.read_only(str(req["target"]), str(req["command"]), actor)
            return {
                "ok": res.ok,
                "exit_code": res.exit_code,
                "output": res.output,
                "truncated": res.truncated,
                "refused": res.refused,
            }
        if op == "status":
            return {
                name: {
                    "remote": s.remote,
                    "policy_version": s.policy_version,
                    "agent_version": s.agent_version,
                }
                for name, s in self.dispatcher.sessions.items()
            }
        if op == "reload":
            return await self.reload()
        if op == "drop":
            await self.dispatcher.revoke(str(req["name"]))
            return {"dropped": req["name"]}
        raise WardenError(f"unknown operation {op!r}", code="bad_request")

    def http_server(self) -> uvicorn.Server:
        """One port for `/mcp` (MCP bearer tokens), `/api` and `/ws` (passkey sessions)."""
        s = self.config.settings
        mcp = build_app(build_server(self.mcp), self.engine, s)
        api = create_api(self.api_ctx, self.bus)
        return uvicorn.Server(
            uvicorn.Config(
                Root(api, mcp),
                host=s.http.listen_host,
                port=s.http.listen_port,
                log_level="warning",
                proxy_headers=False,
                server_header=False,
                lifespan="on",
            )
        )

    async def run(self) -> None:
        port = await self.dispatcher.start()
        mcp_http = self.http_server()
        self.bus.start()
        mcp_task = asyncio.create_task(mcp_http.serve())
        path = self.home / SOCKET
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        old_umask = os.umask(0o177)
        try:
            server = await asyncio.start_unix_server(self._admin, path=str(path))
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
        log.info(
            "agent listener on :%s, /mcp /api /ws on %s:%s, admin socket %s, policy v%s",
            port,
            self.config.settings.http.listen_host,
            self.config.settings.http.listen_port,
            path,
            self.config.policy_version,
        )
        expiry = asyncio.create_task(self._expire_loop())
        scheduling = asyncio.create_task(self.scheduler.run())
        try:
            async with server:
                await server.serve_forever()
        finally:
            expiry.cancel()
            scheduling.cancel()
            mcp_http.should_exit = True
            await self.bus.stop()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(mcp_task, 10)
            await self.dispatcher.stop()


def admin_request(home: Path, payload: dict[str, Any], timeout: float = 3600) -> Any:
    """Send one request to a running `warden serve`."""
    path = home / SOCKET
    if not path.exists():
        raise WardenError("Warden isn't running (`warden serve`)", code="not_running")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(path))
        s.sendall(json.dumps(payload).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    reply = json.loads(data or b"{}")
    if not reply.get("ok"):
        raise WardenError(reply.get("error", "request failed"), code=reply.get("code", "refused"))
    return reply["result"]


def now() -> datetime:
    return datetime.now(UTC)
