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

from sqlmodel import Session

from warden.agents import Registry
from warden.ca import CA
from warden.db import make_engine
from warden.dispatch.server import Dispatcher
from warden.errors import WardenError
from warden.keys import OnlineKey
from warden.plans.service import Config, PlanService
from warden.policy_dist import bundle as bundles
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
    def __init__(self, home: Path, load: Callable[[], Config]) -> None:
        self.home = home
        self._load = load
        self.engine = make_engine(home / "warden.db")
        self.config = self._fresh_config()
        approval = ApprovalKey.load(home / "keys/approval.key")
        online = OnlineKey.load(home / "keys/online.key")
        ca = CA.load_or_create(home / "ca")
        self.plans = PlanService(self.engine, config=lambda: self.config, approval_key=approval)
        self.registry = Registry(self.engine, ca, targets=lambda: self.config.targets)
        self.dispatcher = Dispatcher(
            engine=self.engine,
            plans=self.plans,
            registry=self.registry,
            ca=ca,
            online=online,
            config=lambda: self.config,
        )

    def _fresh_config(self) -> Config:
        cfg = self._load()
        with Session(self.engine) as s:
            version = bundles.published_version(s)
        return Config(policy=cfg.policy, targets=cfg.targets, settings=cfg.settings, policy_version=version)

    async def reload(self) -> dict[str, Any]:
        """After a publish: re-read config, push the latest bundles, apply lockdown, re-check plans."""
        self.config = self._fresh_config()
        pushed, killed = await self.dispatcher.policy_changed()
        invalidated = [p.id for p in self.plans.invalidate_against_current_policy()]
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

    async def run(self) -> None:
        port = await self.dispatcher.start()
        path = self.home / SOCKET
        with contextlib.suppress(FileNotFoundError):
            path.unlink()
        old_umask = os.umask(0o177)
        try:
            server = await asyncio.start_unix_server(self._admin, path=str(path))
        finally:
            os.umask(old_umask)
        os.chmod(path, 0o600)
        log.info("agent listener on :%s, admin socket %s, policy v%s", port, path, self.config.policy_version)
        expiry = asyncio.create_task(self._expire_loop())
        try:
            async with server:
                await server.serve_forever()
        finally:
            expiry.cancel()
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
