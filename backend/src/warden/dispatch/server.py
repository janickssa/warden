"""Agent listener and dispatcher (README 3, 7A).

Agents connect out to wss://<warden>:8443 with mutual TLS. `/enroll` is the only path that accepts a
connection without a client certificate; `/agent` requires a certificate issued by Warden's CA whose serial
belongs to an active agent. Plans are sent only to an agent that is connected and on the latest bundle;
otherwise they wait as `held` and start when the agent becomes current. A dropped connection fails the
running plan with `agent_disconnected` at once. Bundles are pushed when an agent connects, when a heartbeat
shows it behind, and right after a publish (`policy_changed`). During lockdown nothing is dispatched.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from sqlalchemy import Engine
from sqlmodel import Session
from websockets.asyncio.server import Server, ServerConnection, serve
from websockets.exceptions import ConnectionClosed

from warden import audit
from warden.agents import AgentRow, EnrollmentRefused, Registry
from warden.ca import CA
from warden.dispatch import outputs, protocol
from warden.dispatch.protocol import ProtocolError
from warden.errors import DispatchRefused, WardenError
from warden.keys import OnlineKey
from warden.plans.models import Plan, PlanStatus
from warden.plans.runs import StepOutcome
from warden.plans.service import Config, PlanService
from warden.policy.effective import effective_rules
from warden.policy.readonly import check_read_only
from warden.policy_dist import bundle as bundles
from warden.policy_dist import offline_keys
from warden.policy_dist.publish import lockdown_state

log = logging.getLogger("warden.dispatch")

ENROLL_POLL_S = 0.5
READ_ONLY_TIMEOUT_S = 40


@dataclass
class ActiveRun:
    plan: Plan
    agent: str
    outcomes: list[StepOutcome] = field(default_factory=list)
    current: int | None = None
    seq: int = 0
    sent_bytes: dict[int, int] = field(default_factory=dict)
    done: asyncio.Future[Plan] = field(default_factory=lambda: asyncio.get_running_loop().create_future())


@dataclass
class AgentSession:
    agent: AgentRow
    ws: ServerConnection
    remote: str
    policy_version: int = 0
    agent_version: str = ""
    offered_version: int = 0  # latest bundle version sent on this connection, so heartbeats don't resend it
    pending_ro: dict[str, asyncio.Future[protocol.ReadOnlyResult]] = field(default_factory=dict)


@dataclass(frozen=True)
class ReadOnlyOutcome:
    ok: bool
    exit_code: int | None
    output: str
    truncated: bool
    refused: list[dict[str, Any]]
    audit_id: int = 0


class Dispatcher:
    def __init__(
        self,
        *,
        engine: Engine,
        plans: PlanService,
        registry: Registry,
        ca: CA,
        online: OnlineKey,
        config: Callable[[], Config],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._engine = engine
        self._plans = plans
        self._registry = registry
        self._ca = ca
        self._online = online
        self._config = config
        self._clock = clock
        self.sessions: dict[str, AgentSession] = {}
        self.runs: dict[str, ActiveRun] = {}
        self._server: Server | None = None
        self._tasks: set[asyncio.Task[Any]] = set()

    # --- lifecycle -------------------------------------------------------------------------------------

    def ssl_context(self) -> ssl.SSLContext:
        names = list(self._config().settings.agents.server_names)
        cert_path, key_path = self._ca.server_files(names)
        chain = self._ca.dir / "server-chain.pem"
        chain.write_bytes(cert_path.read_bytes() + self._ca.pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(chain, key_path)
        ca_file = self._ca.dir / "ca.pem"
        ctx.load_verify_locations(cafile=str(ca_file))
        ctx.verify_mode = ssl.CERT_OPTIONAL  # /enroll has no client cert yet; /agent checks it below
        return ctx

    async def start(self, host: str | None = None, port: int | None = None) -> int:
        s = self._config().settings.agents
        self._server = await serve(
            self._handle,
            host or s.listen_host,
            s.listen_port if port is None else port,
            ssl=self.ssl_context(),
            max_size=protocol.MAX_FRAME,
            ping_interval=20,
            ping_timeout=20,
        )
        sock = next(iter(self._server.sockets))
        return int(sock.getsockname()[1])

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
        for t in list(self._tasks):
            t.cancel()

    def _spawn(self, coro: Any) -> None:
        task = asyncio.get_running_loop().create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    def _audit(self, actor: str, action: str, subject: str, **detail: Any) -> int:
        with Session(self._engine) as s, s.begin():
            row = audit.append(
                s, ts=self._clock(), actor=actor, action=action, subject=subject, detail=detail
            )
            return row.seq

    async def _handle(self, ws: ServerConnection) -> None:
        path = ws.request.path if ws.request else ""
        remote = str(ws.remote_address[0]) if ws.remote_address else "?"
        try:
            if path == "/enroll":
                await self._enroll(ws, remote)
            elif path == "/agent":
                await self._agent(ws, remote)
            else:
                await ws.close(4404, "unknown path")
        except ConnectionClosed:
            pass
        except Exception:  # never let one connection take the listener down
            log.exception("agent connection from %s failed", remote)
            with contextlib.suppress(Exception):
                await ws.close(1011, "internal error")

    # --- enrollment ------------------------------------------------------------------------------------

    async def _enroll(self, ws: ServerConnection, remote: str) -> None:
        try:
            msg = protocol.parse_enroll(await asyncio.wait_for(ws.recv(), 30))
            sub = self._registry.submit(msg.token, msg.public_key, remote, msg.agent_version)
        except (ProtocolError, EnrollmentRefused, TimeoutError) as exc:
            await ws.send(protocol.encode("enroll_failed", reason=str(exc) or "refused"))
            await ws.close(4403, "enrollment refused")
            return
        await ws.send(protocol.encode("enroll_pending", fingerprint=sub.fingerprint, name=sub.name))
        while True:
            row = self._registry.enrollment(sub.enrollment_id)
            if row.status == "confirmed" and row.cert_pem and row.agent_id:
                with Session(self._engine) as s:
                    bundle = bundles.latest(s, row.name)
                    offline = offline_keys.refs(s)
                if bundle is None:
                    await ws.send(
                        protocol.encode(
                            "enroll_failed", reason="no policy bundle; run `warden policy publish`"
                        )
                    )
                    return
                await ws.send(
                    protocol.encode(
                        "enroll_ok",
                        agent_id=row.agent_id,
                        name=row.name,
                        cert_pem=row.cert_pem,
                        ca_pem=self._ca.pem.decode(),
                        trust={
                            "online_key_id": self._online.key_id,
                            "online_public": self._online.public_b64,
                            "offline_keys": offline,
                        },
                        bundle=bundle,
                    )
                )
                return
            if row.status != "submitted" or datetime.fromisoformat(row.expires_at) <= self._clock():
                await ws.send(protocol.encode("enroll_failed", reason=f"enrollment {row.status}"))
                return
            await asyncio.sleep(ENROLL_POLL_S)

    # --- agent sessions --------------------------------------------------------------------------------

    def _peer_serial(self, ws: ServerConnection) -> str | None:
        obj = ws.transport.get_extra_info("ssl_object")
        der = obj.getpeercert(binary_form=True) if obj is not None else None
        if not der:
            return None
        return format(x509.load_der_x509_certificate(der).serial_number, "x")

    async def _agent(self, ws: ServerConnection, remote: str) -> None:
        serial = self._peer_serial(ws)
        agent = self._registry.by_serial(serial) if serial else None
        if agent is None:
            self._audit(
                "warden", "agent_refused", remote, serial=serial, reason="no valid, active certificate"
            )
            await ws.close(4403, "certificate not accepted")
            return
        hello = protocol.parse_agent(await asyncio.wait_for(ws.recv(), 30))
        if not isinstance(hello, protocol.Hello):
            await ws.close(4400, "expected hello")
            return
        old = self.sessions.get(agent.name)
        if old is not None:
            await old.ws.close(4409, "replaced by a new connection")
        sess = AgentSession(
            agent=agent,
            ws=ws,
            remote=remote,
            policy_version=hello.policy_version,
            agent_version=hello.agent_version,
        )
        self.sessions[agent.name] = sess
        self._registry.seen(
            agent.id, version=hello.agent_version, policy_version=hello.policy_version, remote_addr=remote
        )
        self._audit(
            f"agent:{agent.name}",
            "agent_connected",
            agent.name,
            remote=remote,
            policy_version=hello.policy_version,
            agent_version=hello.agent_version,
        )
        try:
            await self._send_bundle_if_behind(sess)
            self._spawn(self._release_held(agent.name))
            async for frame in ws:
                try:
                    msg = protocol.parse_agent(frame)
                except ProtocolError as exc:
                    log.warning("bad frame from %s: %s", agent.name, exc)
                    await ws.close(4400, "protocol error")
                    break
                await self._on_message(sess, msg)
        finally:
            if self.sessions.get(agent.name) is sess:
                del self.sessions[agent.name]
                self._audit(f"agent:{agent.name}", "agent_disconnected", agent.name, remote=remote)
                for run in [r for r in self.runs.values() if r.agent == agent.name]:
                    self._fail_disconnected(run)
            for fut in sess.pending_ro.values():
                if not fut.done():
                    fut.set_exception(DispatchRefused("agent disconnected", code="agent_disconnected"))

    async def _send_bundle_if_behind(self, sess: AgentSession) -> bool:
        with Session(self._engine) as s:
            bundle = bundles.latest(s, sess.agent.name)
        if bundle is None:
            return False
        version = int(bundle["version"])
        if version <= sess.policy_version or version <= sess.offered_version:
            return False
        sess.offered_version = version
        try:
            await sess.ws.send(protocol.encode("bundle", bundle=bundle))
        except ConnectionClosed:
            return False
        return True

    def _locked(self) -> bool:
        with Session(self._engine) as s:
            return lockdown_state(s)

    async def policy_changed(self) -> tuple[list[str], list[str]]:
        """Called after a human published: push to every connected agent; under lockdown, kill runs."""
        pushed = [
            name for name, sess in list(self.sessions.items()) if await self._send_bundle_if_behind(sess)
        ]
        killed = []
        if self._locked():
            for plan_id in list(self.runs):
                with contextlib.suppress(DispatchRefused, ConnectionClosed):
                    await self.kill(plan_id, "warden:lockdown")
                    killed.append(plan_id)
        else:
            for name in list(self.sessions):
                self._spawn(self._release_held(name))
        return pushed, killed

    def _latest_version(self, target: str) -> int:
        with Session(self._engine) as s:
            b = bundles.latest(s, target)
        return 0 if b is None else int(b["version"])

    async def _on_message(self, sess: AgentSession, msg: protocol.AgentMessage) -> None:
        name = sess.agent.name
        match msg:
            case protocol.Heartbeat():
                sess.policy_version = msg.policy_version
                self._registry.seen(
                    sess.agent.id, version=msg.agent_version, policy_version=msg.policy_version
                )
                await self._send_bundle_if_behind(sess)
            case protocol.BundleAck():
                sess.policy_version = msg.version
                self._registry.seen(sess.agent.id, policy_version=msg.version)
                self._audit(f"agent:{name}", "bundle_ack", f"{name} · v{msg.version}", sha256=msg.sha256)
                self._spawn(self._release_held(name))
            case protocol.BundleRejected():
                self._audit(
                    f"agent:{name}",
                    "bundle_rejected",
                    f"{name} · v{msg.version}",
                    code=msg.code,
                    message=msg.message,
                )
            case protocol.ReadOnlyResult():
                fut = sess.pending_ro.pop(msg.id, None)
                if fut is not None and not fut.done():
                    fut.set_result(msg)
            case (
                protocol.PlanRefused()
                | protocol.StepStarted()
                | protocol.Output()
                | protocol.StepFinished()
                | protocol.RunFinished()
            ):
                self._on_run_message(name, msg)
            case protocol.Hello():
                pass

    # --- runs ------------------------------------------------------------------------------------------

    def _run_for(self, agent: str, plan_id: str) -> ActiveRun | None:
        run = self.runs.get(plan_id)
        return run if run is not None and run.agent == agent else None

    def _on_run_message(self, agent: str, msg: Any) -> None:
        run = self._run_for(agent, msg.plan_id)
        if run is None:
            log.warning("message for unknown run %s from %s", msg.plan_id, agent)
            return
        if isinstance(msg, protocol.PlanRefused):
            self._audit(
                f"agent:{agent}", "plan_refused_by_agent", msg.plan_id, code=msg.code, message=msg.message
            )
            run.outcomes = [StepOutcome(n=1, exit_code=126, refused=msg.code)]
            self._finish(run)
        elif isinstance(msg, protocol.StepStarted):
            run.current = msg.n
        elif isinstance(msg, protocol.Output):
            cap = int(effective_cap_bytes(self._config(), run.plan.target))
            used = run.sent_bytes.get(msg.n, 0)
            data = msg.data[: max(0, cap - used)]
            if data:
                run.sent_bytes[msg.n] = used + len(data)
                run.seq += 1
                with Session(self._engine) as s, s.begin():
                    outputs.append(s, plan_id=msg.plan_id, n=msg.n, seq=run.seq, stream=msg.stream, data=data)
        elif isinstance(msg, protocol.StepFinished):
            expected = len(run.outcomes) + 1
            if msg.n != expected:
                log.warning("out-of-order step %s from %s", msg.n, agent)
                run.outcomes.append(StepOutcome(n=expected, exit_code=None))
                self._finish(run)
                return
            if msg.refused is not None:
                self._audit(
                    f"agent:{agent}",
                    "step_refused",
                    f"{msg.plan_id} · step {msg.n}",
                    code=msg.refused.code,
                    message=msg.refused.message,
                )
            run.outcomes.append(
                StepOutcome(
                    n=msg.n,
                    exit_code=msg.exit_code,
                    timed_out=msg.timed_out,
                    refused=msg.refused.code if msg.refused else None,
                    killed=msg.killed,
                    duration_s=msg.duration_ms / 1000,
                    output_truncated=msg.truncated,
                )
            )
            with Session(self._engine) as s, s.begin():
                rows = outputs.read(s, msg.plan_id, msg.n)
                audit.append(
                    s,
                    ts=self._clock(),
                    actor=f"agent:{agent}",
                    action="step_output",
                    subject=f"{msg.plan_id} · step {msg.n}",
                    detail={"sha256": outputs.digest(rows), "chunks": len(rows), "truncated": msg.truncated},
                )
            run.current = None
        elif isinstance(msg, protocol.RunFinished):
            self._finish(run)

    def _finish(self, run: ActiveRun) -> None:
        if run.done.done():
            return
        self.runs.pop(run.plan.id, None)
        try:
            plan = self._plans.finish_run(run.plan.id, run.outcomes)
        except WardenError as exc:
            log.error("finishing %s failed: %s", run.plan.id, exc)
            plan = self._plans.get(run.plan.id)
        run.done.set_result(plan)

    def _fail_disconnected(self, run: ActiveRun) -> None:
        n = run.current if run.current is not None else len(run.outcomes) + 1
        if n <= len(run.plan.steps):
            run.outcomes.append(StepOutcome(n=n, exit_code=None, disconnected=True))
        self._finish(run)

    async def execute(self, plan_id: str, *, wait: bool = True) -> Plan:
        """Send an approved plan to its agent (README 6 execute_plan). Holds it if the agent can't run it."""
        plan = self._plans.get(plan_id)
        self._plans.validate_for_dispatch(plan_id)
        cfg = self._config()
        try:
            with Session(self._engine) as s:
                bundles.check_published(s, cfg.policy, cfg.targets, plan.target)
        except bundles.PolicyUnpublished as exc:
            self._audit("warden", "dispatch_refused", plan_id, code=exc.code, message=exc.message)
            raise DispatchRefused(exc.message, code=exc.code) from exc
        if self._locked():
            return self._plans.hold(plan_id, "lockdown")
        sess = self.sessions.get(plan.target)
        latest = self._latest_version(plan.target)
        if sess is None or sess.policy_version < latest:
            why = (
                f"{plan.target} is offline"
                if sess is None
                else f"{plan.target} is behind on policy (v{sess.policy_version}, latest v{latest})"
            )
            return self._plans.hold(plan_id, why)
        plan = self._plans.start_run(plan_id)
        if plan.approval is None:
            raise DispatchRefused(f"{plan_id} has no approval", code="not_approved")
        run = ActiveRun(plan=plan, agent=plan.target)
        self.runs[plan_id] = run
        a = plan.approval
        try:
            await sess.ws.send(
                protocol.encode(
                    "run",
                    template=plan.template(),
                    plan_hash=plan.hash,
                    approval={
                        "by": a.by,
                        "at": a.at.isoformat(),
                        "expires_at": plan.expires_at.isoformat(),
                        "hash": a.hash,
                        "signature": a.signature.model_dump(),
                    },
                )
            )
        except ConnectionClosed:
            self._fail_disconnected(run)
        if not wait:
            return plan
        limit = sum(st.timeout_s for st in plan.steps) + 30 * len(plan.steps) + 60
        try:
            return await asyncio.wait_for(asyncio.shield(run.done), limit)
        except TimeoutError:
            run.outcomes.append(StepOutcome(n=len(run.outcomes) + 1, exit_code=None, timed_out=True))
            self._finish(run)
            return await run.done

    def execute_in_background(self, plan_id: str) -> asyncio.Task[Plan]:
        """Start `execute` as a task the dispatcher owns, so a caller that stops waiting doesn't cancel it."""
        task: asyncio.Task[Plan] = asyncio.get_running_loop().create_task(self.execute(plan_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    def run_progress(self, plan_id: str) -> tuple[int, int] | None:
        """(finished steps, total steps) for a running plan."""
        run = self.runs.get(plan_id)
        return None if run is None else (len(run.outcomes), len(run.plan.steps))

    async def kill(self, plan_id: str, actor: str) -> None:
        run = self.runs.get(plan_id)
        if run is None:
            raise DispatchRefused(f"{plan_id} isn't running", code="not_running")
        self._audit(actor, "kill", plan_id)
        sess = self.sessions.get(run.agent)
        if sess is not None:
            await sess.ws.send(protocol.encode("kill", plan_id=plan_id))

    async def _release_held(self, target: str) -> None:
        sess = self.sessions.get(target)
        if sess is None or sess.policy_version < self._latest_version(target) or self._locked():
            return
        for plan in self._plans.list_plans(statuses=(PlanStatus.HELD,), oldest_first=True):
            if plan.target != target:
                continue
            try:
                self._plans.release(plan.id)
                self._audit("warden", "held_released", plan.id, reason=f"{target} is current")
                self._spawn(self.execute(plan.id))
            except WardenError as exc:
                log.info("held plan %s not released: %s", plan.id, exc)

    async def revoke(self, name: str) -> None:
        sess = self.sessions.pop(name, None)
        if sess is not None:
            for run in [r for r in self.runs.values() if r.agent == name]:
                self._fail_disconnected(run)
            await sess.ws.close(4403, "agent revoked")

    # --- read-only -------------------------------------------------------------------------------------

    async def read_only(self, target: str, command: str, actor: str) -> ReadOnlyOutcome:
        """README 8: checked centrally, sent to the agent, checked again there, logged either way."""
        cfg = self._config()
        t = cfg.targets.get(target)
        if t is None:
            raise DispatchRefused(f"unknown target {target}", code="unknown_target")
        rules = effective_rules(cfg.policy, t)
        violations = check_read_only(command, rules, self._plans.resolver)
        if violations:
            detail = [v.model_dump() for v in violations]
            seq = self._audit(
                actor,
                "read_only_refused",
                f"{target} · {command}",
                target=target,
                command=command,
                violations=detail,
            )
            return ReadOnlyOutcome(False, None, "", False, detail, seq)
        sess = self.sessions.get(target)
        if sess is None:
            raise DispatchRefused(f"{target} is offline", code="agent_offline")
        rid = str(uuid.uuid4())
        fut: asyncio.Future[protocol.ReadOnlyResult] = asyncio.get_running_loop().create_future()
        sess.pending_ro[rid] = fut
        await sess.ws.send(protocol.encode("read_only", id=rid, command=command))
        try:
            res = await asyncio.wait_for(fut, READ_ONLY_TIMEOUT_S)
        finally:
            sess.pending_ro.pop(rid, None)
        refused = [res.refused.model_dump()] if res.refused else []
        seq = self._audit(
            actor,
            "read_only" if not refused else "read_only_refused",
            f"{target} · {command}",
            target=target,
            command=command,
            exit_code=res.exit_code,
            output=res.output[:65536],
            truncated=res.truncated,
            refused=refused,
            duration_ms=res.duration_ms,
        )
        return ReadOnlyOutcome(not refused, res.exit_code, res.output, res.truncated, refused, seq)


def effective_cap_bytes(cfg: Config, target: str) -> int:
    t = cfg.targets.get(target)
    if t is None:
        return 0
    return effective_rules(cfg.policy, t).output_cap_mb.value * 1024 * 1024
