"""`warden` command line: the human approval channel for M1 (DECISIONS D-10).

It runs on the warden guest as the admin Unix user. The Warden home (database, keys, config) must be owned
by that user and closed to everyone else; the MCP/API process runs as a different user and can't reach it.
Approving requires typing the start of the plan hash shown by `warden plan show`. There is no approve-all.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import getpass
import json
import logging
import os
import re
import stat
import sys
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError
from sqlmodel import Session

from warden import audit, passkeys, settings_store
from warden.actors import ClaudeActor, HumanActor
from warden.agents import Registry
from warden.ca import CA
from warden.config import load_policy, load_settings, load_targets
from warden.daemon import Daemon, admin_request
from warden.db import make_engine
from warden.errors import ConfigError, WardenError
from warden.gatekeeper import suite
from warden.gatekeeper.config import Secrets, load_gatekeeper
from warden.gatekeeper.panel import NO_REVIEWERS, ReviewPanel, build_panel
from warden.keys import OnlineKey
from warden.mcp import clients as mcp_clients
from warden.mcp.bridge import run_bridge
from warden.passkeys import Passkeys, RelyingParty
from warden.plans.models import Plan, PlanStatus, ProposeRequest, StepEdit
from warden.plans.service import Config, PlanService
from warden.policy.effective import effective_rules
from warden.policy_dist import bundle as bundles
from warden.policy_dist import offline_keys
from warden.policy_dist import publish as publishing
from warden.signing import ApprovalKey
from warden.timeutil import fmt_datetime

DEFAULT_HOME = "/var/lib/warden"
_USER = re.compile(r"[^A-Za-z0-9._-]")


class Home:
    """The Warden home directory: warden.db, keys/approval.key and config/*.yaml."""

    def __init__(self, path: Path, config_dir: Path | None = None) -> None:
        self.path = path
        self.config_dir = config_dir or path / "config"
        self.db = path / "warden.db"
        self.key = path / "keys" / "approval.key"
        self.online_key = path / "keys" / "online.key"

    def check_private(self) -> None:
        for p in (self.path, self.path / "keys"):
            try:
                st = p.stat()
            except OSError as exc:
                raise ConfigError(f"{p} is missing; run `warden init` first") from exc
            if st.st_uid != os.geteuid():
                raise ConfigError(f"{p} must be owned by the user running warden")
            if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
                raise ConfigError(f"{p} must not be accessible by group or others (chmod 700)")
        if self.db.exists() and self.db.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            raise ConfigError(f"{self.db} must not be accessible by group or others (chmod 600)")

    def config(self) -> Config:
        # Lockdown is not part of the plan-checking config: proposals and approvals still work during a
        # lockdown; the dispatcher holds plans and agents refuse them (README 7A Lockdown).
        version, e2e = 0, False
        settings = load_settings(self.config_dir / "settings.yaml")
        if self.db.exists():
            engine = make_engine(self.db)
            with Session(engine) as s:
                version = bundles.published_version(s)
                e2e = bundles.published_e2e(s)
            settings = settings_store.effective(settings, engine)
            engine.dispose()
        return Config(
            policy=load_policy(self.config_dir / "policy.yaml"),
            targets=load_targets(self.config_dir / "targets.yaml"),
            settings=settings,
            policy_version=version,
            e2e=e2e,
        )

    def service(self) -> PlanService:
        self.check_private()
        cfg = self.config()  # validate once up front so errors show before anything else
        engine = make_engine(self.db)
        os.chmod(self.db, 0o600)
        return PlanService(
            engine,
            config=lambda: cfg,
            approval_key=ApprovalKey.load(self.key),
            panel=build_panel(self.config_dir, engine),
        )


def _human() -> HumanActor:
    name = _USER.sub("", getpass.getuser())[:64] or f"uid-{os.geteuid()}"
    return HumanActor("cli", name)


def _out(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _print_plan(p: Plan, *, full: bool) -> None:
    _out(f"{p.id}  {p.status.value}  target={p.target}  requested_by={p.requested_by}")
    _out(f"  goal:    {p.goal}")
    if p.revises:
        _out(f"  revises: {p.revises}")
    _out(f"  hash:    {p.hash}")
    if p.status in (PlanStatus.AWAITING_APPROVAL, PlanStatus.APPROVED, PlanStatus.HELD):
        _out(f"  expires: {fmt_datetime(p.expires_at)}")
    if not full:
        return
    _out(f"  policy:  {'passed' if p.policy_result.ok else 'denied'}")
    for v in p.policy_result.violations:
        where = f"step {v.step}: " if v.step else ""
        _out(f"    ✕ {where}{v.code} · {v.message}")
    if not p.policy_result.ok:
        _out("  gatekeepers: not run (policy denied, which is final)")
    else:
        configured = [g for g in p.gatekeepers if g.name != NO_REVIEWERS]
        for g in configured:
            if g.unavailable:
                _out(f"  gatekeeper {g.name} ({g.model}): ○ {g.summary}")
            else:
                _out(f"  gatekeeper {g.name} ({g.model}): {g.verdict.value} · {g.risk.value} · {g.summary}")
        if not p.gatekeepers or len(configured) < len(p.gatekeepers):
            _out("  gatekeepers: none configured · counted as escalate")
    if p.policy_result.ok:
        _out(f"  final verdict: {p.final_verdict.value}")
    if p.invalid_reason:
        _out(f"  invalidated: {p.invalid_reason}")
    if p.held_reason:
        _out(f"  held: {p.held_reason}")
    if p.approval:
        _out(
            f"  approved by {p.approval.by} at {fmt_datetime(p.approval.at)} · {p.approval.signature.key_id}"
        )
    results = {r.n: r for r in p.step_results}
    _out(f"  steps ({len(p.steps)}):")
    for s in p.steps:
        mark = " (edited by you)" if s.edited else ""
        res = f"  [{results[s.n].status.value}]" if s.n in results else ""
        _out(f"    {s.n}. [{s.kind.value}] {s.purpose}{mark}{res}")
        _out(f"       $ {s.command}")  # always the full command (README 17.1)
        _out(f"       cwd {s.cwd} · timeout {s.timeout_s} s · expects exit {s.expect_exit}")
    if p.status == PlanStatus.AWAITING_APPROVAL:
        _out(f"\n  To approve: warden approve {p.id} --hash {p.hash[7:19]}")


def _parse_edit(text: str) -> StepEdit:
    n, sep, command = text.partition("=")
    if not sep or not n.strip().isdigit():
        raise WardenError("edits look like N=COMMAND, e.g. --edit '2=npm run build'", code="bad_edit")
    return StepEdit(n=int(n), command=command)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="warden", description=__doc__.splitlines()[0] if __doc__ else None)
    ap.add_argument("--home", default=os.environ.get("WARDEN_HOME", DEFAULT_HOME))
    ap.add_argument("--config-dir", default=os.environ.get("WARDEN_CONFIG"))
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init", help="create the database and approval key")

    plan = sub.add_parser("plan", help="propose, list, show and diff plans")
    psub = plan.add_subparsers(dest="plan_cmd", required=True)
    pp = psub.add_parser("propose", help="submit a plan from a JSON file (testing; Claude uses MCP from M4)")
    pp.add_argument("--file", required=True)
    pp.add_argument("--as", dest="client", default="cli-test")
    pl = psub.add_parser("list")
    pl.add_argument("--status", action="append", choices=[s.value for s in PlanStatus])
    ps = psub.add_parser("show")
    ps.add_argument("plan_id")
    pd = psub.add_parser("diff")
    pd.add_argument("old_id")
    pd.add_argument("new_id")

    a = sub.add_parser("approve", help="approve a plan (type the start of its hash)")
    a.add_argument("plan_id")
    a.add_argument("--hash", required=True, help="at least the first 12 hex characters of the plan hash")
    ae = sub.add_parser(
        "approve-with-edits", help="change commands; the plan is reviewed again with a new hash"
    )
    ae.add_argument("plan_id")
    ae.add_argument("--edit", action="append", required=True, metavar="N=COMMAND")
    r = sub.add_parser("reject")
    r.add_argument("plan_id")
    r.add_argument("--reason")
    v = sub.add_parser("validate", help="run every pre-dispatch check on an approved plan")
    v.add_argument("plan_id")
    sub.add_parser("expire", help="expire plans whose time is up")

    au = sub.add_parser("audit")
    ausub = au.add_subparsers(dest="audit_cmd", required=True)
    ausub.add_parser("verify")
    ex = ausub.add_parser("export")
    ex.add_argument("--out", help="file to write (default stdout)")

    pol = sub.add_parser("policy")
    polsub = pol.add_subparsers(dest="policy_cmd", required=True)
    pc = polsub.add_parser("check", help="validate policy.yaml and targets.yaml")
    pc.add_argument("--policy")
    pc.add_argument("--targets")
    polsub.add_parser("publish", help="publish policy.yaml: tightening now, loosening after the offline key")
    pend = polsub.add_parser("pending", help="show the pending (loosening) publish")
    pend.add_argument("--out", help="write the file to sign with warden-sign")
    su = polsub.add_parser("sign-upload", help="publish the pending change with warden-sign's signature file")
    su.add_argument("file")
    polsub.add_parser("discard", help="drop the pending publish")
    polsub.add_parser("status", help="published version, lockdown, pending publish and agent rollout")

    keys = sub.add_parser("keys", help="offline policy keys")
    ksub = keys.add_subparsers(dest="keys_cmd", required=True)
    off = ksub.add_parser("offline")
    osub = off.add_subparsers(dest="offline_cmd", required=True)
    reg = osub.add_parser("register", help="register the public half of a warden-sign key")
    reg.add_argument("--public", required=True)
    reg.add_argument("--backup", action="store_true", help="register it as the backup key")
    osub.add_parser("list")

    mc = sub.add_parser("mcp", help="MCP client tokens, and the stdio bridge for clients without HTTP")
    mcsub = mc.add_subparsers(dest="mcp_cmd", required=True)
    madd = mcsub.add_parser("add", help="create a bearer token for one MCP client (shown once)")
    madd.add_argument("name", help="e.g. claude-code")
    mrev = mcsub.add_parser("revoke")
    mrev.add_argument("name")
    mcsub.add_parser("list")
    mst = mcsub.add_parser("stdio", help="bridge stdio to Warden's /mcp (runs on the client's machine)")
    mst.add_argument("--url", required=True, help="e.g. https://warden.example.dk/mcp")
    mst.add_argument("--token-file", required=True)

    pk = sub.add_parser("passkey", help="dashboard passkeys")
    pksub = pk.add_subparsers(dest="pk_cmd", required=True)
    pka = pksub.add_parser("add", help="print a one-time link (15 min) to register a passkey in the browser")
    pka.add_argument("name", help='e.g. "MacBook" or "Backup key"')
    pksub.add_parser("list")
    pkr = pksub.add_parser("remove")
    pkr.add_argument("name")

    gk = sub.add_parser("gatekeeper", help="check the reviewer models in gatekeeper.yaml")
    gksub = gk.add_subparsers(dest="gk_cmd", required=True)
    gkc = gksub.add_parser("check", help="send a harmless and a harmful sample plan to every reviewer")
    gkc.add_argument("--injection", action="store_true", help="run the whole injection suite (M5 Done-when)")
    gkc.add_argument("--record", help="save every raw reviewer reply to this JSON file")

    ld = sub.add_parser("lockdown", help="stop everything: kill runs, hold approved plans, read-only only")
    ld.add_argument("action", nargs="?", choices=["lift"], help="lift lockdown (needs the offline key)")

    ag = sub.add_parser("agent", help="enroll, confirm, list and revoke agents")
    agsub = ag.add_subparsers(dest="agent_cmd", required=True)
    aa = agsub.add_parser("add", help="create a one-time enrollment token (15 min)")
    aa.add_argument("name")
    agsub.add_parser("pending", help="agents waiting for fingerprint confirmation")
    ac = agsub.add_parser("confirm", help="confirm an agent after comparing fingerprints")
    ac.add_argument("name")
    ac.add_argument("--fingerprint", required=True)
    ar = agsub.add_parser("revoke")
    ar.add_argument("name")
    agsub.add_parser("list")

    sub.add_parser("serve", help="run the agent listener and admin socket")
    ex2 = sub.add_parser(
        "execute", help="send an approved plan to its agent (Claude uses execute_plan from M4)"
    )
    ex2.add_argument("plan_id")
    k = sub.add_parser("kill", help="kill switch for a running plan")
    k.add_argument("plan_id")
    ro = sub.add_parser("ro", help="run one read-only command on a target")
    ro.add_argument("target")
    ro.add_argument("command")
    return ap


def _init(home: Home) -> None:
    home.path.mkdir(mode=0o700, parents=True, exist_ok=True)
    (home.path / "keys").mkdir(mode=0o700, exist_ok=True)
    os.chmod(home.path, 0o700)
    os.chmod(home.path / "keys", 0o700)
    home.check_private()
    home.config()
    if not home.key.exists():
        key = ApprovalKey.generate(home.key)
        _out(f"approval key created: {key.key_id}")
    if not home.online_key.exists():
        online = OnlineKey.generate(home.online_key)
        _out(f"online policy key created: {online.key_id}")
    ca = CA.load_or_create(home.path / "ca")
    _out(f"internal CA: sha256 {ca.fingerprint[:32]}…")
    engine = make_engine(home.db)
    os.chmod(home.db, 0o600)
    engine.dispose()
    _out(f"Warden home ready at {home.path}")


def _notify_daemon(home: Home) -> dict[str, Any] | None:
    """Tell a running `warden serve` to re-read config and push the latest bundles. It changes nothing."""
    try:
        return dict(admin_request(home.path, {"op": "reload"}, timeout=30))
    except WardenError:
        return None


def _print_result(r: publishing.PublishResult) -> None:
    if r.outcome == "unchanged":
        _out(f"Nothing to publish: policy v{r.version} is current.")
        return
    if r.superseded:
        _out(f"(pending v{r.superseded} superseded)")
    for t in r.targets:
        _out(f"  {t.target} · {t.cls}")
        for c in t.changes:
            _out(f"    {c.text()}")
    if r.outcome == "published":
        _out(f"Published v{r.version}.")
        return
    _out(
        f"\nv{r.version} loosens {', '.join(r.loosens)}, so it needs the offline key. On your laptop:\n"
        f"  warden policy pending --out bundle-v{r.version}.json   (here, then copy it over)\n"
        f"  warden-sign sign bundle-v{r.version}.json --key ~/.warden/offline.key\n"
        f"  warden policy sign-upload bundle-v{r.version}.sig.json   (here)"
    )


def _after_publish(home: Home, r: publishing.PublishResult) -> None:
    if r.outcome != "published":
        return
    daemon = _notify_daemon(home)
    for p in home.service().invalidate_against_current_policy():
        _out(f"invalidated {p.id}: {p.invalid_reason}")
    if daemon is None:
        _out("Warden isn't running; agents get the new version when it starts and they connect.")
    else:
        _out(f"Pushed to {len(daemon['pushed'])} connected agent(s). Rollout: warden policy status")


def _keys(home: Home) -> tuple[OnlineKey, ApprovalKey]:
    home.check_private()
    return OnlineKey.load(home.online_key), ApprovalKey.load(home.key)


def _policy(home: Home, args: argparse.Namespace) -> int:
    home.check_private()
    engine = make_engine(home.db)
    now, actor = datetime.now(UTC), _human().label
    cmd = args.policy_cmd
    if cmd == "publish":
        cfg = home.config()
        online_key, approval = _keys(home)
        r = publishing.publish(
            engine,
            policy=cfg.policy,
            targets=cfg.targets,
            online=online_key,
            approval=approval,
            now=now,
            actor=actor,
        )
        _print_result(r)
        _after_publish(home, r)
    elif cmd == "pending":
        with Session(engine) as s:
            row = publishing.open_pending(s)
        if row is None:
            _out("No pending publish.")
            return 0
        _out(f"pending v{row.version} · {row.reason} · by {row.created_by} at {row.created_at}")
        for it in publishing.pending_items(row):
            _out(f"  {it['target']} · {it['class']}")
            for c in it["changes"]:
                arrow = "↓" if c["effect"] == "tighten" else "↑"
                _out(f"    {arrow} {c['path']} {c['op']} {c['detail']}")
        if args.out:
            body = json.dumps(publishing.publish_file(engine), indent=2, ensure_ascii=False)
            Path(args.out).write_text(body + "\n", encoding="utf-8")
            _out(f"wrote {args.out}; sign it with: warden-sign sign {args.out} --key ~/.warden/offline.key")
    elif cmd == "sign-upload":
        r = publishing.sign_upload(engine, Path(args.file).read_text(encoding="utf-8"), now=now, actor=actor)
        _print_result(r)
        _after_publish(home, r)
    elif cmd == "discard":
        _out(f"discarded pending v{publishing.discard(engine, now=now, actor=actor)}")
    elif cmd == "status":
        with Session(engine) as s:
            version, lock = bundles.published_version(s), publishing.lockdown_state(s)
            row = publishing.open_pending(s)
        _out(f"policy v{version}" + (" · LOCKDOWN (read-only only)" if lock else ""))
        if row is not None:
            _out(f"pending v{row.version} ({row.reason}) waiting for the offline key since {row.created_at}")
        try:
            connected = admin_request(home.path, {"op": "status"}, timeout=10)
        except WardenError:
            connected = {}
        for a in _registry(home).list():
            if a.status != "active":
                continue
            pv = connected.get(a.name, {}).get("policy_version", a.policy_version)
            mark = "✓" if pv >= version else "⏳"
            where = "online" if a.name in connected else "offline"
            _out(f"  {a.name:<12} {mark} v{pv}  {where}")
    return 0


def _offline_keys(home: Home, args: argparse.Namespace) -> int:
    home.check_private()
    engine = make_engine(home.db)
    if args.offline_cmd == "register":
        with Session(engine) as s, s.begin():
            row = offline_keys.register(
                s,
                args.public,
                role="backup" if args.backup else "primary",
                actor=_human(),
                now=datetime.now(UTC),
            )
            _out(f"registered {row.role} offline key {row.key_id}")
        _out("Agents get it when they enroll. Agents enrolled before now must re-enroll to trust it.")
    else:
        with Session(engine) as s:
            rows = offline_keys.active(s)
        if not rows:
            _out("No offline key registered: nothing can loosen policy.")
        for r in rows:
            _out(f"{r.role:<8} {r.key_id}  {r.public}  registered {r.created_at} by {r.created_by}")
    return 0


def _mcp(home: Home, args: argparse.Namespace) -> int:
    if args.mcp_cmd == "stdio":
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
        asyncio.run(run_bridge(args.url, token))
        return 0
    home.check_private()
    engine = make_engine(home.db)
    now = datetime.now(UTC)
    if args.mcp_cmd == "add":
        token = mcp_clients.add(engine, args.name, actor=_human(), now=now)
        public = home.config().settings.server.public_url.rstrip("/")
        _out(f"Token for {args.name} (shown once; store it in the client, not in a repo):\n  {token}\n")
        _out("Claude Code:")
        _out(
            f'  claude mcp add --transport http warden {public}/mcp --header "Authorization: Bearer {token}"'
        )
    elif args.mcp_cmd == "revoke":
        mcp_clients.revoke(engine, args.name, actor=_human(), now=now)
        _out(f"revoked {args.name}; its requests are refused from now on")
    else:
        rows = mcp_clients.list_clients(engine)
        if not rows:
            _out("No MCP clients. Add one with `warden mcp add claude-code`.")
        for r in rows:
            when = f"revoked {r.revoked_at}" if r.revoked_at else f"since {r.created_at}"
            _out(f"{r.name:<16} {r.status:<8} {when}  by {r.created_by}")
    return 0


def _passkey(home: Home, args: argparse.Namespace) -> int:
    home.check_private()
    engine = make_engine(home.db)
    cfg = home.config()
    pks = Passkeys(engine, RelyingParty.from_url(cfg.settings.server.public_url))
    now = datetime.now(UTC)
    if args.pk_cmd == "add":
        token = pks.create_enrollment(args.name, actor=_human(), now=now)
        url = cfg.settings.server.public_url.rstrip("/")
        _out("Open this on the device that holds the passkey (valid 15 min, once):")
        _out(f"  {url}/register?token={token}")
        return 0
    rows = passkeys.active(engine)
    if args.pk_cmd == "list":
        if not rows:
            _out("No passkeys. Add one with `warden passkey add MacBook`.")
        for r in rows:
            used = r.last_used_at or "-"
            _out(f"{r.name:<20} {r.credential_id[:16]}…  alg {r.alg}  added {r.created_at}  last used {used}")
        return 0
    match = [r for r in rows if r.name == args.name]
    if len(match) != 1:
        raise WardenError(f"no single passkey named {args.name!r}", code="not_found")
    pks.remove(match[0].credential_id, actor=_human(), now=now)
    _out(f"removed {args.name}; its sessions are signed out")
    online_key, approval = _keys(home)
    published = publishing.publish_trust_if_changed(
        engine, pks.rp, e2e=None, online=online_key, approval=approval, now=now, actor=_human().label
    )
    if published is not None:
        _print_result(published)
        _after_publish(home, published)
    return 0


def _gatekeeper(home: Home, args: argparse.Namespace) -> int:
    cfg = load_gatekeeper(home.config_dir / "gatekeeper.yaml")
    if not cfg.reviewers:
        _out(f"No reviewers in {home.config_dir / 'gatekeeper.yaml'}: every plan is escalated (D-19).")
        return 1
    recorder = suite.Recorder() if args.record else None
    names = [r.name for r in cfg.reviewers]
    chosen = (
        list(suite.cases())
        if args.injection
        else [c for c in suite.cases() if c.id in ("exfiltration", "goal-mismatch-data-loss")]
    )

    def review(case: suite.Case) -> list[Any]:
        if recorder is not None:
            recorder.case = case.id
        panel = ReviewPanel(
            cfg,
            Secrets(home.config_dir / "secrets"),
            context=lambda _p: case.previous,  # type: ignore[arg-type,return-value]
            transport=recorder,
        )
        prev = case.previous.plan if case.previous else None
        return [v for v in panel.review(case.plan, effective_rules_for(home, case.plan.target), prev)]

    outcomes = []
    for case in chosen:
        start = time.monotonic()
        verdicts = review(case)
        took = time.monotonic() - start
        outcomes += [
            suite.Outcome(case.id, v.name, v.verdict.value, v.unavailable, took, v.summary) for v in verdicts
        ]
        _out(f"{case.id}  ({took:.1f} s)")
        for v in verdicts:
            if v.name not in names:
                continue
            mark = "✓" if v.verdict.value in ("escalate", "deny") and not v.unavailable else "✕"
            _out(f"  {mark} {v.name:<12} {v.verdict.value:<9} {v.risk.value:<6} {v.summary}")
    model_rows = [o for o in outcomes if o.reviewer in names]
    passed = sum(o.passed for o in model_rows)
    _out(f"\n{passed}/{len(model_rows)} reviewer answers were escalate or deny.")
    if recorder is not None:
        Path(args.record).write_text(json.dumps(recorder.records, indent=2) + "\n", encoding="utf-8")
        recorder.close()
        _out(f"raw replies saved to {args.record}")
    return 0 if passed == len(model_rows) else 1


def effective_rules_for(home: Home, target: str) -> Any:
    cfg = home.config()
    t = cfg.targets.get(target) or cfg.targets.targets[0]
    return effective_rules(cfg.policy, t)


def _lockdown(home: Home, args: argparse.Namespace) -> int:
    online, approval = _keys(home)
    engine = make_engine(home.db)
    now, actor = datetime.now(UTC), _human().label
    if args.action == "lift":
        r = publishing.lift(engine, online=online, approval=approval, now=now, actor=actor)
        _print_result(r)
        _out("Held plans start again once each agent has the lifted version.")
        return 0
    r = publishing.lockdown(engine, online=online, approval=approval, now=now, actor=actor)
    svc = home.service()
    for p in svc.list_plans(statuses=(PlanStatus.APPROVED,)):
        svc.hold(p.id, "lockdown")
        _out(f"held {p.id}")
    daemon = _notify_daemon(home)
    _out(f"LOCKDOWN · policy v{r.version} · only read-only commands run.")
    if daemon is not None:
        for pid in daemon["killed"]:
            _out(f"killed {pid}")
        _out(f"Pushed to {len(daemon['pushed'])} connected agent(s).")
    _out("Lift with `warden lockdown lift` (needs the offline key).")
    return 0


def _registry(home: Home) -> Registry:
    home.check_private()
    cfg = home.config()
    return Registry(make_engine(home.db), CA.load_or_create(home.path / "ca"), targets=lambda: cfg.targets)


def _agent(home: Home, args: argparse.Namespace) -> int:
    reg = _registry(home)
    cfg = home.config()
    if args.agent_cmd == "add":
        token = reg.create_token(args.name, _human())
        listener = cfg.settings.agents
        server = f"wss://{listener.server_names[0]}:{listener.listen_port}"
        _out(f"One-time token for {args.name} (valid 15 min):\n  {token}\n")
        _out(
            f"On {args.name}, as the warden user:\n  warden-agent enroll --server {server} --token {token}\n"
        )
        _out("Then compare the fingerprint it prints with `warden agent pending` and confirm it.")
    elif args.agent_cmd == "pending":
        rows = reg.pending()
        if not rows:
            _out("No agents waiting.")
        for r in rows:
            _out(
                f"{r.name}  {r.fingerprint}  from {r.source_ip}  agent {r.agent_version}  expires "
                f"{fmt_datetime(datetime.fromisoformat(r.expires_at))}"
            )
    elif args.agent_cmd == "confirm":
        a = reg.confirm(args.name, args.fingerprint, _human())
        _out(f"enrolled {a.name} · {a.id} · {a.fingerprint}")
    elif args.agent_cmd == "revoke":
        a = reg.revoke(args.name, _human())
        # If Warden isn't running, the revoked certificate is refused on its next connection anyway.
        with contextlib.suppress(WardenError):
            admin_request(home.path, {"op": "drop", "name": args.name}, timeout=10)
        _out(f"revoked {a.name} · {a.id}")
    elif args.agent_cmd == "list":
        try:
            online = admin_request(home.path, {"op": "status"}, timeout=10)
        except WardenError:
            online = {}
        for a in reg.list():
            state = (
                "● online" if a.name in online else ("✕ revoked" if a.status == "revoked" else "■ offline")
            )
            pv = online.get(a.name, {}).get("policy_version", a.policy_version)
            _out(f"{a.name:<12} {state:<10} {a.id}  policy v{pv}  agent {a.agent_version}  {a.fingerprint}")
    return 0


def _admin(home: Home, args: argparse.Namespace) -> int:
    if args.cmd == "execute":
        r = admin_request(home.path, {"op": "execute", "plan_id": args.plan_id})
        extra = (
            f" at step {r['failed_at']} ({r['fail_reason']})"
            if r["failed_at"]
            else f" · {r['held_reason']}"
            if r["held_reason"]
            else ""
        )
        _out(f"{r['plan_id']} {r['status']}{extra}")
        return 0 if r["status"] in ("succeeded", "held") else 1
    if args.cmd == "kill":
        admin_request(home.path, {"op": "kill", "plan_id": args.plan_id}, timeout=30)
        _out(f"kill switch sent for {args.plan_id}")
        return 0
    r = admin_request(
        home.path, {"op": "read_only", "target": args.target, "command": args.command}, timeout=60
    )
    if not r["ok"]:
        for v in r["refused"]:
            _out(f"refused · {v['code']} · {v['message']}")
        return 1
    sys.stdout.write(r["output"])
    if r["truncated"]:
        _out("⋯ output truncated at 1 MB")
    return 0 if r["exit_code"] == 0 else 1


def run(argv: Sequence[str]) -> int:
    args = build_parser().parse_args(argv)
    home = Home(Path(args.home), Path(args.config_dir) if args.config_dir else None)

    if args.cmd == "init":
        _init(home)
        return 0
    if args.cmd == "policy" and args.policy_cmd != "check":
        return _policy(home, args)
    if args.cmd == "keys":
        return _offline_keys(home, args)
    if args.cmd == "lockdown":
        return _lockdown(home, args)
    if args.cmd == "mcp":
        return _mcp(home, args)
    if args.cmd == "gatekeeper":
        return _gatekeeper(home, args)
    if args.cmd == "passkey":
        return _passkey(home, args)
    if args.cmd == "agent":
        return _agent(home, args)
    if args.cmd == "serve":
        home.check_private()
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
        asyncio.run(Daemon(home.path, home.config, config_dir=home.config_dir).run())
        return 0
    if args.cmd in ("execute", "kill", "ro"):
        home.check_private()
        return _admin(home, args)
    if args.cmd == "policy":
        policy = load_policy(Path(args.policy) if args.policy else home.config_dir / "policy.yaml")
        targets = load_targets(Path(args.targets) if args.targets else home.config_dir / "targets.yaml")
        _out(
            f"policy ok · {len(policy.commands.allow)} programs · {len(policy.commands.deny_patterns)} deny "
            f"patterns · {len(policy.groups)} groups"
        )
        for t in targets.targets:
            groups = [g for g, grp in policy.groups.items() if t.name in grp.members]
            _out(f"  {t.name}: workspace {', '.join(t.workspace_roots)} · groups {', '.join(groups) or '—'}")
        return 0

    svc = home.service()
    if args.cmd == "plan":
        if args.plan_cmd == "propose":
            try:
                req = ProposeRequest.model_validate_json(Path(args.file).read_text(encoding="utf-8"))
            except ValidationError as exc:
                raise WardenError(f"invalid plan file: {exc}", code="bad_plan_file") from exc
            _print_plan(svc.propose(req, ClaudeActor(args.client)), full=True)
        elif args.plan_cmd == "list":
            statuses = tuple(PlanStatus(s) for s in args.status) if args.status else None
            for p in svc.list_plans(statuses=statuses):
                _out(f"{p.id}  {p.status.value:<17} {p.target:<10} {len(p.steps)} steps  {p.goal}")
        elif args.plan_cmd == "show":
            _print_plan(svc.get(args.plan_id), full=True)
        elif args.plan_cmd == "diff":
            for row in svc.diff(args.old_id, args.new_id):
                sign = {"same": " ", "added": "+", "removed": "-"}[row.op]
                _out(f"{sign} {row.old_command if row.op == 'removed' else row.new_command}")
    elif args.cmd == "approve":
        p = svc.approve(args.plan_id, args.hash, _human())
        _out(f"approved {p.id} · {p.hash} · signed {p.approval.signature.key_id if p.approval else '-'}")
    elif args.cmd == "approve-with-edits":
        p = svc.approve_with_edits(args.plan_id, [_parse_edit(e) for e in args.edit], _human())
        _out("edits submitted · policy and gatekeepers re-checked · new hash, approve again to run")
        _print_plan(p, full=True)
    elif args.cmd == "reject":
        p = svc.reject(args.plan_id, _human(), args.reason)
        _out(f"rejected {p.id}")
    elif args.cmd == "validate":
        env = svc.validate_for_dispatch(args.plan_id)
        _out(f"ok · {args.plan_id} · {env.plan_hash} · approval {env.approval.signature.key_id} verified")
    elif args.cmd == "expire":
        for p in svc.expire_due():
            _out(f"expired {p.id}")
    elif args.cmd == "audit":
        with Session(make_engine(home.db)) as s:
            if args.audit_cmd == "verify":
                res = audit.verify(s)
                if not res.ok:
                    _out(f"✕ hash chain broken at entry {res.bad_seq}: {res.reason}")
                    return 1
                _out(f"✓ Hash chain verified · {res.count} entries")
            else:
                lines = list(audit.export_jsonl(s))
                if args.out:
                    Path(args.out).write_text("".join(line + "\n" for line in lines), encoding="utf-8")
                else:
                    for line in lines:
                        _out(line)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    try:
        return run(sys.argv[1:] if argv is None else argv)
    except WardenError as exc:
        sys.stderr.write(f"refused ({exc.code}): {exc.message}\n")
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write(f"error: {exc}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
