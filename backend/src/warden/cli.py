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
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError
from sqlmodel import Session

from warden import audit
from warden.actors import ClaudeActor, HumanActor
from warden.agents import Registry
from warden.ca import CA
from warden.config import load_policy, load_settings, load_targets
from warden.daemon import Daemon, admin_request
from warden.db import make_engine
from warden.errors import ConfigError, WardenError
from warden.keys import OnlineKey
from warden.plans.models import Plan, PlanStatus, ProposeRequest, StepEdit
from warden.plans.service import Config, PlanService
from warden.policy_dist import bundle as bundles
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
        return Config(
            policy=load_policy(self.config_dir / "policy.yaml"),
            targets=load_targets(self.config_dir / "targets.yaml"),
            settings=load_settings(self.config_dir / "settings.yaml"),
        )

    def service(self) -> PlanService:
        self.check_private()
        cfg = self.config()  # validate once up front so errors show before anything else
        engine = make_engine(self.db)
        os.chmod(self.db, 0o600)
        return PlanService(engine, config=lambda: cfg, approval_key=ApprovalKey.load(self.key))


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
    elif p.gatekeepers:
        for g in p.gatekeepers:
            shown = "○ Unavailable · counted as escalate" if g.unavailable else g.verdict.value
            _out(f"  gatekeeper {g.name} ({g.model}): {shown} · {g.risk.value} · {g.summary}")
    else:
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
    polsub.add_parser("publish", help="sign and publish each target's first policy bundle")

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


def _publish(home: Home) -> int:
    home.check_private()
    cfg = home.config()
    engine = make_engine(home.db)
    with Session(engine) as s, s.begin():
        published = bundles.publish_initial(
            s,
            policy=cfg.policy,
            targets=cfg.targets,
            online=OnlineKey.load(home.online_key),
            approval=ApprovalKey.load(home.key),
            now=datetime.now(UTC),
            actor=_human().label,
        )
    _out(
        f"published v1 for {', '.join(published)}"
        if published
        else "nothing to publish: every target is current"
    )
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
    if args.cmd == "policy" and args.policy_cmd == "publish":
        return _publish(home)
    if args.cmd == "agent":
        return _agent(home, args)
    if args.cmd == "serve":
        home.check_private()
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
        asyncio.run(Daemon(home.path, home.config()).run())
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
