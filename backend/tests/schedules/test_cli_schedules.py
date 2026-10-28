"""`warden schedule list|show|pause|resume|delete` (no create or approve: those need the dashboard)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from clihelp import Cli, step

from warden.actors import HumanActor
from warden.cli import Home
from warden.db import make_engine
from warden.keys import b64url
from warden.plans.models import PasskeyAssertion
from warden.plans.runs import StepOutcome
from warden.schedules import grant
from warden.schedules.service import ScheduleService
from warden.signing import ApprovalKey

DASH = HumanActor("dashboard", "alice")


@pytest.fixture
def cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Cli:
    c = Cli(tmp_path, capsys)
    c.ok("init")
    return c


def test_schedule_commands(cli: Cli) -> None:
    assert "No schedules" in cli.ok("schedule", "list")
    out = cli.ok(
        "plan",
        "propose",
        "--file",
        cli.plan_file("p.json", {"goal": "Nightly tests", "target": "dev", "steps": [step(1, "npm test")]}),
    )
    pid = out.split()[0]
    home = Home(cli.home, cli.config)
    plans = home.service()
    p = plans.approve(pid, plans.get(pid).hash, HumanActor("cli", "alice"))
    plans.start_run(p.id)
    plans.finish_run(p.id, [StepOutcome(n=1, exit_code=0)])
    svc = ScheduleService(
        make_engine(home.db), plans, approval_key=ApprovalKey.load(home.key), default_days=lambda: 90
    )
    sch = svc.create(pid, name="nightly", cron="0 3 * * *", days=90, actor=DASH)
    at = datetime.now(UTC)
    challenge = b64url(hashlib.sha256(grant.message(svc.payload_for(sch.id, DASH, at))).digest())
    client = b64url(json.dumps({"challenge": challenge}).encode())
    svc.approve(
        sch.id,
        DASH,
        passkey=PasskeyAssertion(
            credential_id="c", authenticator_data="A", client_data_json=client, signature="A"
        ),
        at=at,
    )

    listing = cli.ok("schedule", "list")
    assert "nightly" in listing
    assert "Every day at 03:00" in listing
    shown = cli.ok("schedule", "show", "nightly")
    assert "$ npm test" in shown
    assert sch.row.template_hash in shown
    assert "paused" in cli.ok("schedule", "pause", "nightly")
    assert svc.get(sch.id).status == "paused"
    cli.ok("schedule", "resume", sch.id)
    assert svc.get(sch.id).status == "active"
    cli.ok("schedule", "delete", "nightly")
    code, _, err = cli("schedule", "show", "nightly")
    assert code != 0
    assert "no single schedule" in err
