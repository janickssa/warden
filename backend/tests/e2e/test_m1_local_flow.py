"""M1 Done-when: plans propose, approve and validate locally (README section 15).

Drives the real `warden` CLI in-process. Execution needs the agent (M2), so the failed run in the middle is
recorded through the plan service exactly as the M2 dispatcher will do it.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from clihelp import Cli, step

from warden.cli import Home
from warden.plans.runs import StepOutcome

GOAL = "Deploy myapp on dev and verify HTTP health"
STEPS = [
    step(1, "git clone https://github.com/you/myapp /srv/dev/myapp", "git", "/srv/dev"),
    step(2, "git -C /srv/dev/myapp checkout v1.4.2", "git"),
    step(3, "npm ci"),
    step(4, "docker compose -p dev-myapp up -d --build", "docker"),
    step(5, "curl -I http://localhost:8080/health", "http_check"),
]


def test_propose_approve_validate_fail_revise(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    cli = Cli(tmp_path, capsys)
    cli.ok("init")

    # 1. Claude (simulated) proposes; policy passes; no gatekeepers yet, so the verdict is escalate.
    out = cli.ok(
        "plan",
        "propose",
        "--as",
        "claude-code",
        "--file",
        cli.plan_file("p1.json", {"goal": GOAL, "target": "dev", "steps": STEPS}),
    )
    first = out.split()[0]
    assert "awaiting_approval" in out
    assert "final verdict: escalate" in out

    # 2. A human approves with the hash prefix; validation (everything before dispatch) passes.
    h1 = Cli.field(cli.ok("plan", "show", first), "hash:")
    cli.ok("approve", first, "--hash", h1[7:19])
    assert "verified" in cli.ok("validate", first)

    # 3. Tampering with the approved plan in the database is caught before dispatch.
    db = cli.home / "warden.db"
    with sqlite3.connect(db) as conn:
        (body,) = conn.execute("SELECT body FROM plans WHERE id=?", (first,)).fetchone()
        conn.execute("UPDATE plans SET body=? WHERE id=?", (body.replace("npm ci", "npm test"), first))
    code, _, err = cli("validate", first)
    assert code == 1
    assert "hash_mismatch" in err
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE plans SET body=? WHERE id=?", (body, first))
    cli.ok("validate", first)

    # 4. The run fails at step 3 (npm ci exits 1); the rest is skipped (what the M2 dispatcher records).
    svc = Home(cli.home, cli.config).service()
    svc.start_run(first)
    failed = svc.finish_run(first, [StepOutcome(1, 0), StepOutcome(2, 0), StepOutcome(3, 1)])
    shown = cli.ok("plan", "show", first)
    assert "failed" in shown
    assert "[skipped]" in shown
    assert failed.failed_at == 3

    # 5. A failed plan can't be approved or validated again; Claude proposes a revision.
    assert cli("approve", first, "--hash", h1[7:19])[0] == 1
    assert cli("validate", first)[0] == 1
    revised = [STEPS[1], step(0, "npm install --package-lock-only"), *STEPS[2:]]
    revised = [{**s, "n": i} for i, s in enumerate(revised, 1)]
    out = cli.ok(
        "plan",
        "propose",
        "--as",
        "claude-code",
        "--file",
        cli.plan_file("p2.json", {"goal": GOAL, "target": "dev", "steps": revised, "revises": first}),
    )
    second = out.split()[0]
    assert f"revises: {first}" in out

    # 6. The human sees the diff, approves the revision, and it validates.
    diff = cli.ok("plan", "diff", first, second).splitlines()
    assert diff[0].startswith("- git clone")
    assert "+ npm install --package-lock-only" in diff
    h2 = Cli.field(cli.ok("plan", "show", second), "hash:")
    assert h2 != h1
    cli.ok("approve", second, "--hash", h2[7:19])
    cli.ok("validate", second)

    # 7. The audit log recorded everything and the hash chain verifies.
    assert "Hash chain verified" in cli.ok("audit", "verify")
    actions = [json.loads(line)["action"] for line in cli.ok("audit", "export").splitlines()]
    for expected in (
        "propose_plan",
        "review",
        "approve",
        "dispatch_refused",
        "run_started",
        "step_failed",
        "run_finished",
    ):
        assert expected in actions
