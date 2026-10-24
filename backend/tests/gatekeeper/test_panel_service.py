"""The panel inside PlanService: verdicts land on the plan, and revisions carry the real failure context."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx2
from sqlalchemy import Engine
from sqlmodel import Session
from svc import ALICE, World

from warden import audit
from warden.actors import ClaudeActor
from warden.dispatch import outputs
from warden.gatekeeper.config import GatekeeperConfig, ReviewerConfig, Secrets
from warden.gatekeeper.panel import ReviewPanel, previous_context
from warden.plans import diagnosis
from warden.plans.models import PlanStatus, Verdict
from warden.plans.runs import StepOutcome
from warden.signing import ApprovalKey


def test_revision_review_sees_output_and_notes(engine: Engine, tmp_path: Path) -> None:
    bodies: list[dict[str, Any]] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        body = json.loads(request.content)
        bodies.append(body)
        user = body["messages"][1]["content"]
        steps = sorted(
            {
                int(x.split(".")[0])
                for x in user.split("STEPS:\n")[1].split("\n\n")[0].splitlines()
                if x[:1].isdigit()
            }
        )
        ans = {
            "verdict": "escalate",
            "risk": "medium",
            "per_step": [{"n": n, "matches_goal": True, "note": ""} for n in steps],
            "summary": "Check the lockfile step.",
        }
        return httpx2.Response(200, json={"message": {"content": json.dumps(ans)}, "done": True})

    cfg = GatekeeperConfig(reviewers=(ReviewerConfig(name="local", provider="ollama", model="qwen3:14b"),))
    panel = ReviewPanel(
        cfg,
        Secrets(tmp_path / "secrets"),
        context=previous_context(engine),
        transport=httpx2.MockTransport(handler),
    )
    w = World(engine=engine, key=ApprovalKey.generate(tmp_path / "k"), panel=panel)

    first = w.propose("npm ci")
    assert {g.name for g in first.gatekeepers} == {"injection-scan", "local"}
    assert first.final_verdict == Verdict.ESCALATE
    w.svc.approve(first.id, first.hash, ALICE)
    w.svc.start_run(first.id)
    with Session(engine) as s, s.begin():
        outputs.append(s, plan_id=first.id, n=1, seq=1, stream="stderr", data="npm ERR! missing lockfile\n")
    w.svc.finish_run(first.id, [StepOutcome(n=1, exit_code=1)])
    assert w.svc.get(first.id).status == PlanStatus.FAILED
    with Session(engine) as s, s.begin():
        seq = audit.append(
            s,
            ts=w.clock(),
            actor="claude-code",
            action="read_only",
            subject="dev · ls",
            detail={
                "target": "dev",
                "command": "ls /srv/dev/myapp",
                "exit_code": 0,
                "output": "package.json\n",
            },
        ).seq
    diagnosis.post(
        engine,
        plan_id=first.id,
        note="No lockfile in the repo.",
        audit_ids=[seq],
        actor=ClaudeActor("claude-code"),
        now=w.clock(),
    )

    w.propose("npm install --package-lock-only", "npm ci", revises=first.id)
    user = bodies[-1]["messages"][1]["content"]
    assert f"THIS PLAN REVISES {first.id}" in user
    for text in ("npm ERR! missing lockfile", "No lockfile in the repo.", "package.json"):
        idx = user.index(text)
        assert user.rfind("<untrusted", 0, idx) > user.rfind("</untrusted>", 0, idx)
