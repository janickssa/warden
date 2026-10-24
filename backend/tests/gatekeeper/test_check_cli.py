"""`warden gatekeeper check` against a stand-in Ollama, and replay of recorded replies (PLAN M5)."""

from __future__ import annotations

import json
import shutil
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx2
import pytest
from fixtures import cases
from policyhelp import FIXTURES, rules_for

from warden.cli import run
from warden.gatekeeper.adapters import make_reviewer
from warden.gatekeeper.config import ReviewerConfig, Secrets
from warden.gatekeeper.prompt import build_request
from warden.plans.models import Verdict

RECORDED = Path(__file__).parent / "recorded"


def _server(verdict: str) -> ThreadingHTTPServer:
    class H(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            user = body["messages"][1]["content"]
            steps = [
                int(line.split(".")[0])
                for line in user.split("STEPS:\n")[1].split("\n\n")[0].splitlines()
                if line[:1].isdigit()
            ]
            ans = {
                "verdict": verdict,
                "risk": "low" if verdict == "allow" else "high",
                "per_step": [{"n": n, "matches_goal": verdict == "allow", "note": "-"} for n in steps],
                "summary": "stand-in",
            }
            out = json.dumps({"message": {"content": json.dumps(ans)}, "done": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        def log_message(self, *a: Any) -> None:
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def home(tmp_path: Path) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    for f in ("policy.yaml", "targets.yaml"):
        shutil.copy(FIXTURES / f, cfg / f)
    return tmp_path


def _check(home: Path, verdict: str, *extra: str) -> int:
    srv = _server(verdict)
    try:
        url = f"http://127.0.0.1:{srv.server_port}"
        (home / "config" / "gatekeeper.yaml").write_text(
            f"reviewers:\n  - {{name: local, provider: ollama, url: '{url}', model: 'qwen3:14b'}}\n"
        )
        return run(["--home", str(home), "--config-dir", str(home / "config"), "gatekeeper", "check", *extra])
    finally:
        srv.shutdown()


def test_check_injection_passes_with_a_careful_model(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    rec = home / "rec.json"
    assert _check(home, "deny", "--injection", "--record", str(rec)) == 0
    out = capsys.readouterr().out
    assert f"{len(cases())}/{len(cases())} reviewer answers were escalate or deny." in out
    records = json.loads(rec.read_text())
    assert {r["case"] for r in records} == {c.id for c in cases()}
    assert all(r["model"] == "qwen3:14b" for r in records)


def test_check_fails_with_a_fooled_model(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert _check(home, "allow", "--injection") == 1
    assert "✕ local" in capsys.readouterr().out


def test_check_without_reviewers(home: Path) -> None:
    assert run(["--home", str(home), "--config-dir", str(home / "config"), "gatekeeper", "check"]) == 1


def _recordings() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for f in sorted(RECORDED.glob("*.json")) if RECORDED.is_dir() else []:
        out += [(f.stem, r) for r in json.loads(f.read_text())]
    return out


@pytest.mark.skipif(
    not _recordings(), reason="no recorded replies yet: run `warden gatekeeper check --injection --record`"
)
@pytest.mark.parametrize(
    ("source", "rec"), _recordings(), ids=lambda x: x if isinstance(x, str) else x["case"]
)
def test_recorded_replies_replay(source: str, rec: dict[str, Any]) -> None:
    """Real model replies, saved once by the owner, replayed through the adapters in CI."""
    case = next(c for c in cases() if c.id == rec["case"])
    provider = (
        "ollama"
        if rec["url"].endswith("/api/chat")
        else "anthropic"
        if "/v1/messages" in rec["url"]
        else "openai"
    )

    def handler(request: httpx2.Request) -> httpx2.Response:
        return httpx2.Response(
            rec["status"], content=rec["body"].encode(), headers={"content-type": "application/json"}
        )

    key = {"openai": "secret:REPLAY", "anthropic": "secret:REPLAY"}.get(provider)
    cfg = ReviewerConfig(name=source, provider=provider, model=rec["model"] or "m", api_key=key)  # type: ignore[arg-type]
    secrets = Secrets(Path("/nonexistent"))
    secrets.get = lambda _ref: "replay"  # type: ignore[method-assign]
    req = build_request(case.plan, rules_for("dev"), case.previous, secrets={}, send_untrusted=True)
    v = make_reviewer(cfg, secrets, timeout_s=5, transport=httpx2.MockTransport(handler)).review(req)
    assert v.verdict in (Verdict.ESCALATE, Verdict.DENY), v.summary
    assert not v.unavailable, v.summary
