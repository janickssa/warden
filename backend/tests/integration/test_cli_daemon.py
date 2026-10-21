"""The M2 flow exactly as a human runs it: `warden serve`, `warden agent add/confirm`, `warden-agent enroll`
and `run`, then propose → approve → `warden execute` → fail → revise, plus `warden ro` and `warden kill`.
This is the automated dry run of docs/m2-demo.md.
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from harness import agent_binary

pytestmark = pytest.mark.skipif(
    shutil.which("go") is None or os.geteuid() != 0, reason="needs Go and root (to run the agent as nobody)"
)

REPO = Path(__file__).resolve().parents[3]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Box:
    def __init__(self) -> None:
        self.user = pwd.getpwnam("nobody")
        self.root = Path(tempfile.mkdtemp(prefix="warden-cli-it-"))
        os.chmod(self.root, 0o755)
        self.home, self.cfg, self.ws, self.state = (
            self.root / d for d in ("home", "config", "ws", "agent-state")
        )
        self.cfg.mkdir()
        self.ws.mkdir()
        os.chown(self.ws, self.user.pw_uid, self.user.pw_gid)
        self.state.mkdir(mode=0o700)
        os.chown(self.state, self.user.pw_uid, self.user.pw_gid)
        self.port = free_port()
        (self.cfg / "policy.yaml").write_text(
            "deny_paths: [/etc, /root, /home]\ncommands:\n  allow:\n    echo: {}\n    sleep: {}\n    ls: {}\n"
            '    "false": {}\n    "true": {}\n'
        )
        (self.cfg / "targets.yaml").write_text(f"- {{name: dev, workspace_roots: [{self.ws}]}}\n")
        (self.cfg / "settings.yaml").write_text(
            f"agents: {{listen_host: 127.0.0.1, listen_port: {self.port}, server_names: [127.0.0.1]}}\n"
        )
        self.procs: list[subprocess.Popen[bytes]] = []

    def warden(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        res = subprocess.run(  # noqa: PLW1510 - the caller decides via `check`
            [
                sys.executable,
                "-m",
                "warden.cli",
                "--home",
                str(self.home),
                "--config-dir",
                str(self.cfg),
                *args,
            ],
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, "PYTHONPATH": str(REPO / "backend/src")},
        )
        if check:
            assert res.returncode == 0, res.stdout + res.stderr
        return res

    def as_agent(
        self, *args: str, stdout: int | None = None, stderr: int | None = None
    ) -> subprocess.Popen[bytes]:
        p = subprocess.Popen(
            [str(agent_binary()), *args, "--state", str(self.state)],
            user=self.user.pw_uid,
            group=self.user.pw_gid,
            env={"HOME": str(self.state), "PATH": "/usr/bin:/bin"},
            stdout=stdout,
            stderr=stderr,
        )
        self.procs.append(p)
        return p

    def plan(self, name: str, *commands: str, revises: str | None = None) -> str:
        steps = [
            {
                "n": i,
                "kind": "shell",
                "command": c,
                "purpose": f"Step {i}",
                "cwd": str(self.ws),
                "timeout_s": 60,
            }
            for i, c in enumerate(commands, 1)
        ]
        path = self.root / f"{name}.json"
        path.write_text(
            json.dumps({"goal": "M2 dry run", "target": "dev", "steps": steps, "revises": revises})
        )
        out = self.warden("plan", "propose", "--as", "claude-code", "--file", str(path)).stdout
        return out.split()[0]

    def approve(self, plan_id: str) -> None:
        show = self.warden("plan", "show", plan_id).stdout
        h = next(line.split()[1] for line in show.splitlines() if line.strip().startswith("hash:"))
        self.warden("approve", plan_id, "--hash", h[7:19])


@pytest.fixture
def box() -> Iterator[Box]:
    b = Box()
    try:
        yield b
    finally:
        for p in b.procs:
            p.kill()
            p.wait()
        shutil.rmtree(b.root, ignore_errors=True)


def wait_until(cond: object, timeout: float = 20) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if cond():  # type: ignore[operator]
            return
        time.sleep(0.1)
    raise AssertionError("timed out")


def test_m2_dry_run(box: Box) -> None:
    box.warden("init")
    assert "published v1 for dev" in box.warden("policy", "publish").stdout
    serve = subprocess.Popen(
        [sys.executable, "-m", "warden.cli", "--home", str(box.home), "--config-dir", str(box.cfg), "serve"],
        env={**os.environ, "PYTHONPATH": str(REPO / "backend/src")},
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    box.procs.append(serve)
    wait_until((box.home / "admin.sock").exists)
    assert (box.home / "admin.sock").stat().st_mode & 0o777 == 0o600

    token = next(t for t in box.warden("agent", "add", "dev").stdout.split() if t.startswith("wdn_enr_"))
    enroll = box.as_agent(
        "enroll",
        "--server",
        f"wss://127.0.0.1:{box.port}",
        "--token",
        token,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    assert enroll.stdout is not None
    fp = enroll.stdout.readline().decode().split(": ", 1)[1].strip()
    wait_until(lambda: fp in box.warden("agent", "pending").stdout)
    box.warden("agent", "confirm", "dev", "--fingerprint", fp)
    assert enroll.wait(timeout=30) == 0

    box.as_agent("run", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    wait_until(lambda: "● online" in box.warden("agent", "list").stdout)

    first = box.plan("p1", "echo step one", "false", "echo never")
    box.approve(first)
    res = box.warden("execute", first, check=False)
    assert res.returncode == 1
    assert "failed at step 2 (exit_code)" in res.stdout

    second = box.plan("p2", "echo step one", "true", "echo fixed", revises=first)
    assert box.warden("plan", "diff", first, second).stdout.splitlines()[1] == "- false"
    box.approve(second)
    assert "succeeded" in box.warden("execute", second).stdout

    (box.ws / "hello.txt").write_text("hej\n")
    assert "hello.txt" in box.warden("ro", "dev", f"ls {box.ws}").stdout
    refused = box.warden("ro", "dev", "ls /etc", check=False)
    assert refused.returncode == 1
    assert "denied_path" in refused.stdout

    long_ = box.plan("p3", "sleep 60")
    box.approve(long_)
    runner = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "warden.cli",
            "--home",
            str(box.home),
            "--config-dir",
            str(box.cfg),
            "execute",
            long_,
        ],
        env={**os.environ, "PYTHONPATH": str(REPO / "backend/src")},
        stdout=subprocess.PIPE,
        text=True,
    )
    wait_until(lambda: "running" in box.warden("plan", "show", long_).stdout)
    time.sleep(0.5)
    box.warden("kill", long_)
    out, _ = runner.communicate(timeout=30)
    assert "cancelled" in out

    box.warden("agent", "revoke", "dev")
    wait_until(lambda: "● online" not in box.warden("agent", "list").stdout)
    assert "Hash chain verified" in box.warden("audit", "verify").stdout
