"""The M2, M3 and M4 flows exactly as a human runs them, as automated dry runs of docs/m2-demo.md,
docs/m3-demo.md and docs/m4-demo.md.

M2: `warden serve`, `warden agent add/confirm`, `warden-agent enroll` and `run`, then propose → approve →
`warden execute` → fail → revise, plus `warden ro` and `warden kill`.
M3: `warden-sign keygen`, `warden keys offline register`, tighten → pushed at once, loosen → pending →
`warden-sign sign` → `warden policy sign-upload`, lockdown and lift.
M4: `warden mcp add`, then Claude's whole loop over Streamable HTTP with a bearer token against the real
agent, a human approving with the CLI meanwhile; the stdio bridge; refusals without a token.
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
from typing import Any

import pytest
from harness import agent_binary, go_binary

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
        self.mcp_port = free_port()
        (self.cfg / "policy.yaml").write_text(
            "deny_paths: [/etc, /root, /home]\ncommands:\n  allow:\n    echo: {}\n    sleep: {}\n    ls: {}\n"
            '    "false": {}\n    "true": {}\n'
        )
        (self.cfg / "targets.yaml").write_text(f"- {{name: dev, workspace_roots: [{self.ws}]}}\n")
        (self.cfg / "settings.yaml").write_text(
            f"agents: {{listen_host: 127.0.0.1, listen_port: {self.port}, server_names: [127.0.0.1]}}\n"
            f"http: {{listen_host: 127.0.0.1, listen_port: {self.mcp_port}}}\n"
            "server: {public_url: 'https://warden.example.dk'}\n"
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

    def start(self) -> None:
        serve = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "warden.cli",
                "--home",
                str(self.home),
                "--config-dir",
                str(self.cfg),
                "serve",
            ],
            env={**os.environ, "PYTHONPATH": str(REPO / "backend/src")},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.procs.append(serve)
        wait_until((self.home / "admin.sock").exists)

    def enroll_and_run(self) -> str:
        token = next(t for t in self.warden("agent", "add", "dev").stdout.split() if t.startswith("wdn_enr_"))
        enroll = self.as_agent(
            "enroll",
            "--server",
            f"wss://127.0.0.1:{self.port}",
            "--token",
            token,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        assert enroll.stdout is not None
        fp = enroll.stdout.readline().decode().split(": ", 1)[1].strip()
        wait_until(lambda: fp in self.warden("agent", "pending").stdout)
        self.warden("agent", "confirm", "dev", "--fingerprint", fp)
        rest = enroll.stdout.read().decode()
        assert enroll.wait(timeout=30) == 0
        self.as_agent("run", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        wait_until(lambda: "● online" in self.warden("agent", "list").stdout)
        return rest

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
    assert "Published v1." in box.warden("policy", "publish").stdout
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


def test_m3_dry_run(box: Box) -> None:
    sign = go_binary("warden-sign")
    key, passfile = box.root / "offline.key", box.root / "pass"
    passfile.write_text("correct horse battery staple\n")

    def warden_sign(*args: str) -> str:
        res = subprocess.run(
            [str(sign), *args, "--passphrase-file", str(passfile)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert res.returncode == 0, res.stdout + res.stderr
        return res.stdout

    box.warden("init")
    created = warden_sign("keygen", "--out", str(key), "--scrypt-n", "16384")
    public = created.split("public: ")[1].split()[0]
    assert (
        "registered primary offline key"
        in box.warden("keys", "offline", "register", "--public", public).stdout
    )
    assert "Published v1." in box.warden("policy", "publish").stdout
    box.start()
    assert "Trusts offline key" in box.enroll_and_run()

    policy = box.cfg / "policy.yaml"
    base = policy.read_text()
    policy.write_text(base.replace("[/etc, /root, /home]", "[/etc, /root, /home, /srv/secret]"))
    out = box.warden("policy", "publish").stdout
    assert "↓ deny_paths add /srv/secret" in out
    assert "Published v2." in out
    assert "Pushed to 1 connected agent(s)" in out
    wait_until(lambda: "dev          ✓ v2" in box.warden("policy", "status").stdout, timeout=5)

    policy.write_text(base)  # removing /srv/secret again loosens
    out = box.warden("policy", "publish").stdout
    assert "v3 loosens dev" in out
    assert "pending v3" in box.warden("policy", "status").stdout
    pf = box.root / "bundle-v3.json"
    box.warden("policy", "pending", "--out", str(pf))
    bad = box.warden("policy", "sign-upload", str(pf), check=False)  # not a signature file
    assert bad.returncode == 1
    signed = warden_sign("sign", str(pf), "--key", str(key), "--yes")
    assert "loosen deny_paths remove /srv/secret" in signed
    out = box.warden("policy", "sign-upload", str(box.root / "bundle-v3.sig.json")).stdout
    assert "Published v3." in out
    wait_until(lambda: "dev          ✓ v3" in box.warden("policy", "status").stdout, timeout=5)

    out = box.warden("lockdown").stdout
    assert "LOCKDOWN · policy v4" in out
    wait_until(lambda: "dev          ✓ v4" in box.warden("policy", "status").stdout, timeout=5)
    p = box.plan("p-lock", "echo locked")
    box.approve(p)
    assert "held · lockdown" in box.warden("execute", p).stdout
    assert "LOCKDOWN" in box.warden("policy", "status").stdout

    assert "v5 loosens dev" in box.warden("lockdown", "lift").stdout
    pf5 = box.root / "bundle-v5.json"
    box.warden("policy", "pending", "--out", str(pf5))
    warden_sign("sign", str(pf5), "--key", str(key), "--yes")
    box.warden("policy", "sign-upload", str(box.root / "bundle-v5.sig.json"))
    wait_until(lambda: "succeeded" in box.warden("plan", "show", p).stdout, timeout=10)
    assert "LOCKDOWN" not in box.warden("policy", "status").stdout
    assert "Hash chain verified" in box.warden("audit", "verify").stdout


def test_m4_dry_run(box: Box) -> None:
    import asyncio
    import threading

    import httpx2
    from mcp import Client, StdioServerParameters
    from mcp.client.streamable_http import streamable_http_client

    box.warden("init")
    box.warden("policy", "publish")
    out = box.warden("mcp", "add", "claude-code").stdout
    token = next(t for t in out.split() if t.startswith("wdn_mcp_"))
    assert "claude mcp add --transport http warden https://warden.example.dk/mcp" in out
    assert "claude-code" in box.warden("mcp", "list").stdout
    box.start()
    box.enroll_and_run()
    url = f"http://127.0.0.1:{box.mcp_port}/mcp"
    wait_until(lambda: httpx2.get(f"http://127.0.0.1:{box.mcp_port}/healthz").status_code in (200, 404))

    # No token, a wrong token or a foreign Host never reach the MCP layer.
    init = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert httpx2.post(url, json=init).status_code == 401
    assert httpx2.post(url, json=init, headers={"Authorization": "Bearer wdn_mcp_nope"}).status_code == 401
    foreign = httpx2.post(
        url, json=init, headers={"Authorization": f"Bearer {token}", "Host": "evil.example.com"}
    )
    assert foreign.status_code in (403, 421)

    def data(r: Any) -> dict[str, Any]:
        assert not r.is_error, r.content
        sc = r.structured_content
        return sc.get("result", sc) if set(sc) == {"result"} else sc

    def approve_later(plan_id: str) -> threading.Thread:
        def go() -> None:
            time.sleep(1)
            box.approve(plan_id)

        t = threading.Thread(target=go)
        t.start()
        return t

    def step(n: int, command: str) -> dict[str, Any]:
        return {
            "n": n,
            "kind": "shell",
            "command": command,
            "purpose": f"Step {n}",
            "cwd": str(box.ws),
            "timeout_s": 60,
        }

    async def claude() -> None:
        http = httpx2.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, timeout=httpx2.Timeout(30, read=300)
        )
        async with http, Client(streamable_http_client(url, http_client=http)) as c:
            names = sorted(t.name for t in (await c.list_tools()).tools)
            assert names == sorted(
                [
                    "propose_plan",
                    "get_plan",
                    "wait_for_approval",
                    "execute_plan",
                    "diff_plans",
                    "read_only",
                    "list_resources",
                    "post_diagnosis",
                ]
            )
            res = data(await c.call_tool("list_resources", {}))
            assert res["targets"][0]["target"] == "dev"
            assert res["targets"][0]["online"] is True

            p = data(
                await c.call_tool(
                    "propose_plan",
                    {
                        "goal": "M4 dry run",
                        "target": "dev",
                        "steps": [step(1, "echo step one"), step(2, "false")],
                    },
                )
            )
            assert p["status"] == "awaiting_approval"
            assert p["requested_by"] == "claude-code"
            t = approve_later(p["plan_id"])
            waited = data(await c.call_tool("wait_for_approval", {"plan_id": p["plan_id"], "timeout_s": 60}))
            await asyncio.to_thread(t.join)
            assert waited["status"] == "approved"

            done = data(await c.call_tool("execute_plan", {"plan_id": p["plan_id"]}))
            assert done["status"] == "failed"
            assert done["failed_at"] == 2
            assert "step one" in done["steps"][0]["output_untrusted"]["text"]

            ro = data(await c.call_tool("read_only", {"target": "dev", "command": f"ls {box.ws}"}))
            assert ro["ok"] is True
            diag = data(
                await c.call_tool(
                    "post_diagnosis",
                    {
                        "plan_id": p["plan_id"],
                        "note": "Step 2 is `false`; drop it.",
                        "read_only_audit_ids": [ro["audit_id"]],
                    },
                )
            )
            assert diag["evidence"][0]["command"] == f"ls {box.ws}"

            r = data(
                await c.call_tool(
                    "propose_plan",
                    {
                        "goal": "M4 dry run",
                        "target": "dev",
                        "revises": p["plan_id"],
                        "steps": [step(1, "echo step one"), step(2, "true")],
                    },
                )
            )
            diff = data(await c.call_tool("diff_plans", {"old_id": p["plan_id"], "new_id": r["plan_id"]}))
            assert [row["op"] for row in diff["rows"]] == ["same", "removed", "added"]
            assert (
                "not_approved"
                in (await c.call_tool("execute_plan", {"plan_id": r["plan_id"]})).content[0].text
            )
            t = approve_later(r["plan_id"])
            await c.call_tool("wait_for_approval", {"plan_id": r["plan_id"], "timeout_s": 60})
            await asyncio.to_thread(t.join)
            ok = data(await c.call_tool("execute_plan", {"plan_id": r["plan_id"]}))
            assert ok["status"] == "succeeded"

        # The stdio bridge, as a stdio-only client would start it.
        token_file = box.root / "mcp-token"
        token_file.write_text(token + "\n")
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "warden.cli", "mcp", "stdio", "--url", url, "--token-file", str(token_file)],
            env={**os.environ, "PYTHONPATH": str(REPO / "backend/src")},
        )
        async with Client(params) as c:
            got = data(await c.call_tool("get_plan", {"plan_id": r["plan_id"]}))
            assert got["status"] == "succeeded"

    asyncio.run(claude())
    log = box.warden("audit", "export").stdout
    assert '"actor":"claude-code"' in log
    assert "diagnosis_posted" in log
    box.warden("mcp", "revoke", "claude-code")
    assert httpx2.post(url, json=init, headers={"Authorization": f"Bearer {token}"}).status_code == 401
