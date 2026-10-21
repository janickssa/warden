"""Run the `warden` CLI in-process against a temporary Warden home."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from warden.cli import main

REPO = Path(__file__).resolve().parents[2]


class Cli:
    def __init__(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        self.home = tmp_path / "home"
        self.config = tmp_path / "config"
        self.config.mkdir()
        shutil.copy(REPO / "config/policy.example.yaml", self.config / "policy.yaml")
        shutil.copy(REPO / "config/targets.example.yaml", self.config / "targets.yaml")
        shutil.copy(REPO / "config/settings.example.yaml", self.config / "settings.yaml")
        self.tmp = tmp_path
        self.capsys = capsys

    def __call__(self, *args: str) -> tuple[int, str, str]:
        code = main(["--home", str(self.home), "--config-dir", str(self.config), *args])
        out, err = self.capsys.readouterr()
        return code, out, err

    def ok(self, *args: str) -> str:
        code, out, err = self(*args)
        assert code == 0, err
        return out

    def plan_file(self, name: str, plan: dict[str, Any]) -> str:
        path = self.tmp / name
        path.write_text(json.dumps(plan), encoding="utf-8")
        return str(path)

    @staticmethod
    def field(out: str, label: str) -> str:
        line = next(line for line in out.splitlines() if line.strip().startswith(label))
        return line.split(label, 1)[1].strip()


def step(n: int, command: str, kind: str = "shell", cwd: str = "/srv/dev/myapp") -> dict[str, Any]:
    return {"n": n, "kind": kind, "command": command, "purpose": f"Step {n}", "cwd": cwd, "timeout_s": 120}
