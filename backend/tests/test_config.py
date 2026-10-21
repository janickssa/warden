from __future__ import annotations

from pathlib import Path

import pytest

from warden.config import (
    load_policy,
    load_settings,
    load_targets,
    parse_policy,
    parse_settings,
    parse_targets,
)
from warden.errors import ConfigError

CONFIG = Path(__file__).resolve().parents[2] / "config"


def test_example_files_load() -> None:
    policy = load_policy(CONFIG / "policy.example.yaml")
    targets = load_targets(CONFIG / "targets.example.yaml")
    settings = load_settings(CONFIG / "settings.example.yaml")
    assert "git" in policy.commands.allow
    assert policy.groups["high-security"].limits.plan_max_steps == 10
    assert targets.get("dev") is not None
    assert settings.approvals.expiry_min == 30


@pytest.mark.parametrize(
    "text",
    [
        "deny_paths: [/etc]\ndeny_paths: []\n",  # duplicate key would silently drop /etc
        "commands:\n  allow:\n    git: {}\n    git: {subcommands: [push]}\n",
        "unknown_field: 1\n",
        "commands:\n  allow:\n    git: {subcommands: [clone], extra: 1}\n",
        "commands:\n  deny_patterns: ['([unclosed']\n",
        "deny_paths: [relative/path]\n",
        "deny_paths: [/srv/../etc]\n",
        "network:\n  git_hosts: ['github.com/evil']\n",
        "limits:\n  step_timeout_s: 0\n",
        "groups:\n  g:\n    limits: {plan_max_steps: 26}\n",  # above global 25
        "groups:\n  g:\n    commands: {allow: {rm: {}}}\n",  # groups can't add allows
        "groups:\n  g:\n    members: [a, a]\n",
        "- just\n- a list\n",
        "!!python/object/apply:os.system ['id']\n",
    ],
)
def test_bad_policy_refused(text: str) -> None:
    with pytest.raises(ConfigError):
        parse_policy(text)


@pytest.mark.parametrize(
    "text",
    [
        "- {name: dev, workspace_roots: [/]}\n",
        "- {name: dev, workspace_roots: [/etc/app]}\n",
        "- {name: dev, workspace_roots: [/usr/local/x]}\n",
        "- {name: dev, workspace_roots: []}\n",
        "- {name: Dev, workspace_roots: [/srv/dev]}\n",
        "- {name: dev, workspace_roots: [/srv/dev]}\n- {name: dev, workspace_roots: [/srv/x]}\n",
        "- {name: dev, workspace_roots: [/srv/dev], ssh: {host: x}}\n",
    ],
)
def test_bad_targets_refused(text: str) -> None:
    with pytest.raises(ConfigError):
        parse_targets(text)


def test_bad_settings_refused() -> None:
    with pytest.raises(ConfigError):
        parse_settings("approvals:\n  approve_all: true\n")
