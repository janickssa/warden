"""Compile effective rules (global + groups, README 7B) into the JSON an agent enforces.

The agent never reads YAML and never merges groups itself: it gets one compiled, signed rule set for its own
target. The same JSON feeds policy-fixtures/compiled/, so the Go engine runs the shared corpus against
exactly what a bundle would contain.
"""

from __future__ import annotations

from typing import Any

from warden.policy.effective import EffectiveRules, LimitValue
from warden.policy.schema import Target

RULES_SCHEMA = 1


def _limit(v: LimitValue) -> dict[str, Any]:
    return {"value": v.value, "group": v.group}


def compile_rules(rules: EffectiveRules, target: Target) -> dict[str, Any]:
    return {
        "schema": RULES_SCHEMA,
        "target": rules.target,
        "workspace_roots": list(rules.workspace_roots),
        "docker_socket": target.docker_socket,
        "deny_paths": list(rules.deny_paths),
        "allow": {
            name: {
                "subcommands": list(rule.subcommands) if rule.subcommands is not None else None,
                "flags_deny": list(rule.flags_deny),
            }
            for name, rule in sorted(rules.allow.items())
        },
        "deny_patterns": [{"source": p.source, "group": p.group} for p in rules.deny_patterns],
        "allowed_projects": list(rules.allowed_projects),
        "denied_containers": list(rules.denied_containers),
        "git_hosts": list(rules.git_hosts),
        "http_check_hosts": list(rules.http_check_hosts),
        "limits": {
            "step_timeout_s": _limit(rules.step_timeout_s),
            "plan_max_steps": _limit(rules.plan_max_steps),
            "output_cap_mb": _limit(rules.output_cap_mb),
        },
        "read_only": {
            "mode": rules.read_only_mode.label,
            "group": rules.read_only_mode_group,
            "deny_paths": [{"path": p, "group": g} for p, g in rules.read_only_deny_paths],
        },
        "approvals": {"passkey": rules.passkey},
        "gatekeepers": {"unanimous": rules.unanimous},
        "groups": list(rules.groups),
        "lockdown": rules.lockdown,
    }
