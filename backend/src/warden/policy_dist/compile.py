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

# The approval trust agents enforce (README 10.0, D-12): end-to-end signing, the passkeys allowed to approve,
# and the WebAuthn relying party and origins their assertions must name. Not derived from policy.yaml: it is
# set by trust publishes (passkey added/removed, e2e toggled) and carried over by every other publish.
DEFAULT_TRUST: dict[str, Any] = {"e2e": False, "approvers": [], "webauthn": {"rp_id": "", "origins": []}}


def _limit(v: LimitValue) -> dict[str, Any]:
    return {"value": v.value, "group": v.group}


def compile_rules(
    rules: EffectiveRules, target: Target, trust: dict[str, Any] | None = None
) -> dict[str, Any]:
    t = trust if trust is not None else DEFAULT_TRUST
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
        "approvals": {
            "passkey": rules.passkey,
            "e2e": bool(t["e2e"]),
            "approvers": [dict(a) for a in t["approvers"]],
            "webauthn": {"rp_id": t["webauthn"]["rp_id"], "origins": list(t["webauthn"]["origins"])},
        },
        "gatekeepers": {"unanimous": rules.unanimous},
        "groups": list(rules.groups),
        "lockdown": rules.lockdown,
    }
