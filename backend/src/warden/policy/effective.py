"""Effective rules for one target = global policy + every group it belongs to (README 7B).

Groups only add restrictions: deny lists are unioned, limits take the minimum, the read-only mode takes the
strictest, and passkey/unanimous are OR-ed. Nothing in a group can add an allowed command, host or project
(the schema has no such fields), so the result is never looser than the global policy.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from warden.policy.schema import BinaryRule, Policy, ReadOnlyMode, Target


@dataclass(frozen=True, slots=True)
class DenyPattern:
    source: str
    regex: re.Pattern[str]
    group: str | None  # None = global policy


@dataclass(frozen=True, slots=True)
class LimitValue:
    value: int
    group: str | None  # the group that lowered it, if any


@dataclass(frozen=True)
class EffectiveRules:
    target: str
    policy_version: int
    workspace_roots: tuple[str, ...]
    deny_paths: tuple[str, ...]
    allow: Mapping[str, BinaryRule]
    deny_patterns: tuple[DenyPattern, ...]
    allowed_projects: tuple[str, ...]
    denied_containers: tuple[str, ...]
    git_hosts: tuple[str, ...]
    http_check_hosts: tuple[str, ...]
    step_timeout_s: LimitValue
    plan_max_steps: LimitValue
    output_cap_mb: LimitValue
    read_only_mode: ReadOnlyMode
    read_only_mode_group: str | None
    read_only_deny_paths: tuple[tuple[str, str], ...]  # (path, group)
    passkey: bool
    unanimous: bool
    groups: tuple[str, ...]
    lockdown: bool = False
    extra: Mapping[str, object] = field(default_factory=dict)


def _min_limit(current: LimitValue, candidate: int | None, group: str) -> LimitValue:
    if candidate is None or candidate >= current.value:
        return current
    return LimitValue(candidate, group)


def _dedupe[T](items: list[T]) -> tuple[T, ...]:
    seen: list[T] = []
    for it in items:
        if it not in seen:
            seen.append(it)
    return tuple(seen)


def effective_rules(
    policy: Policy, target: Target, *, version: int = 0, lockdown: bool = False
) -> EffectiveRules:
    groups = sorted(name for name, g in policy.groups.items() if target.name in g.members)

    deny_paths = list(policy.deny_paths)
    patterns = [DenyPattern(p, re.compile(p), None) for p in policy.commands.deny_patterns]
    step_timeout = LimitValue(policy.limits.step_timeout_s, None)
    max_steps = LimitValue(policy.limits.plan_max_steps, None)
    output_cap = LimitValue(policy.limits.output_cap_mb, None)
    ro_mode, ro_group = ReadOnlyMode.ALLOWED, None
    ro_deny: list[tuple[str, str]] = []
    passkey = unanimous = False

    for name in groups:
        g = policy.groups[name]
        patterns.extend(DenyPattern(p, re.compile(p), name) for p in g.commands.deny_patterns)
        step_timeout = _min_limit(step_timeout, g.limits.step_timeout_s, name)
        max_steps = _min_limit(max_steps, g.limits.plan_max_steps, name)
        output_cap = _min_limit(output_cap, g.limits.output_cap_mb, name)
        mode = ReadOnlyMode.parse(g.read_only.mode)
        if mode > ro_mode:
            ro_mode, ro_group = mode, name
        ro_deny.extend((p, name) for p in g.read_only.deny_paths)
        passkey = passkey or g.approvals.passkey
        unanimous = unanimous or g.gatekeepers.unanimous

    return EffectiveRules(
        target=target.name,
        policy_version=version,
        workspace_roots=target.workspace_roots,
        deny_paths=_dedupe(deny_paths),
        allow=MappingProxyType(dict(policy.commands.allow)),
        deny_patterns=tuple(patterns),
        allowed_projects=policy.docker.allowed_projects,
        denied_containers=policy.docker.denied_containers,
        git_hosts=policy.network.git_hosts,
        http_check_hosts=policy.network.http_check_hosts,
        step_timeout_s=step_timeout,
        plan_max_steps=max_steps,
        output_cap_mb=output_cap,
        read_only_mode=ro_mode,
        read_only_mode_group=ro_group,
        read_only_deny_paths=_dedupe(ro_deny),
        passkey=passkey,
        unanimous=unanimous,
        groups=tuple(groups),
        lockdown=lockdown,
    )
