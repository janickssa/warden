"""Groups can only add restrictions (README 7B, section 16 rule 16)."""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from policyhelp import FIXTURES, fixture_policy, fixture_targets, mkstep

from warden.config import parse_policy
from warden.errors import ConfigError
from warden.policy.effective import effective_rules
from warden.policy.engine import check_step
from warden.policy.paths import LexicalResolver
from warden.policy.readonly import check_read_only
from warden.policy.schema import Group, Policy, ReadOnlyMode

PATHS = ["/srv/dev/myapp/secret", "/srv/dev/other", "/home", "/srv/dev"]
PATTERNS = [r"npm\s+test", r"docker\s+restart", r"curl\s.*-I", r"git\s+fetch", r"build"]

groups_strategy = st.builds(
    lambda mode, paths, patterns, steps, timeout, passkey, unanimous: Group(
        members=("dev",),
        read_only={"mode": mode, "deny_paths": tuple(paths)},
        commands={"deny_patterns": tuple(patterns)},
        limits={"plan_max_steps": steps, "step_timeout_s": timeout},
        approvals={"passkey": passkey},
        gatekeepers={"unanimous": unanimous},
    ),
    st.sampled_from(["allowed", "restricted", "off"]),
    st.lists(st.sampled_from(PATHS), max_size=3, unique=True),
    st.lists(st.sampled_from(PATTERNS), max_size=3, unique=True),
    st.one_of(st.none(), st.integers(min_value=1, max_value=25)),
    st.one_of(st.none(), st.integers(min_value=1, max_value=600)),
    st.booleans(),
    st.booleans(),
)


def _with_groups(groups: list[Group]) -> Policy:
    base = fixture_policy()
    return base.model_copy(update={"groups": {f"g{i}": g for i, g in enumerate(groups)}})


def _corpus() -> list[dict[str, Any]]:
    out = []
    for path in sorted((FIXTURES / "cases").glob("*.yaml")):
        out += [
            c for c in yaml.safe_load(path.read_text(encoding="utf-8")) if c.get("target", "dev") == "dev"
        ]
    return out


CORPUS = _corpus()
DEV = fixture_targets().get("dev")


def _denied(policy: Policy, case: dict[str, Any]) -> bool:
    assert DEV is not None
    rules = effective_rules(policy, DEV)
    if case.get("mode", "step") == "read_only":
        return bool(check_read_only(case["command"], rules, LexicalResolver()))
    step = mkstep(case["command"], case.get("kind", "shell"), case.get("cwd", "/srv/dev/myapp"))
    return bool(check_step(step, rules, LexicalResolver()))


@settings(max_examples=60, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(groups_strategy, min_size=1, max_size=3))
def test_effective_rules_never_looser(groups: list[Group]) -> None:
    assert DEV is not None
    base = effective_rules(fixture_policy(), DEV)
    eff = effective_rules(_with_groups(groups), DEV)
    assert set(base.deny_paths) <= set(eff.deny_paths)
    assert {p.source for p in base.deny_patterns} <= {p.source for p in eff.deny_patterns}
    assert dict(eff.allow) == dict(base.allow)
    assert eff.allowed_projects == base.allowed_projects
    assert eff.denied_containers == base.denied_containers
    assert eff.git_hosts == base.git_hosts
    assert eff.http_check_hosts == base.http_check_hosts
    assert eff.plan_max_steps.value <= base.plan_max_steps.value
    assert eff.step_timeout_s.value <= base.step_timeout_s.value
    assert eff.output_cap_mb.value <= base.output_cap_mb.value
    assert eff.read_only_mode >= base.read_only_mode
    assert eff.passkey >= base.passkey
    assert eff.unanimous >= base.unanimous


@settings(max_examples=25, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(st.lists(groups_strategy, min_size=1, max_size=3))
def test_anything_denied_globally_stays_denied(groups: list[Group]) -> None:
    widened = [
        c["id"] for c in CORPUS if _denied(fixture_policy(), c) and not _denied(_with_groups(groups), c)
    ]
    assert widened == []


def test_overlapping_groups_strictest_wins() -> None:
    policy = parse_policy(
        (FIXTURES / "policy.yaml").read_text()
        + """
  a:
    members: [dev]
    read_only: {mode: restricted}
    limits: {plan_max_steps: 12}
  b:
    members: [dev]
    read_only: {mode: "off"}
    limits: {plan_max_steps: 20}
    approvals: {passkey: true}
"""
    )
    assert DEV is not None
    eff = effective_rules(policy, DEV)
    assert eff.read_only_mode == ReadOnlyMode.OFF
    assert eff.read_only_mode_group == "b"
    assert eff.plan_max_steps.value == 12
    assert eff.plan_max_steps.group == "a"
    assert eff.passkey is True


def test_read_only_off_names_the_group() -> None:
    policy = _with_groups([Group(members=("dev",), read_only={"mode": "off"})])
    assert DEV is not None
    v = check_read_only("ls /srv/dev", effective_rules(policy, DEV), LexicalResolver())
    assert v[0].code == "read_only_off"
    assert "group g0" in v[0].message


def test_group_step_limit_names_the_group() -> None:
    from policyhelp import rules_for

    from warden.policy.engine import check_plan

    steps = [mkstep("npm test", n=i, cwd="/srv/app") for i in range(1, 12)]
    res = check_plan(steps, rules_for("sec-auth"), LexicalResolver())
    v = next(v for v in res.violations if v.code == "too_many_steps")
    assert v.group == "high-security"
    assert "group high-security" in v.message


@pytest.mark.parametrize(
    "snippet",
    [
        "  g:\n    commands: {allow: {bash: {}}}\n",
        "  g:\n    network: {git_hosts: [evil.example]}\n",
        "  g:\n    docker: {allowed_projects: ['*']}\n",
        "  g:\n    limits: {plan_max_steps: 100}\n",
        "  g:\n    limits: {step_timeout_s: 9999}\n",
        "  g:\n    deny_paths: []\n",
    ],
)
def test_group_cannot_express_widening(snippet: str) -> None:
    with pytest.raises(ConfigError):
        parse_policy((FIXTURES / "policy.yaml").read_text() + snippet)
