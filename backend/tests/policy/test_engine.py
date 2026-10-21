from __future__ import annotations

import pytest
from policyhelp import mkstep, rules_for

from warden.config import parse_policy
from warden.policy import engine
from warden.policy.effective import effective_rules
from warden.policy.engine import check_plan, check_step
from warden.policy.paths import LexicalResolver
from warden.policy.readonly import check_read_only
from warden.policy.schema import Target

R = LexicalResolver()


def test_plan_passes() -> None:
    steps = [
        mkstep("git -C /srv/dev/myapp checkout v1.4.2", "git", n=1),
        mkstep("npm ci", n=2),
        mkstep("docker compose -p dev-myapp up -d --build", "docker", n=3),
        mkstep("curl -I http://localhost:8080/health", "http_check", n=4),
    ]
    res = check_plan(steps, rules_for("dev"), R)
    assert res.ok, res.violations
    assert res.policy_version == 1


def test_empty_plan() -> None:
    assert not check_plan([], rules_for("dev"), R).ok


def test_too_many_steps() -> None:
    steps = [mkstep("npm test", n=i) for i in range(1, 27)]
    assert "too_many_steps" in [v.code for v in check_plan(steps, rules_for("dev"), R).violations]


def test_step_numbers_must_be_sequential() -> None:
    res = check_plan([mkstep("npm ci", n=1), mkstep("npm test", n=3)], rules_for("dev"), R)
    assert "bad_step_numbers" in [v.code for v in res.violations]


def test_timeout_above_limit() -> None:
    assert [v.code for v in check_step(mkstep("npm ci", timeout_s=601), rules_for("dev"), R)] == [
        "timeout_too_long"
    ]


def test_one_bad_step_fails_the_plan_and_names_the_step() -> None:
    res = check_plan([mkstep("npm ci", n=1), mkstep("npm publish", n=2)], rules_for("dev"), R)
    assert not res.ok
    assert {v.step for v in res.violations} == {2}


def test_placeholder_must_refer_to_earlier_capture() -> None:
    ok = [
        mkstep("docker ps -q", "docker", n=1, captures={"container_id": "stdout_trimmed"}),
        mkstep("docker logs {{step1.container_id}}", "docker", n=2),
    ]
    assert check_plan(ok, rules_for("dev"), R).ok
    undeclared = [
        mkstep("docker ps -q", "docker", n=1),
        mkstep("docker logs {{step1.container_id}}", "docker", n=2),
    ]
    assert [v.code for v in check_plan(undeclared, rules_for("dev"), R).violations] == ["bad_placeholder"]
    forward = [
        mkstep("docker logs {{step2.container_id}}", "docker", n=1),
        mkstep("docker ps -q", "docker", n=2, captures={"container_id": "stdout_trimmed"}),
    ]
    assert [v.code for v in check_plan(forward, rules_for("dev"), R).violations] == ["bad_placeholder"]


def test_bad_capture_name() -> None:
    step = mkstep("docker ps -q", "docker", captures={"Bad-Name": "stdout_trimmed"})
    assert "bad_capture" in [v.code for v in check_step(step, rules_for("dev"), R)]


def test_lockdown_denies_every_step_but_not_read_only() -> None:
    rules = rules_for("dev", lockdown=True)
    assert [v.code for v in check_step(mkstep("npm test"), rules, R)] == ["lockdown"]
    assert check_read_only("ls /srv/dev", rules, R) == ()


def test_engine_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object, **_k: object) -> list[object]:
        raise RuntimeError("bug")

    monkeypatch.setattr(engine, "check_program", boom)
    assert [v.code for v in check_step(mkstep("npm ci"), rules_for("dev"), R)] == ["policy_error"]
    res = check_plan([mkstep("npm ci")], rules_for("dev"), R)
    assert not res.ok
    assert res.violations[0].code == "policy_error"


def test_read_only_error_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    from warden.policy import readonly

    monkeypatch.setattr(readonly, "_shape", lambda *_: (_ for _ in ()).throw(RuntimeError("bug")))
    assert [v.code for v in check_read_only("ls /srv/dev", rules_for("dev"), R)] == ["policy_error"]


# --- the baseline can't be switched off by policy ------------------------------------------------------

PERMISSIVE = """
commands:
  allow:
    bash: {}
    rm: {}
    chmod: {}
    python3: {}
    docker: {}
    sudo: {}
"""


@pytest.mark.parametrize(
    ("command", "kind", "code"),
    [
        ("bash script.sh", "shell", "baseline_program"),
        ("sudo ls", "shell", "baseline_program"),
        ("rm -rf /", "shell", "baseline_rm_root"),
        ("rm -rf /srv", "shell", "baseline_rm_root"),
        ("chmod u+s /srv/dev/x", "shell", "baseline_setuid"),
        ("python3 -c x", "shell", "baseline_inline_code"),
        ("docker run --privileged alpine", "docker", "baseline_docker_flag"),
        ("docker run -v /:/host alpine", "docker", "baseline_docker_mount"),
        ("docker run -v /var/run/docker.sock:/s alpine", "docker", "baseline_docker_mount"),
        ("rm /usr/local/bin/warden-agent", "shell", "baseline_protected_path"),
    ],
)
def test_baseline_holds_under_permissive_policy(command: str, kind: str, code: str) -> None:
    policy = parse_policy(PERMISSIVE)
    rules = effective_rules(policy, Target(name="dev", workspace_roots=("/srv/dev",)))
    got = [v.code for v in check_step(mkstep(command, kind, cwd="/srv/dev"), rules, R)]
    assert code in got
