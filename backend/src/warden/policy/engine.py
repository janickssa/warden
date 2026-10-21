"""Policy engine entry points (README section 7, invariant 6).

Deterministic and LLM-free. Any unexpected error while checking becomes a `policy_error` violation, so a
bug in the engine denies instead of allowing (section 16 rule 6).
"""

from __future__ import annotations

from collections.abc import Sequence

from warden.errors import InputRefused
from warden.plans.models import CAPTURE_NAME, PolicyResult, Step, Violation
from warden.plans.placeholders import check_step_placeholders
from warden.policy import baseline
from warden.policy.effective import EffectiveRules
from warden.policy.lexer import LexRefused, lex
from warden.policy.matcher import check_cwd, check_deny_patterns, check_paths, check_program
from warden.policy.paths import PathResolver


def _dedupe(items: Sequence[Violation]) -> tuple[Violation, ...]:
    seen: list[Violation] = []
    for v in items:
        if v not in seen:
            seen.append(v)
    return tuple(seen)


def _check_step(
    step: Step, rules: EffectiveRules, resolver: PathResolver
) -> tuple[list[Violation], tuple[str, ...]]:
    n = step.n
    if rules.lockdown:
        return [
            Violation(code="lockdown", message="lockdown: only read-only commands are allowed", step=n)
        ], ()
    try:
        lexed = lex(step.command)
    except LexRefused as exc:
        return [Violation(code=exc.code, message=exc.message, step=n)], ()
    argv = lexed.argv
    out = check_cwd(step.cwd, rules, resolver, n)
    cwd_ok = not out
    out += baseline.check(argv, step.cwd if step.cwd.startswith("/") else "/", resolver, step=n)
    out += check_program(step.kind, argv, rules, n)
    if cwd_ok:
        out += check_paths(argv, step.cwd, rules, resolver, n)
    out += check_deny_patterns(step.command, argv, rules, n)
    limit = rules.step_timeout_s
    if step.timeout_s > limit.value:
        who = f"group {limit.group}: " if limit.group else ""
        out.append(
            Violation(
                code="timeout_too_long",
                step=n,
                group=limit.group,
                message=f"{who}timeout {step.timeout_s} s is above limits.step_timeout_s {limit.value} s",
            )
        )
    for name in step.captures:
        if not CAPTURE_NAME.match(name):
            out.append(Violation(code="bad_capture", message=f"capture name {name!r} isn't valid", step=n))
    return out, argv


def check_step(step: Step, rules: EffectiveRules, resolver: PathResolver) -> tuple[Violation, ...]:
    try:
        out, _ = _check_step(step, rules, resolver)
    except Exception as exc:  # fail closed
        return (
            Violation(code="policy_error", message=f"policy check failed: {type(exc).__name__}", step=step.n),
        )
    return _dedupe(out)


def check_plan(steps: Sequence[Step], rules: EffectiveRules, resolver: PathResolver) -> PolicyResult:
    try:
        out: list[Violation] = []
        if not steps:
            out.append(Violation(code="empty_plan", message="a plan needs at least one step"))
        limit = rules.plan_max_steps
        if len(steps) > limit.value:
            who = f"group {limit.group}: " if limit.group else ""
            out.append(
                Violation(
                    code="too_many_steps",
                    group=limit.group,
                    message=f"{who}{len(steps)} steps is above limits.plan_max_steps {limit.value}",
                )
            )
        if [s.n for s in steps] != list(range(1, len(steps) + 1)):
            out.append(
                Violation(code="bad_step_numbers", message="steps must be numbered 1, 2, 3, … in order")
            )
        argvs: list[tuple[str, ...]] = []
        for s in steps:
            vs, argv = _check_step(s, rules, resolver)
            out += vs
            argvs.append(argv)
        if not out:
            try:
                check_step_placeholders(steps, argvs)
            except InputRefused as exc:
                out.append(Violation(code=exc.code, message=exc.message))
        violations = _dedupe(out)
        return PolicyResult(ok=not violations, violations=violations, policy_version=rules.policy_version)
    except Exception as exc:  # fail closed
        return PolicyResult(
            ok=False,
            violations=(
                Violation(code="policy_error", message=f"policy check failed: {type(exc).__name__}"),
            ),
            policy_version=rules.policy_version,
        )
