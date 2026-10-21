"""Runs policy-fixtures/cases/*.yaml. The Go agent runs the same corpus (M2)."""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from policyhelp import FIXTURES, mkstep, rules_for

from warden.policy.engine import check_step
from warden.policy.paths import LexicalResolver
from warden.policy.readonly import check_read_only

KEYS = {"id", "mode", "target", "kind", "cwd", "command", "expect", "code"}


def _load() -> list[tuple[str, dict[str, Any]]]:
    out = []
    for path in sorted((FIXTURES / "cases").glob("*.yaml")):
        for case in yaml.safe_load(path.read_text(encoding="utf-8")):
            out.append((f"{path.stem}:{case['id']}", case))
    return out


CASES = _load()


def test_corpus_is_well_formed() -> None:
    ids = [cid for cid, _ in CASES]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    assert len(CASES) >= 150
    for cid, case in CASES:
        assert set(case) <= KEYS, cid
        assert case["expect"] in ("allow", "deny"), cid
        assert case.get("mode", "step") in ("step", "read_only"), cid


@pytest.mark.parametrize("case", [c for _, c in CASES], ids=[cid for cid, _ in CASES])
def test_case(case: dict[str, Any]) -> None:
    target = case.get("target", "dev")
    rules = rules_for(target)
    cwd = case.get("cwd", "/srv/app" if target == "sec-auth" else "/srv/dev/myapp")
    if case.get("mode", "step") == "read_only":
        violations = check_read_only(case["command"], rules, LexicalResolver())
    else:
        step = mkstep(case["command"], case.get("kind", "shell"), cwd)
        violations = check_step(step, rules, LexicalResolver())
    codes = [v.code for v in violations]
    detail = "\n".join(f"  {v.code}: {v.message}" for v in violations)
    if case["expect"] == "allow":
        assert not violations, f"expected allow, got:\n{detail}"
    else:
        assert violations, "expected deny, got allow"
        if "code" in case:
            assert case["code"] in codes, f"expected {case['code']}, got:\n{detail}"
