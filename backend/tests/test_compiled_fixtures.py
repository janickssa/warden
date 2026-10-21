"""policy-fixtures/compiled/*.json must match what Warden would put in a bundle today.

Regenerate with: UPDATE_FIXTURES=1 uv run pytest tests/test_compiled_fixtures.py
"""

from __future__ import annotations

import json
import os

import pytest
from policyhelp import FIXTURES, fixture_targets, rules_for

from warden.policy_dist.compile import compile_rules

TARGETS = [t.name for t in fixture_targets().targets]


@pytest.mark.parametrize("name", TARGETS)
def test_compiled_fixture_is_current(name: str) -> None:
    target = fixture_targets().get(name)
    assert target is not None
    compiled = compile_rules(rules_for(name), target)
    text = json.dumps(compiled, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    path = FIXTURES / "compiled" / f"{name}.json"
    if os.environ.get("UPDATE_FIXTURES") == "1":
        path.parent.mkdir(exist_ok=True)
        path.write_text(text, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == text, "run UPDATE_FIXTURES=1 to regenerate"


def test_group_rules_are_compiled_in() -> None:
    target = fixture_targets().get("sec-auth")
    assert target is not None
    c = compile_rules(rules_for("sec-auth"), target)
    assert c["read_only"]["mode"] == "restricted"
    assert c["limits"]["plan_max_steps"] == {"value": 10, "group": "high-security"}
    assert {"source": r"docker\s+exec", "group": "high-security"} in c["deny_patterns"]
