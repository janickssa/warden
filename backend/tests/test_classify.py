"""Tighten/loosen classifier, plus the shared vectors the Go agent runs.

Regenerate vectors with: UPDATE_FIXTURES=1 uv run pytest tests/test_classify.py
"""

from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from typing import Any

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st
from policyhelp import FIXTURES, fixture_targets, rules_for

from warden.policy_dist.classify import classify
from warden.policy_dist.compile import compile_rules

KEY = {"key_id": "ed25519:aaaa", "public": "AAAA"}
APPROVER = {"credential_id": "cred-1", "alg": -7, "public": "MFkw-spki", "name": "MacBook"}


def base() -> dict[str, Any]:
    t = fixture_targets().get("dev")
    assert t is not None
    return {"rules": compile_rules(rules_for("dev"), t), "approval_keys": [KEY]}


def edit(fn: Callable[[dict[str, Any]], object]) -> dict[str, Any]:
    b = base()
    fn(b["rules"])
    return b


MUTATIONS: list[tuple[str, Callable[[dict[str, Any]], object], str]] = [
    ("add deny path", lambda r: r["deny_paths"].append("/srv/dev/secret"), "tighten"),
    ("remove deny path", lambda r: r["deny_paths"].remove("/etc"), "loosen"),
    (
        "add deny pattern",
        lambda r: r["deny_patterns"].append({"source": "npm\\s+publish", "group": None}),
        "tighten",
    ),
    ("remove deny pattern", lambda r: r["deny_patterns"].pop(0), "loosen"),
    ("relabel deny pattern group", lambda r: r["deny_patterns"][0].update(group="g"), "none"),
    ("remove program", lambda r: r["allow"].pop("npm"), "tighten"),
    ("add program", lambda r: r["allow"].update(rm={"subcommands": None, "flags_deny": []}), "loosen"),
    ("remove subcommand", lambda r: r["allow"]["git"]["subcommands"].remove("fetch"), "tighten"),
    ("add subcommand", lambda r: r["allow"]["git"]["subcommands"].append("push"), "loosen"),
    ("unrestricted subcommands", lambda r: r["allow"]["git"].update(subcommands=None), "loosen"),
    ("restrict subcommands", lambda r: r["allow"]["curl"].update(subcommands=["x"]), "tighten"),
    ("add flag deny", lambda r: r["allow"]["curl"]["flags_deny"].append("-L"), "tighten"),
    ("remove flag deny", lambda r: r["allow"]["curl"]["flags_deny"].remove("-o"), "loosen"),
    ("unknown field in program", lambda r: r["allow"]["git"].update(extra=1), "loosen"),
    ("add git host", lambda r: r["git_hosts"].append("gitlab.com"), "loosen"),
    ("remove http host", lambda r: r["http_check_hosts"].remove("localhost"), "tighten"),
    ("widen project glob", lambda r: r["allowed_projects"].append("*"), "loosen"),
    ("add denied container", lambda r: r["denied_containers"].append("db-*"), "tighten"),
    ("remove denied container", lambda r: r["denied_containers"].remove("prod-*"), "loosen"),
    ("lower step limit", lambda r: r["limits"]["plan_max_steps"].update(value=10), "tighten"),
    ("raise timeout", lambda r: r["limits"]["step_timeout_s"].update(value=601), "loosen"),
    ("lower timeout", lambda r: r["limits"]["step_timeout_s"].update(value=300), "tighten"),
    ("read-only restricted", lambda r: r["read_only"].update(mode="restricted"), "tighten"),
    (
        "read-only add deny path",
        lambda r: r["read_only"]["deny_paths"].append({"path": "/srv/x", "group": "g"}),
        "tighten",
    ),
    ("passkey on", lambda r: r["approvals"].update(passkey=True), "tighten"),
    ("e2e on", lambda r: r["approvals"].update(e2e=True), "tighten"),
    ("add approver", lambda r: r["approvals"]["approvers"].append(dict(APPROVER)), "loosen"),
    ("change rp id", lambda r: r["approvals"]["webauthn"].update(rp_id="evil.example.com"), "loosen"),
    (
        "add origin",
        lambda r: r["approvals"]["webauthn"]["origins"].append("https://evil.example.com"),
        "loosen",
    ),
    ("unknown approvals field", lambda r: r["approvals"].update(surprise=True), "loosen"),
    ("unknown webauthn field", lambda r: r["approvals"]["webauthn"].update(surprise=True), "loosen"),
    ("unanimous on", lambda r: r["gatekeepers"].update(unanimous=True), "tighten"),
    ("lockdown on", lambda r: r.update(lockdown=True), "tighten"),
    ("add workspace root", lambda r: r["workspace_roots"].append("/srv/other"), "loosen"),
    ("change docker socket", lambda r: r.update(docker_socket="/var/run/docker.sock"), "loosen"),
    ("change target", lambda r: r.update(target="dev2"), "loosen"),
    ("unknown top-level field", lambda r: r.update(surprise=True), "loosen"),
    (
        "mixed tighten and loosen",
        lambda r: (r["deny_paths"].append("/x"), r["git_hosts"].append("evil.example")),
        "loosen",
    ),
    ("group names only", lambda r: r.update(groups=["informational"]), "none"),
]


@pytest.mark.parametrize(("name", "fn", "expected"), MUTATIONS, ids=[m[0] for m in MUTATIONS])
def test_mutation(name: str, fn: Callable[[dict[str, Any]], object], expected: str) -> None:
    assert classify(base(), edit(fn)).cls == expected


def test_reverse_of_tighten_is_loosen() -> None:
    for _name, fn, expected in MUTATIONS:
        if expected == "tighten":
            assert classify(edit(fn), base()).cls == "loosen"


def test_approval_keys() -> None:
    more = base()
    more["approval_keys"].append({"key_id": "ed25519:bbbb", "public": "BBBB"})
    assert classify(base(), more).cls == "loosen"
    assert classify(more, base()).cls == "tighten"
    swapped = base()
    swapped["approval_keys"] = [{"key_id": "ed25519:aaaa", "public": "CCCC"}]
    assert classify(base(), swapped).cls == "loosen"


def test_no_previous_bundle_is_never_tighten() -> None:
    assert classify(None, base()).cls == "loosen"


@settings(max_examples=150, deadline=None)
@given(st.lists(st.sampled_from(range(len(MUTATIONS))), min_size=1, max_size=4, unique=True))
def test_any_loosening_mutation_makes_the_whole_change_loosen(picks: list[int]) -> None:
    names = {MUTATIONS[i][0] for i in picks}
    assume(not {"raise timeout", "lower timeout"} <= names)  # same field: the last one wins
    new = base()
    try:
        for i in picks:
            MUTATIONS[i][1](new["rules"])
    except (AttributeError, KeyError, ValueError):
        assume(False)  # two mutations that conflict (e.g. "any subcommand" then "add subcommand")
    expected = [MUTATIONS[i][2] for i in picks]
    got = classify(base(), new).cls
    if "loosen" in expected:
        assert got == "loosen"
    elif "tighten" in expected:
        assert got == "tighten"


def make_vectors() -> list[dict[str, Any]]:
    out = []
    for name, fn, expected in MUTATIONS:
        old, new = base(), edit(fn)
        if name in (
            "unknown field in program",
            "unknown top-level field",
            "unknown approvals field",
            "unknown webauthn field",
        ):
            continue  # the agent's strict decoder refuses these outright
        out.append({"name": name, "old": old, "new": new, "expected": expected})
    keys = base()
    keys["approval_keys"].append({"key_id": "ed25519:bbbb", "public": "BBBB"})
    out.append({"name": "add approval key", "old": base(), "new": keys, "expected": "loosen"})
    out.append({"name": "remove approval key", "old": keys, "new": base(), "expected": "tighten"})
    with_approver = edit(lambda r: r["approvals"]["approvers"].append(dict(APPROVER)))
    out.append({"name": "remove approver", "old": with_approver, "new": base(), "expected": "tighten"})
    swapped = edit(lambda r: r["approvals"]["approvers"].append({**APPROVER, "public": "OTHER"}))
    out.append({"name": "swap approver key", "old": with_approver, "new": swapped, "expected": "loosen"})
    with_origin = edit(lambda r: r["approvals"]["webauthn"]["origins"].append("https://warden.example.dk"))
    out.append({"name": "remove origin", "old": with_origin, "new": base(), "expected": "tighten"})
    return copy.deepcopy(out)


def test_vectors_are_current() -> None:
    text = json.dumps(make_vectors(), indent=1, sort_keys=True, ensure_ascii=True) + "\n"
    path = FIXTURES / "classify_vectors.json"
    if os.environ.get("UPDATE_FIXTURES") == "1":
        path.write_text(text, encoding="utf-8")
    assert path.read_text(encoding="utf-8") == text, "run UPDATE_FIXTURES=1 to regenerate"
