from __future__ import annotations

import unicodedata

import pytest
from factories import plan, step
from hypothesis import given
from hypothesis import strategies as st

from warden.errors import CanonicalError
from warden.plans.canonical import canonical_bytes
from warden.plans.hashing import plan_hash


def test_canonical_is_sorted_and_compact() -> None:
    assert canonical_bytes({"b": 1, "a": [True, None, "x"]}) == b'{"a":[true,null,"x"],"b":1}'


def test_canonical_keeps_utf8_unescaped() -> None:
    assert canonical_bytes({"m": "Tilføj"}) == '{"m":"Tilføj"}'.encode()


@pytest.mark.parametrize("bad", [1.5, float("nan"), 2**53, {"x": 0.0}, {1: "a"}, b"bytes"])
def test_canonical_refuses_unrepresentable(bad: object) -> None:
    with pytest.raises(CanonicalError):
        canonical_bytes(bad)


def test_canonical_refuses_non_nfc() -> None:
    decomposed = unicodedata.normalize("NFD", "å")
    with pytest.raises(CanonicalError):
        canonical_bytes({"m": decomposed})


def test_hash_is_stable_and_tagged() -> None:
    p = plan()
    assert p.hash.startswith("sha256:")
    assert len(p.hash) == 7 + 64
    assert plan_hash(p) == plan_hash(p.model_copy())


@pytest.mark.parametrize(
    "change",
    [
        {"target": "dev2"},
        {"goal": "Deploy myapp on dev"},
        {"revises": "pln_01JB7M2A0000000000000000AA"},
        {"id": "pln_01JB7M2A0000000000000000BB"},
    ],
)
def test_hash_binds_plan_fields(change: dict[str, object]) -> None:
    p = plan()
    assert plan_hash(p.model_copy(update=change)) != p.hash


@pytest.mark.parametrize(
    "change",
    [
        {"command": "npm install"},
        {"purpose": "Something else"},
        {"cwd": "/srv/dev/other"},
        {"timeout_s": 301},
        {"expect_exit": 1},
        {"captures": {"container_id": "stdout_trimmed"}},
        {"n": 2},
    ],
)
def test_hash_binds_every_step_field(change: dict[str, object]) -> None:
    p = plan()
    changed = p.model_copy(update={"steps": (p.steps[0].model_copy(update=change),)})
    assert plan_hash(changed) != p.hash


def test_edited_flag_is_metadata_not_hashed() -> None:
    p = plan()
    changed = p.model_copy(update={"steps": (p.steps[0].model_copy(update={"edited": True}),)})
    assert plan_hash(changed) == p.hash


def test_step_order_matters() -> None:
    a, b = step(1, "npm ci"), step(2, "npm test")
    p1 = plan([a, b])
    p2 = p1.model_copy(update={"steps": (b.model_copy(update={"n": 1}), a.model_copy(update={"n": 2}))})
    assert plan_hash(p1) != plan_hash(p2)


def test_placeholders_are_hashed_unexpanded() -> None:
    p = plan(
        [
            step(1, "docker ps", kind="docker", captures={"container_id": "stdout_trimmed"}),
            step(2, "docker logs {{step1.container_id}}", kind="docker"),
        ]
    )
    assert "{{step1.container_id}}" in canonical_bytes(p.template()).decode()


@given(
    st.dictionaries(
        st.text(alphabet="abcxyz", min_size=1, max_size=5),
        st.integers(min_value=-1000, max_value=1000),
        max_size=8,
    )
)
def test_key_order_never_changes_bytes(d: dict[str, int]) -> None:
    reversed_d = dict(reversed(list(d.items())))
    assert canonical_bytes(d) == canonical_bytes(reversed_d)


def test_shared_vectors_for_go_agent() -> None:
    import hashlib
    import json
    from pathlib import Path

    path = Path(__file__).resolve().parents[2] / "policy-fixtures" / "canonical_vectors.json"
    for vec in json.loads(path.read_text(encoding="utf-8")):
        data = canonical_bytes(vec["value"])
        assert data.decode() == vec["canonical"], vec["name"]
        assert hashlib.sha256(data).hexdigest() == vec["sha256"], vec["name"]
