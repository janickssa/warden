"""Placeholders: {{stepN.name}} for captures and {{secret:NAME}} for secrets (README section 5).

A placeholder must be a whole argv element. The template (with placeholders unexpanded) is what gets
hashed and approved; values are substituted as single argv elements at run time and validated by type.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from warden.errors import InputRefused
from warden.plans.models import Step

PLACEHOLDER = re.compile(
    r"^\{\{(?:step(?P<step>[1-9][0-9]{0,3})\.(?P<name>[a-z][a-z0-9_]{0,31})"
    r"|secret:(?P<secret>[A-Z][A-Z0-9_]{0,63}))\}\}$"
)

_CONTAINER_ID = re.compile(r"^[a-f0-9]{12,64}$")
_PORT = re.compile(r"^[0-9]{1,5}$")
_GENERIC = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def is_placeholder(token: str) -> bool:
    return PLACEHOLDER.match(token) is not None


def contains_brace_pair(token: str) -> bool:
    return "{{" in token or "}}" in token


def validate_capture_value(name: str, value: str) -> bool:
    """Type check for a captured runtime value, chosen by the capture name."""
    if name.endswith("container_id"):
        return _CONTAINER_ID.match(value) is not None
    if name.endswith("port"):
        return _PORT.match(value) is not None and 1 <= int(value) <= 65535
    return _GENERIC.match(value) is not None


def check_step_placeholders(steps: Sequence[Step], argvs: Sequence[Sequence[str]]) -> None:
    """Every {{stepN.name}} must refer to a capture declared by an earlier step."""
    declared: dict[int, set[str]] = {}
    for step, argv in zip(steps, argvs, strict=True):
        for token in argv:
            m = PLACEHOLDER.match(token)
            if m is None or m.group("step") is None:
                continue
            ref, name = int(m.group("step")), m.group("name")
            if ref >= step.n:
                raise InputRefused(
                    f"step {step.n}: {token} refers to a step that hasn't run yet", code="bad_placeholder"
                )
            if name not in declared.get(ref, set()):
                raise InputRefused(
                    f"step {step.n}: {token} refers to a capture step {ref} doesn't declare",
                    code="bad_placeholder",
                )
        declared[step.n] = set(step.captures)
