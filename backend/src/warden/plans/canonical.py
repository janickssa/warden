"""Canonical JSON (DECISIONS D-08).

Sorted keys, no insignificant whitespace, UTF-8 without escaping non-ASCII, no floats, integers within the
IEEE-754 safe range, and every string already NFC. The Go agent implements the same rules and both run
the shared vectors in policy-fixtures/canonical_vectors.json.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from warden.errors import CanonicalError
from warden.text import is_nfc

MAX_SAFE_INT = 2**53 - 1


def _check(value: Any, path: str) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalError(f"{path}: integer outside the safe range")
        return
    if isinstance(value, float):
        raise CanonicalError(f"{path}: floats are not allowed in canonical JSON")
    if isinstance(value, str):
        if not is_nfc(value):
            raise CanonicalError(f"{path}: string is not NFC-normalised")
        return
    if isinstance(value, list | tuple):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalError(f"{path}: object keys must be strings")
            if not is_nfc(key):
                raise CanonicalError(f"{path}: key {key!r} is not NFC-normalised")
            _check(item, f"{path}.{key}")
        return
    raise CanonicalError(f"{path}: unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _check(value, "$")
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return text.encode("utf-8")


def sha256_tagged(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()
