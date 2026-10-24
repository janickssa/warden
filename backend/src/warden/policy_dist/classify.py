"""Tighten/loosen classification of a target's compiled rules (README 7A, 7B; section 16 rule 12).

Runs on Warden before publishing and, with the same logic, on every agent before accepting a bundle (the
Go copy in agent/internal/bundle/classify.go; shared vectors in policy-fixtures/classify_vectors.json).
Every field is compared as a set or a number. Anything that can't be proven to tighten is "loosen".
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

Effect = Literal["tighten", "loosen"]
Class = Literal["none", "tighten", "loosen"]

RO_LEVEL = {"allowed": 0, "restricted": 1, "off": 2}

# key -> direction. "deny": adding tightens. "allow": adding loosens.
_SET_FIELDS: dict[str, Literal["deny", "allow"]] = {
    "deny_paths": "deny",
    "denied_containers": "deny",
    "allowed_projects": "allow",
    "git_hosts": "allow",
    "http_check_hosts": "allow",
    "workspace_roots": "allow",
}
_FLAGS = ("approvals.passkey", "approvals.e2e", "gatekeepers.unanimous", "lockdown")
_APPROVALS_KNOWN = {"passkey", "e2e", "approvers", "webauthn"}
_KNOWN = {
    "schema",
    "target",
    "docker_socket",
    "allow",
    "deny_patterns",
    "limits",
    "read_only",
    "approvals",
    "gatekeepers",
    "groups",
    "lockdown",
    *_SET_FIELDS,
}


@dataclass(frozen=True)
class Change:
    path: str
    op: str  # add | remove | lower | raise | change
    effect: Effect
    detail: str

    def text(self) -> str:
        arrow = "↓" if self.effect == "tighten" else "↑"
        return f"{arrow} {self.path} {self.op} {self.detail}"


@dataclass(frozen=True)
class Classification:
    cls: Class
    changes: tuple[Change, ...]


def _set_diff(path: str, old: list[str], new: list[str], direction: str) -> list[Change]:
    out = []
    for v in sorted(set(new) - set(old)):
        out.append(Change(path, "add", "tighten" if direction == "deny" else "loosen", v))
    for v in sorted(set(old) - set(new)):
        out.append(Change(path, "remove", "loosen" if direction == "deny" else "tighten", v))
    return out


def _get(d: dict[str, Any], dotted: str) -> Any:
    cur: Any = d
    for part in dotted.split("."):
        cur = cur.get(part) if isinstance(cur, dict) else None
    return cur


def classify_rules(old: dict[str, Any], new: dict[str, Any]) -> list[Change]:
    out: list[Change] = []
    for key in sorted((set(old) | set(new)) - _KNOWN):
        if old.get(key) != new.get(key):
            out.append(Change(key, "change", "loosen", "unknown field"))
    for key in ("schema", "target", "docker_socket"):
        if old.get(key) != new.get(key):
            out.append(Change(key, "change", "loosen", f"{old.get(key)} → {new.get(key)}"))
    for key, direction in _SET_FIELDS.items():
        out += _set_diff(key, list(old.get(key) or []), list(new.get(key) or []), direction)

    old_allow, new_allow = dict(old.get("allow") or {}), dict(new.get("allow") or {})
    for prog in sorted(set(new_allow) - set(old_allow)):
        out.append(Change("commands.allow", "add", "loosen", prog))
    for prog in sorted(set(old_allow) - set(new_allow)):
        out.append(Change("commands.allow", "remove", "tighten", prog))
    for prog in sorted(set(old_allow) & set(new_allow)):
        o, n = old_allow[prog], new_allow[prog]
        path = f"commands.allow.{prog}"
        if set(o) != {"subcommands", "flags_deny"} or set(n) != {"subcommands", "flags_deny"}:
            if o != n:
                out.append(Change(path, "change", "loosen", "unknown field"))
            continue
        os_, ns = o["subcommands"], n["subcommands"]
        if os_ is None and ns is not None:
            out.append(Change(f"{path}.subcommands", "change", "tighten", f"any → {', '.join(ns)}"))
        elif os_ is not None and ns is None:
            out.append(Change(f"{path}.subcommands", "change", "loosen", f"{', '.join(os_)} → any"))
        elif os_ is not None and ns is not None:
            out += _set_diff(f"{path}.subcommands", os_, ns, "allow")
        out += _set_diff(f"{path}.flags_deny", o["flags_deny"], n["flags_deny"], "deny")

    out += _set_diff(
        "commands.deny_patterns",
        [p["source"] for p in old.get("deny_patterns") or []],
        [p["source"] for p in new.get("deny_patterns") or []],
        "deny",
    )

    for lim in sorted(set(_get(old, "limits") or {}) | set(_get(new, "limits") or {})):
        a, b = _get(old, f"limits.{lim}.value"), _get(new, f"limits.{lim}.value")
        if a == b:
            continue
        if isinstance(a, int) and isinstance(b, int):
            out.append(
                Change(
                    f"limits.{lim}",
                    "lower" if b < a else "raise",
                    "tighten" if b < a else "loosen",
                    f"{a} → {b}",
                )
            )
        else:
            out.append(Change(f"limits.{lim}", "change", "loosen", f"{a} → {b}"))

    a, b = _get(old, "read_only.mode"), _get(new, "read_only.mode")
    if a != b:
        if a in RO_LEVEL and b in RO_LEVEL:
            out.append(
                Change(
                    "read_only.mode",
                    "change",
                    "tighten" if RO_LEVEL[b] > RO_LEVEL[a] else "loosen",
                    f"{a} → {b}",
                )
            )
        else:
            out.append(Change("read_only.mode", "change", "loosen", f"{a} → {b}"))
    out += _set_diff(
        "read_only.deny_paths",
        [d["path"] for d in _get(old, "read_only.deny_paths") or []],
        [d["path"] for d in _get(new, "read_only.deny_paths") or []],
        "deny",
    )

    oa, na = dict(old.get("approvals") or {}), dict(new.get("approvals") or {})
    for key in sorted((set(oa) | set(na)) - _APPROVALS_KNOWN):
        if oa.get(key) != na.get(key):
            out.append(Change(f"approvals.{key}", "change", "loosen", "unknown field"))
    out += _set_diff(
        "approvals.approvers",
        [f"{a.get('credential_id')}={a.get('alg')}:{a.get('public')}" for a in oa.get("approvers") or []],
        [f"{a.get('credential_id')}={a.get('alg')}:{a.get('public')}" for a in na.get("approvers") or []],
        "allow",
    )
    ow, nw = dict(oa.get("webauthn") or {}), dict(na.get("webauthn") or {})
    if ow.get("rp_id") != nw.get("rp_id"):
        out.append(
            Change("approvals.webauthn.rp_id", "change", "loosen", f"{ow.get('rp_id')} → {nw.get('rp_id')}")
        )
    out += _set_diff(
        "approvals.webauthn.origins", list(ow.get("origins") or []), list(nw.get("origins") or []), "allow"
    )
    for key in sorted((set(ow) | set(nw)) - {"rp_id", "origins"}):
        if ow.get(key) != nw.get(key):
            out.append(Change(f"approvals.webauthn.{key}", "change", "loosen", "unknown field"))

    for flag in _FLAGS:
        a, b = bool(_get(old, flag)), bool(_get(new, flag))
        if a != b:
            out.append(Change(flag, "change", "tighten" if b else "loosen", f"{a} → {b}".lower()))
    return out


def _key_set(keys: list[dict[str, str]]) -> list[str]:
    return [f"{k['key_id']}={k['public']}" for k in keys]


def classify(old: dict[str, Any] | None, new: dict[str, Any]) -> Classification:
    """Classify bundle content {"rules": …, "approval_keys": […]} against the installed one."""
    if old is None:
        return Classification("loosen", (Change("bundle", "add", "loosen", "initial bundle"),))
    changes = classify_rules(old["rules"], new["rules"])
    changes += _set_diff(
        "approval_keys", _key_set(old["approval_keys"]), _key_set(new["approval_keys"]), "allow"
    )
    if not changes:
        return Classification("none", ())
    cls: Class = "tighten" if all(c.effect == "tighten" for c in changes) else "loosen"
    return Classification(cls, tuple(changes))
