"""Path classification, normalisation and workspace checks.

Warden checks paths lexically when a plan is proposed. It can't follow symlinks on the target, so each
agent repeats the check with the real `realpath` before every step (README 7A). `LocalResolver` does the
same thing on the local filesystem; tests use it to prove the symlink logic the agent mirrors.
"""

from __future__ import annotations

import os
import posixpath
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

_URL = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")


def is_url(token: str) -> bool:
    return _URL.match(token) is not None


def is_path_like(token: str) -> bool:
    if is_url(token):
        return False
    return token in (".", "..") or token.startswith(("/", "./", "../", "~")) or "/" in token


def lexical_join(cwd: str, path: str) -> str:
    """Absolute, normalised path ('..' collapsed lexically). `cwd` must be absolute."""
    joined = path if path.startswith("/") else posixpath.join(cwd, path)
    norm = posixpath.normpath(joined)
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return norm


def is_within(path: str, root: str) -> bool:
    if root == "/":
        return True
    return path == root or path.startswith(root.rstrip("/") + "/")


def within_any(path: str, roots: Iterable[str]) -> str | None:
    """The first root that contains `path`, or None."""
    return next((r for r in roots if is_within(path, r)), None)


class ResolveError(Exception):
    """The path can't be resolved safely (symlink loop, permission error, ...)."""


@dataclass(frozen=True, slots=True)
class Resolved:
    lexical: str  # normalised, symlinks not followed
    real: str  # symlinks followed where they exist; equals `lexical` for the lexical resolver


class PathResolver(Protocol):
    def resolve(self, path: str, cwd: str) -> Resolved: ...


class LexicalResolver:
    """Central-side resolver: normalises without touching any filesystem."""

    def resolve(self, path: str, cwd: str) -> Resolved:
        lex = lexical_join(cwd, path)
        return Resolved(lexical=lex, real=lex)


class LocalResolver:
    """Follows symlinks on the local filesystem, like the agent does on its target.

    For paths that don't exist yet (e.g. a clone destination), the deepest existing ancestor is resolved
    and the rest appended. Symlink loops and unreadable components raise ResolveError (deny).
    `root` lets tests map a fake target filesystem into a temporary directory.
    """

    def __init__(self, root: str = "/") -> None:
        self._root = os.path.realpath(root)

    def _to_host(self, path: str) -> str:
        return path if self._root == "/" else self._root + path

    def _from_host(self, path: str) -> str:
        if self._root == "/":
            return path
        if path == self._root:
            return "/"
        if path.startswith(self._root + "/"):
            return path[len(self._root) :]
        # Resolved outside the mapped root: report it as a path that's outside every workspace.
        return "/__outside_root__" + path

    def resolve(self, path: str, cwd: str) -> Resolved:
        lex = lexical_join(cwd, path)
        # Resolve the raw path component by component, as the kernel does: `lnk/../x` goes through the
        # symlink's target before `..`, which a lexical normalisation would get wrong.
        raw = path if path.startswith("/") else cwd.rstrip("/") + "/" + path
        host = self._to_host(raw)
        if ".." in raw.split("/") and not os.path.lexists(host):
            raise ResolveError(f"can't resolve {raw}: it contains '..' and doesn't exist")
        missing: list[str] = []
        probe = host
        while True:
            try:
                real = os.path.realpath(probe, strict=True)
                break
            except FileNotFoundError:
                if os.path.lexists(probe):
                    # A dangling symlink: follow its text so it can't hide where it points.
                    real = os.path.realpath(probe, strict=False)
                    break
                parent = os.path.dirname(probe)
                if parent == probe:
                    raise ResolveError(f"can't resolve {lex}") from None
                missing.append(os.path.basename(probe))
                probe = parent
            except OSError as exc:  # ELOOP, EACCES, ...
                raise ResolveError(f"can't resolve {lex}: {exc.strerror}") from exc
        for part in reversed(missing):
            real = os.path.join(real, part)
        return Resolved(lexical=lex, real=self._from_host(real))
