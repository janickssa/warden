"""Read-only allowlist (README section 8) with group read-only modes (README 7B).

These run without a plan, so the allowlist is narrow and fixed in code (a safe default per section 16
rule 8): every program has exact shapes, every path must be absolute and inside the workspace, and group
restrictions name the group in the reason.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from warden.plans.models import Violation
from warden.policy import baseline
from warden.policy.effective import EffectiveRules
from warden.policy.lexer import LexRefused, lex
from warden.policy.matcher import check_curl, check_deny_patterns, check_path, name_matches
from warden.policy.paths import PathResolver, ResolveError, is_within
from warden.policy.schema import ReadOnlyMode

_INT = re.compile(r"^[0-9]{1,6}$")
LS_FLAGS = frozenset("lahdRrtS1AF")
LS_LONG = frozenset({"--all", "--almost-all", "--human-readable", "--directory", "--recursive", "--reverse"})
GIT_STATUS_FLAGS = frozenset({"-s", "--short", "-b", "--branch", "--porcelain"})
GIT_LOG_FLAGS = frozenset({"--oneline", "--stat", "--decorate", "--graph", "--no-color", "--all", "-p"})
DOCKER_PS_FLAGS = frozenset({"-a", "--all", "-q", "--quiet", "--no-trunc", "-s", "--size"})


def _v(code: str, message: str, group: str | None = None) -> Violation:
    return Violation(code=code, message=message, group=group)


def _refuse(message: str) -> list[Violation]:
    return [_v("not_read_only", f"not on the read-only allowlist: {message}")]


def _file_args(
    argv: Sequence[str],
    allowed_flags: frozenset[str],
    long_flags: frozenset[str] = frozenset(),
    value_flags: frozenset[str] = frozenset(),
) -> tuple[list[str], list[Violation]]:
    """Split `cmd [flags] path...` into paths; refuse unknown flags."""
    paths: list[str] = []
    errors: list[Violation] = []
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in value_flags:
            if i + 1 >= len(argv) or not _INT.match(argv[i + 1]):
                errors += _refuse(f"{argv[0]} {tok} needs a number")
            i += 2
            continue
        if tok.startswith("--"):
            name, _, value = tok.partition("=")
            if name in long_flags or (name == "--lines" and _INT.match(value)):
                i += 1
                continue
            errors += _refuse(f"{argv[0]} {tok}")
        elif tok.startswith("-") and len(tok) > 1:
            if not all(c in allowed_flags for c in tok[1:]):
                errors += _refuse(f"{argv[0]} {tok}")
        else:
            paths.append(tok)
        i += 1
    if not paths:
        errors += _refuse(f"{argv[0]} needs at least one absolute path")
    return paths, errors


def _shape(argv: Sequence[str], rules: EffectiveRules) -> tuple[list[str], list[Violation]]:
    """Return (paths to check, violations) for one read-only command."""
    program = argv[0]
    if program == "ls":
        return _file_args(argv, LS_FLAGS, LS_LONG)
    if program == "cat":
        return _file_args(argv, frozenset("n"))
    if program in ("head", "tail"):
        return _file_args(argv, frozenset(), value_flags=frozenset({"-n", "-c"}))
    if program == "stat":
        return _file_args(argv, frozenset())
    if program == "df":
        return ([], []) if tuple(argv) == ("df", "-h") else ([], _refuse("only `df -h`"))
    if program == "free":
        return ([], []) if tuple(argv) == ("free", "-m") else ([], _refuse("only `free -m`"))
    if program == "git":
        if len(argv) < 4 or argv[1] != "-C" or argv[3] not in ("status", "log"):
            return [], _refuse("git must be `git -C <path> status` or `git -C <path> log`")
        allowed = GIT_STATUS_FLAGS if argv[3] == "status" else GIT_LOG_FLAGS
        errors: list[Violation] = []
        i = 4
        while i < len(argv):
            tok = argv[i]
            if (
                argv[3] == "log"
                and tok in ("-n", "--max-count")
                and i + 1 < len(argv)
                and _INT.match(argv[i + 1])
            ):
                i += 2
                continue
            if argv[3] == "log" and tok.startswith("--max-count=") and _INT.match(tok.split("=", 1)[1]):
                i += 1
                continue
            if tok not in allowed:
                errors += _refuse(f"git {argv[3]} {tok}")
            i += 1
        return [argv[2]], errors
    if program == "docker":
        return [], _docker(argv, rules)
    if program == "curl":
        return [], check_curl(argv, rules, None, read_only=True)
    return [], _refuse(f"{program} isn't a read-only command")


def _docker(argv: Sequence[str], rules: EffectiveRules) -> list[Violation]:
    sub = argv[1] if len(argv) > 1 else ""
    out: list[Violation] = []
    names: list[str] = []
    if sub == "ps":
        i = 2
        while i < len(argv):
            tok = argv[i]
            if tok in ("--filter", "-f") and i + 1 < len(argv):
                val = argv[i + 1]
                names.append(val.split("=", 1)[1] if "=" in val else val)
                i += 2
                continue
            if tok not in DOCKER_PS_FLAGS:
                out += _refuse(f"docker ps {tok}")
            i += 1
    elif sub == "logs":
        rest = list(argv[2:])
        if "--tail" not in rest:
            return _refuse("docker logs needs --tail N")
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok in ("--tail", "--since") and i + 1 < len(rest):
                if tok == "--tail" and not _INT.match(rest[i + 1]):
                    out += _refuse("docker logs --tail needs a number")
                i += 2
                continue
            if tok in ("-t", "--timestamps"):
                i += 1
                continue
            if tok.startswith("-"):
                out += _refuse(f"docker logs {tok}")
            else:
                names.append(tok)
            i += 1
        if len(names) != 1:
            out += _refuse("docker logs needs exactly one container")
    elif sub == "inspect":
        for tok in argv[2:]:
            if tok.startswith("-"):
                out += _refuse(f"docker inspect {tok}")
            else:
                names.append(tok)
        if not names:
            out += _refuse("docker inspect needs a container")
    elif sub == "compose":
        rest = list(argv[2:])
        if rest[:1] in (["-p"], ["--project-name"]):
            if len(rest) < 2 or not name_matches(rest[1], rules.allowed_projects):
                out.append(_v("compose_project_denied", "compose project isn't in docker.allowed_projects"))
            rest = rest[2:]
        if rest != ["ps"]:
            out += _refuse("only `docker compose [-p <project>] ps`")
    else:
        return _refuse(f"docker {sub}")
    for name in names:
        hit = name_matches(name, rules.denied_containers)
        if hit:
            out.append(_v("container_denied", f"container {name} matches docker.denied_containers {hit}"))
    return out


def check_read_only(command: str, rules: EffectiveRules, resolver: PathResolver) -> tuple[Violation, ...]:
    try:
        return _check(command, rules, resolver)
    except Exception as exc:  # fail closed
        return (_v("policy_error", f"read-only check failed: {type(exc).__name__}"),)


def _check(command: str, rules: EffectiveRules, resolver: PathResolver) -> tuple[Violation, ...]:
    if rules.read_only_mode == ReadOnlyMode.OFF:
        g = rules.read_only_mode_group
        return (_v("read_only_off", f"group {g}: read-only commands are off; this needs a plan", g),)
    try:
        lexed = lex(command)
    except LexRefused as exc:
        return (_v(exc.code, exc.message),)
    argv = lexed.argv
    cwd = rules.workspace_roots[0]
    paths, out = _shape(argv, rules)
    for p in paths:
        if not p.startswith("/"):
            out.append(_v("relative_path", f"{p}: read-only commands need absolute paths"))
            continue
        if rules.read_only_mode == ReadOnlyMode.RESTRICTED:
            try:
                res = resolver.resolve(p, cwd)
            except ResolveError:
                continue
            for deny, group in rules.read_only_deny_paths:
                if is_within(res.lexical, deny) or is_within(res.real, deny):
                    out.append(
                        _v(
                            "read_only_denied_path",
                            f"group {group}: read_only.deny_paths includes {deny}",
                            group,
                        )
                    )
                    break
        out += check_path(p, cwd, rules, resolver, None)
    out += baseline.check(argv, cwd, resolver)
    out += check_deny_patterns(command, argv, rules, None)
    seen: list[Violation] = []
    for v in out:
        if v not in seen:
            seen.append(v)
    return tuple(seen)
