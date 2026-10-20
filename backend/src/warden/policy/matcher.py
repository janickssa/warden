"""Structural matching of one argv against the effective rules (README section 7).

Regex deny patterns are a backup layer; the real decision is made here, per program:
program allowed?  step kind matches?  subcommand allowed?  flags allowed?  every path inside the workspace
and outside denied paths?  hosts, compose projects and containers allowed?
"""

from __future__ import annotations

import fnmatch
import re
import shlex
from collections.abc import Iterable, Sequence
from urllib.parse import urlsplit

from warden.plans.models import StepKind, Violation
from warden.plans.placeholders import is_placeholder
from warden.policy.effective import EffectiveRules
from warden.policy.paths import PathResolver, ResolveError, is_url, within_any
from warden.policy.schema import BinaryRule
from warden.text import is_ascii_printable

PROGRAM_KIND = {"git": StepKind.GIT, "docker": StepKind.DOCKER, "curl": StepKind.HTTP_CHECK}

# git: options allowed before the subcommand. Everything else there is refused (config injection etc.).
GIT_GLOBAL_WITH_VALUE = frozenset({"-C"})
GIT_GLOBAL_NO_VALUE = frozenset(
    {"--no-pager", "-P", "--no-replace-objects", "--literal-pathspecs", "--no-optional-locks"}
)
# git: options refused after any subcommand (they run programs or change where git reads config from).
GIT_DENY_ANYWHERE = frozenset(
    {"-c", "--config", "--config-env", "--upload-pack", "--receive-pack", "--exec", "--template",
     "--separate-git-dir", "--recurse-submodules", "--recursive", "--git-dir", "--work-tree", "--ext-diff",
     "--open-files-in-pager", "--textconv"}
)  # fmt: skip
GIT_URL_SUBCOMMANDS = frozenset({"clone", "fetch", "pull", "ls-remote", "remote", "submodule", "push"})
_SCP_LIKE = re.compile(r"^[^/\s:]+@[^/\s:]+:|^[A-Za-z0-9.-]+:[^/]")

# curl (http_check): an allowlist. Anything that writes files, follows redirects or changes routing is out.
CURL_SHORT_NOARG = frozenset("IsSfiv46")
CURL_LONG_NOARG = frozenset(
    {"--head", "--silent", "--show-error", "--fail", "--fail-with-body", "--include", "--verbose",
     "--compressed", "--ipv4", "--ipv6", "--no-progress-meter"}
)  # fmt: skip
CURL_SHORT_ARG = frozenset({"-m", "-H", "-A", "-X"})
CURL_LONG_ARG = frozenset(
    {"--max-time", "--connect-timeout", "--header", "--user-agent", "--retry", "--request"}
)
CURL_METHODS = frozenset({"GET", "HEAD"})

# npm: options allowed before the subcommand, and options refused anywhere.
NPM_GLOBAL_WITH_VALUE = frozenset({"--prefix"})
NPM_GLOBAL_NO_VALUE = frozenset({"--silent", "-s", "--no-audit", "--no-fund", "--quiet", "-q"})
NPM_DENY_ANYWHERE = frozenset(
    {"-g", "--global", "--location", "--userconfig", "--globalconfig", "--script-shell"}
)


def _v(code: str, message: str, step: int | None, group: str | None = None) -> Violation:
    return Violation(code=code, message=message, step=step, group=group)


def host_matches(host: str, patterns: Iterable[str]) -> bool:
    host = host.lower().rstrip(".")
    for p in patterns:
        if p.startswith("*."):
            if host.endswith(p[1:]) and host != p[2:]:
                return True
        elif host == p:
            return True
    return False


def name_matches(name: str, globs: Iterable[str]) -> str | None:
    return next((g for g in globs if fnmatch.fnmatchcase(name, g)), None)


# --- flags --------------------------------------------------------------------------------------------


def _flag_denied(tok: str, denied: Iterable[str]) -> str | None:
    """Match `--flag`, `--flag=value`, unambiguous `--fla` prefixes, `-o`, `-ovalue` and `-sSo` clusters."""
    denied = tuple(denied)
    if tok.startswith("--"):
        name = tok.split("=", 1)[0]
        for d in denied:
            if d.startswith("--") and (name == d or (len(name) > 2 and d.startswith(name))):
                return d
        return None
    if tok.startswith("-") and len(tok) > 1:
        for c in tok[1:]:
            if f"-{c}" in denied:
                return f"-{c}"
    return None


def _check_flags_deny(argv: Sequence[str], rule: BinaryRule, step: int | None) -> list[Violation]:
    out = []
    for tok in argv[1:]:
        if tok == "--":
            break
        hit = _flag_denied(tok, rule.flags_deny)
        if hit:
            out.append(_v("flag_denied", f"{argv[0]} flag {tok} matches {hit} in flags_deny", step))
    return out


def _subcommand(argv: Sequence[str], start: int) -> tuple[str | None, int]:
    i = start
    while i < len(argv) and argv[i].startswith("-"):
        i += 1
    return (argv[i], i) if i < len(argv) else (None, i)


def _check_subcommand(program: str, sub: str | None, rule: BinaryRule, step: int | None) -> list[Violation]:
    if rule.subcommands is None:
        return []
    if sub is None:
        return [_v("missing_subcommand", f"{program} needs a subcommand", step)]
    if sub not in rule.subcommands:
        allowed = ", ".join(rule.subcommands)
        return [
            _v(
                "subcommand_not_allowed",
                f"{program} {sub} isn't in commands.allow.{program}.subcommands ({allowed})",
                step,
            )
        ]
    return []


# --- per program --------------------------------------------------------------------------------------


def _git_url_ok(url: str, rules: EffectiveRules) -> str | None:
    """None if the URL is an allowed https URL, else the reason."""
    if not is_url(url):
        return "only https:// URLs are allowed for git"
    parts = urlsplit(url)
    if parts.scheme != "https":
        return f"scheme {parts.scheme}:// isn't allowed (https only)"
    if parts.username is not None or parts.password is not None:
        return "credentials in the URL aren't allowed"
    if parts.port not in (None, 443):
        return f"port {parts.port} isn't allowed"
    if not parts.hostname or not host_matches(parts.hostname, rules.git_hosts):
        return f"host {parts.hostname} isn't in network.git_hosts"
    return None


def _check_git(argv: Sequence[str], rules: EffectiveRules, step: int | None) -> list[Violation]:
    out: list[Violation] = []
    i = 1
    while i < len(argv) and argv[i].startswith("-"):
        tok = argv[i]
        if tok in GIT_GLOBAL_WITH_VALUE:
            i += 2
            continue
        if tok in GIT_GLOBAL_NO_VALUE:
            i += 1
            continue
        out.append(_v("git_option_denied", f"git option {tok} isn't allowed before the subcommand", step))
        i += 1
    sub = argv[i] if i < len(argv) else None
    out += _check_subcommand("git", sub, rules.allow["git"], step)

    for tok in argv[i + 1 :]:
        if tok == "--":
            break
        hit = _flag_denied(tok, GIT_DENY_ANYWHERE)
        if hit:
            out.append(_v("git_option_denied", f"git option {tok} isn't allowed ({hit})", step))
        if sub in ("clone", "fetch", "pull", "ls-remote") and tok in ("-u",):
            out.append(_v("git_option_denied", "git -u (upload-pack) isn't allowed", step))

    urls = [t for t in argv[i + 1 :] if is_url(t) or _SCP_LIKE.match(t) or "::" in t or t.startswith("file:")]
    for url in urls:
        why = _git_url_ok(url, rules)
        if why:
            out.append(_v("git_url_denied", f"git URL {url}: {why}", step))
    if sub == "clone" and not urls:
        out.append(_v("git_url_denied", "git clone needs an https:// URL", step))
    return out


def _docker_containers(argv: Sequence[str], start: int) -> list[str]:
    """Positional arguments (and key=value filter values) after a container subcommand."""
    names: list[str] = []
    for tok in argv[start:]:
        if tok.startswith("-"):
            if tok.startswith("--") and "=" in tok:
                val = tok.split("=", 1)[1]
                names.append(val.split("=", 1)[1] if "=" in val else val)
            continue
        names.append(tok.split("=", 1)[1] if "=" in tok else tok)
    return names


def _check_docker(argv: Sequence[str], rules: EffectiveRules, step: int | None) -> list[Violation]:
    out: list[Violation] = []
    if len(argv) < 2 or argv[1].startswith("-"):
        return [
            _v(
                "docker_option_denied",
                "docker global options (-H, --context, --config, ...) aren't allowed; "
                "start with the subcommand",
                step,
            )
        ]
    sub = argv[1]
    out += _check_subcommand("docker", sub, rules.allow["docker"], step)
    if sub == "compose":
        project: str | None = None
        i = 2
        while i < len(argv) and argv[i].startswith("-"):
            tok = argv[i]
            if tok in ("-p", "--project-name"):
                project = argv[i + 1] if i + 1 < len(argv) else None
                i += 2
            elif tok.startswith("--project-name="):
                project = tok.split("=", 1)[1]
                i += 1
            elif tok in ("-f", "--file", "--env-file", "--project-directory", "--profile"):
                i += 2
            elif tok.split("=", 1)[0] in ("--file", "--env-file", "--project-directory", "--profile"):
                i += 1
            else:
                out.append(_v("docker_option_denied", f"docker compose option {tok} isn't allowed", step))
                i += 1
        if project is None:
            out.append(
                _v(
                    "compose_project_required",
                    "docker compose needs -p <project> so Warden can check it "
                    "against docker.allowed_projects",
                    step,
                )
            )
        elif not is_placeholder(project) and not name_matches(project, rules.allowed_projects):
            out.append(
                _v(
                    "compose_project_denied",
                    f"compose project {project} isn't in docker.allowed_projects",
                    step,
                )
            )
        if i >= len(argv):
            out.append(_v("missing_subcommand", "docker compose needs a subcommand", step))
        return out
    for name in _docker_containers(argv, 2):
        hit = name_matches(name, rules.denied_containers)
        if hit:
            out.append(
                _v("container_denied", f"container {name} matches docker.denied_containers {hit}", step)
            )
    return out


def check_http_url(url: str, rules: EffectiveRules, step: int | None) -> list[Violation]:
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        return [_v("http_url_denied", f"{url}: only http:// and https:// are allowed", step)]
    if parts.username is not None or parts.password is not None:
        return [_v("http_url_denied", f"{url}: credentials in the URL aren't allowed", step)]
    try:
        _ = parts.port
    except ValueError:
        return [_v("http_url_denied", f"{url}: invalid port", step)]
    if not parts.hostname or not host_matches(parts.hostname, rules.http_check_hosts):
        return [_v("http_host_denied", f"host {parts.hostname} isn't in network.http_check_hosts", step)]
    return []


def check_curl(
    argv: Sequence[str], rules: EffectiveRules, step: int | None, *, read_only: bool = False
) -> list[Violation]:
    out: list[Violation] = []
    urls: list[str] = []
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok.startswith("--"):
            name, eq, value = tok.partition("=")
            if name in CURL_LONG_NOARG and not eq:
                i += 1
                continue
            if name in CURL_LONG_ARG and not read_only:
                val = value if eq else (argv[i + 1] if i + 1 < len(argv) else "")
                if name == "--request" and val not in CURL_METHODS:
                    out.append(_v("curl_method_denied", f"curl --request {val}: only GET and HEAD", step))
                i += 1 if eq else 2
                continue
            if name in ("--max-time", "--connect-timeout") and read_only:
                i += 1 if eq else 2
                continue
            out.append(_v("curl_flag_not_allowed", f"curl {name} isn't allowed in an HTTP check", step))
            i += 1
            continue
        if tok.startswith("-") and len(tok) > 1:
            if tok in CURL_SHORT_ARG and (not read_only or tok == "-m"):
                val = argv[i + 1] if i + 1 < len(argv) else ""
                if tok == "-X" and val not in CURL_METHODS:
                    out.append(_v("curl_method_denied", f"curl -X {val}: only GET and HEAD", step))
                i += 2
                continue
            bad = [c for c in tok[1:] if c not in CURL_SHORT_NOARG]
            if bad:
                out.append(_v("curl_flag_not_allowed", f"curl {tok} isn't allowed in an HTTP check", step))
            i += 1
            continue
        urls.append(tok)
        i += 1
    if len(urls) != 1:
        out.append(_v("http_url_denied", "an HTTP check needs exactly one URL", step))
    for url in urls:
        out += check_http_url(url, rules, step)
    return out


def _check_npm(argv: Sequence[str], rules: EffectiveRules, step: int | None) -> list[Violation]:
    out: list[Violation] = []
    i = 1
    while i < len(argv) and argv[i].startswith("-"):
        tok = argv[i]
        if tok in NPM_GLOBAL_WITH_VALUE:
            i += 2
        elif tok.split("=", 1)[0] in NPM_GLOBAL_WITH_VALUE or tok in NPM_GLOBAL_NO_VALUE:
            i += 1
        else:
            out.append(_v("npm_option_denied", f"npm option {tok} isn't allowed before the subcommand", step))
            i += 1
    sub = argv[i] if i < len(argv) else None
    out += _check_subcommand("npm", sub, rules.allow["npm"], step)
    for tok in argv[1:]:
        hit = _flag_denied(tok, NPM_DENY_ANYWHERE)
        if hit:
            out.append(_v("npm_option_denied", f"npm {tok} isn't allowed ({hit})", step))
    return out


# --- paths --------------------------------------------------------------------------------------------


def path_candidates(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """(tokens to resolve as paths, short flags with attached paths).

    Every non-flag token is checked as a path relative to cwd, not only ones that look like paths: a bare
    name can be a symlink out of the workspace. Values that aren't files simply resolve inside cwd.
    """
    paths: list[str] = []
    attached: list[str] = []
    end_of_options = False
    for tok in argv[1:]:
        if not end_of_options and tok == "--":
            end_of_options = True
            continue
        if not end_of_options and tok.startswith("-") and tok != "-":
            if tok.startswith("--"):
                if "=" in tok:
                    paths.append(tok.split("=", 1)[1])
            elif "/" in tok:
                attached.append(tok)
            continue
        paths.append(tok)
    keep = [p for p in paths if p and p != "-" and not is_url(p) and not is_placeholder(p)]
    return keep, attached


def check_path(
    token: str,
    cwd: str,
    rules: EffectiveRules,
    resolver: PathResolver,
    step: int | None,
    *,
    what: str = "path",
) -> list[Violation]:
    if token.startswith("~"):
        return [_v("tilde_path", f"{what} {token}: ~ isn't expanded (no shell); use an absolute path", step)]
    try:
        res = resolver.resolve(token, cwd)
    except ResolveError as exc:
        return [_v("path_unresolvable", f"{what} {token}: {exc}", step)]
    for p in (res.lexical, res.real):
        hit = within_any(p, rules.deny_paths)
        if hit:
            return [_v("denied_path", f"{what} {token} resolves to {p}, inside deny_paths {hit}", step)]
    roots = " ".join(rules.workspace_roots)
    if not within_any(res.lexical, rules.workspace_roots):
        return [
            _v(
                "outside_workspace",
                f"{what} {token} resolves to {res.lexical}, outside workspace_roots {roots}",
                step,
            )
        ]
    if not within_any(res.real, rules.workspace_roots):
        return [
            _v(
                "symlink_escape",
                f"{what} {token}: realpath {res.lexical} → {res.real} leaves workspace_roots {roots}",
                step,
            )
        ]
    return []


def check_cwd(cwd: str, rules: EffectiveRules, resolver: PathResolver, step: int | None) -> list[Violation]:
    if not cwd.startswith("/") or not all(is_ascii_printable(c) for c in cwd):
        return [_v("bad_cwd", f"cwd {cwd!r} must be an absolute ASCII path", step)]
    return check_path(cwd, "/", rules, resolver, step, what="cwd")


def check_paths(
    argv: Sequence[str], cwd: str, rules: EffectiveRules, resolver: PathResolver, step: int | None
) -> list[Violation]:
    tokens, attached = path_candidates(argv)
    out = [
        _v("attached_path_value", f"{tok}: put the value in its own argument (e.g. -C /path)", step)
        for tok in attached
    ]
    for tok in tokens:
        out += check_path(tok, cwd, rules, resolver, step)
    return out


def check_deny_patterns(
    raw: str, argv: Sequence[str], rules: EffectiveRules, step: int | None
) -> list[Violation]:
    joined = shlex.join(argv)
    out = []
    for dp in rules.deny_patterns:
        if dp.regex.search(raw) or dp.regex.search(joined):
            where = (
                f"group {dp.group}: matches deny pattern" if dp.group else "matches commands.deny_patterns"
            )
            out.append(_v("deny_pattern", f"{where} “{dp.source}”", step, dp.group))
    return out


# --- entry point --------------------------------------------------------------------------------------


def check_program(
    kind: StepKind, argv: Sequence[str], rules: EffectiveRules, step: int | None
) -> list[Violation]:
    program = argv[0]
    if "/" in program:
        return [_v("program_path", f"{program}: use the bare program name, not a path", step)]
    expected = PROGRAM_KIND.get(program, StepKind.SHELL)
    out: list[Violation] = []
    if kind != expected:
        out.append(_v("kind_mismatch", f"{program} must be a {expected.value} step, not {kind.value}", step))
    rule = rules.allow.get(program)
    if rule is None:
        out.append(_v("program_not_allowed", f"{program} isn't in commands.allow", step))
        return out
    if program == "git":
        out += _check_git(argv, rules, step)
    elif program == "docker":
        out += _check_docker(argv, rules, step)
    elif program == "curl":
        out += check_curl(argv, rules, step)
    elif program == "npm":
        out += _check_npm(argv, rules, step)
    elif rule.subcommands is not None:
        sub, _ = _subcommand(argv, 1)
        out += _check_subcommand(program, sub, rule, step)
    out += _check_flags_deny(argv, rule, step)
    return out
