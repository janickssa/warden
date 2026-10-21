"""Baseline rules that no policy, group or setting can override (README 7A, section 16 rule 13).

The Go agent compiles in the same list. They overlap with policy on purpose: if policy.yaml is ever
loosened by mistake, these still hold.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from warden.plans.models import Violation
from warden.plans.placeholders import is_placeholder
from warden.policy.paths import PathResolver, ResolveError, is_url, is_within

# Never touched by a step, whatever the policy says. Includes the agent's own binary, config and keys.
PROTECTED_TREES: tuple[str, ...] = (
    "/etc",
    "/usr",
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/proc",
    "/sys",
    "/dev",
    "/root",
    "/run",
    "/var/run",
    "/var/lib/docker",
    "/var/lib/warden-agent",
    "/usr/local/bin/warden-agent",
)

# Programs that are never allowed: privilege changes, shells and anything that runs other commands.
FORBIDDEN_PROGRAMS: frozenset[str] = frozenset(
    {
        "sudo", "su", "doas", "pkexec", "runuser",
        "sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "busybox",
        "env", "xargs", "nohup", "setsid", "chroot", "nsenter", "unshare", "eval", "exec",
        "timeout", "watch", "script", "expect", "find",
        "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet",
        "dd", "mount", "umount", "losetup", "mkfs", "fdisk", "parted", "wipefs",
        "systemctl", "service", "crontab", "at", "batch",
        "kill", "pkill", "killall",
        "iptables", "ip6tables", "nft", "ufw",
        "reboot", "shutdown", "poweroff", "halt", "init",
        "chown", "chgrp", "setcap", "useradd", "usermod", "passwd", "visudo",
        "warden-agent",
    }
)  # fmt: skip

# Interpreters may run files, but never inline code.
INTERPRETERS: frozenset[str] = frozenset(
    {"python", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun", "lua", "Rscript"}
)
INLINE_CODE_FLAGS: frozenset[str] = frozenset({"-c", "-e", "-E", "-r", "-p", "--eval", "--print"})

# Docker flags that break isolation. Checked as flag names, with or without "=value".
DOCKER_DANGEROUS_FLAGS: frozenset[str] = frozenset(
    {"--privileged", "--cap-add", "--device", "--security-opt", "--pid", "--ipc", "--uts", "--userns",
     "--cgroupns", "--device-cgroup-rule", "--sysctl"}
)  # fmt: skip
DOCKER_NETWORK_FLAGS: frozenset[str] = frozenset({"--network", "--net"})
DOCKER_MOUNT_FLAGS: frozenset[str] = frozenset({"-v", "--volume", "--mount"})

_SETUID_MODE = re.compile(r"^(0?[2-7][0-7]{3}|.*[ugoa]*[+=][rwxXt]*s.*)$")
_DOCKER_SOCK = re.compile(r"docker\.sock|docker-proxy\.sock")


def _v(code: str, message: str, step: int | None) -> Violation:
    return Violation(code=code, message=f"baseline: {message}", step=step)


def _flag_items(argv: Sequence[str]) -> list[tuple[str, str | None]]:
    """(flag name, attached-or-next value) pairs for long and short flags, up to `--`."""
    items: list[tuple[str, str | None]] = []
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            break
        if tok.startswith("--"):
            if "=" in tok:
                name, value = tok.split("=", 1)
                items.append((name, value))
            else:
                items.append((tok, argv[i + 1] if i + 1 < len(argv) else None))
        elif tok.startswith("-") and len(tok) > 1:
            items.append((tok[:2], tok[2:] or (argv[i + 1] if i + 1 < len(argv) else None)))
        i += 1
    return items


def _mount_source(flag: str, value: str) -> str | None:
    if flag == "--mount":
        for part in value.split(","):
            key, _, val = part.partition("=")
            if key in ("source", "src"):
                return val
        return None
    return value.split(":", 1)[0]


def check(
    argv: Sequence[str], cwd: str, resolver: PathResolver, *, step: int | None = None
) -> list[Violation]:
    out: list[Violation] = []
    program = argv[0]

    if program in FORBIDDEN_PROGRAMS or program.startswith("mkfs."):
        out.append(_v("baseline_program", f"{program} is never allowed", step))
    if program in INTERPRETERS:
        for tok in argv[1:]:
            name = tok.split("=", 1)[0]
            if name in INLINE_CODE_FLAGS or (
                tok.startswith("-")
                and not tok.startswith("--")
                and any(f"-{c}" in INLINE_CODE_FLAGS for c in tok[1:])
            ):
                out.append(_v("baseline_inline_code", f"{program} {tok} runs inline code", step))
                break

    if program == "rm":
        if any(t == "--no-preserve-root" for t in argv):
            out.append(_v("baseline_rm_root", "rm --no-preserve-root is never allowed", step))
        for tok in argv[1:]:
            if tok.startswith("-"):
                continue
            try:
                res = resolver.resolve(tok, cwd)
            except ResolveError:
                continue  # reported by the path checks
            for p in (res.lexical, res.real):
                if p.count("/") <= 1 or tok in ("/*", "/."):
                    out.append(
                        _v("baseline_rm_root", f"rm on {p} (filesystem root or a top-level directory)", step)
                    )
                    break

    if program == "chmod":
        for tok in argv[1:]:
            if not tok.startswith("-") and _SETUID_MODE.match(tok) and not tok.startswith("/"):
                out.append(_v("baseline_setuid", f"chmod {tok} sets setuid/setgid bits", step))

    if program in ("docker", "podman"):
        for name, value in _flag_items(argv):
            if name in DOCKER_DANGEROUS_FLAGS:
                out.append(_v("baseline_docker_flag", f"docker {name} is never allowed", step))
            if name in DOCKER_NETWORK_FLAGS and value is not None and value.startswith("host"):
                out.append(_v("baseline_docker_flag", f"docker {name}={value} is never allowed", step))
            if name in DOCKER_MOUNT_FLAGS and value is not None:
                src = _mount_source(name, value)
                if src is not None and src.startswith("/"):
                    norm = "/" + src.strip("/")
                    if norm == "/":
                        out.append(_v("baseline_docker_mount", "mounting / is never allowed", step))
                    elif any(is_within(norm, t) for t in PROTECTED_TREES):
                        out.append(_v("baseline_docker_mount", f"mounting {norm} is never allowed", step))
                if _DOCKER_SOCK.search(value):
                    out.append(
                        _v("baseline_docker_mount", "mounting the Docker socket is never allowed", step)
                    )

    candidates = [cwd]
    end_of_options = False
    for tok in argv[1:]:
        if not end_of_options and tok == "--":
            end_of_options = True
            continue
        if not end_of_options and tok.startswith("-"):
            if tok.startswith("--") and "=" in tok:
                candidates.append(tok.split("=", 1)[1])
            continue
        candidates.append(tok)
    for candidate in candidates:
        if not candidate or is_url(candidate) or is_placeholder(candidate):
            continue
        try:
            res = resolver.resolve(candidate, cwd)
        except ResolveError:
            continue  # reported by the path checks
        for tree in PROTECTED_TREES:
            if is_within(res.lexical, tree) or is_within(res.real, tree):
                where = res.real if is_within(res.real, tree) else res.lexical
                out.append(
                    _v("baseline_protected_path", f"{candidate} resolves to {where}, inside {tree}", step)
                )
                break
    return out
