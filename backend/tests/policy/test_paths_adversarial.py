"""Symlink and traversal attacks against a real filesystem (what the agent does with realpath, README 7A).

A fake target filesystem is built under tmp_path and mapped to `/` by LocalResolver(root=tmp_path).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from policyhelp import mkstep, rules_for

from warden.policy.engine import check_step
from warden.policy.paths import LexicalResolver, LocalResolver, ResolveError, is_path_like, lexical_join
from warden.policy.readonly import check_read_only


@pytest.fixture
def fs(tmp_path: Path) -> LocalResolver:
    app = tmp_path / "srv/dev/myapp"
    app.mkdir(parents=True)
    (app / "package.json").write_text("{}")
    (app / "src").mkdir()
    (tmp_path / "srv/dev/other").mkdir()
    (tmp_path / "srv/prod/app").mkdir(parents=True)
    (tmp_path / "var/cache/npm/_cacache").mkdir(parents=True)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/shadow").write_text("secret")
    (tmp_path / "home/admin/.ssh").mkdir(parents=True)

    # The prototype's case: .cache is a symlink to /var/cache/npm (relative, so it stays in tmp_path).
    os.symlink("../../../var/cache/npm", app / ".cache")
    os.symlink("../../prod/app", app / "prod-link")  # into a denied path
    os.symlink("/etc/shadow", app / "abs-shadow")  # absolute: points at the host's real /etc
    os.symlink("../../../etc/shadow", app / "rel-shadow")
    os.symlink("src", app / "inside-link")  # stays inside: fine
    os.symlink("loop-b", app / "loop-a")
    os.symlink("loop-a", app / "loop-b")
    os.symlink("../../../etc/does-not-exist", app / "dangling")
    os.symlink("../../../var/cache/npm", app / "sub-escape")
    os.symlink("../../../home/admin", tmp_path / "srv/dev/other/home-link")
    return LocalResolver(root=str(tmp_path))


def codes(
    command: str, resolver: LocalResolver, kind: str = "shell", cwd: str = "/srv/dev/myapp"
) -> list[str]:
    return [v.code for v in check_step(mkstep(command, kind, cwd), rules_for("dev"), resolver)]


def test_resolver_follows_symlink_out(fs: LocalResolver) -> None:
    res = fs.resolve(".cache/_cacache", "/srv/dev/myapp")
    assert res.lexical == "/srv/dev/myapp/.cache/_cacache"
    assert res.real == "/var/cache/npm/_cacache"


def test_prototype_cache_symlink_is_refused(fs: LocalResolver) -> None:
    # pln_01JB6T2Q step 2: rm under a symlinked .cache. Central lexical check can't see it; the agent can.
    lexical = check_step(
        mkstep("npm run /srv/dev/myapp/.cache/_cacache"), rules_for("dev"), LexicalResolver()
    )
    assert lexical == ()
    assert "symlink_escape" in codes("npm run /srv/dev/myapp/.cache/_cacache", fs)


def test_symlink_into_denied_path(fs: LocalResolver) -> None:
    assert "denied_path" in codes("npm --prefix prod-link ci", fs)


def test_absolute_symlink_to_host_etc(fs: LocalResolver) -> None:
    assert codes("npm run abs-shadow", fs)


def test_relative_symlink_to_etc(fs: LocalResolver) -> None:
    got = codes("npm run rel-shadow", fs)
    assert "denied_path" in got
    assert "baseline_protected_path" in got


def test_bare_name_symlink_is_checked(fs: LocalResolver) -> None:
    # Not path-like (no slash) but still a symlink out of the workspace.
    assert "symlink_escape" in codes("npm run sub-escape", fs)


def test_symlink_then_dotdot(fs: LocalResolver) -> None:
    # Lexically `sub-escape/../shadow` is inside myapp; the kernel goes through the link first.
    assert codes("npm run sub-escape/../npm/_cacache", fs)
    assert "symlink_escape" in codes("npm run sub-escape/..", fs)


def test_symlink_loop_is_refused(fs: LocalResolver) -> None:
    with pytest.raises(ResolveError):
        fs.resolve("loop-a", "/srv/dev/myapp")
    assert "path_unresolvable" in codes("npm run loop-a", fs)


def test_dangling_symlink_is_followed(fs: LocalResolver) -> None:
    assert fs.resolve("dangling", "/srv/dev/myapp").real == "/etc/does-not-exist"
    assert "denied_path" in codes("npm run dangling", fs)


def test_nonexistent_with_dotdot_is_refused(fs: LocalResolver) -> None:
    assert "path_unresolvable" in codes("npm --prefix nope/../../x ci", fs)


def test_inside_symlink_is_fine(fs: LocalResolver) -> None:
    assert codes("npm --prefix inside-link ci", fs) == []


def test_new_path_inside_workspace_is_fine(fs: LocalResolver) -> None:
    cmd = "git clone https://github.com/you/x /srv/dev/new-repo"
    assert codes(cmd, fs, kind="git", cwd="/srv/dev") == []


def test_cwd_that_is_a_symlink_out(fs: LocalResolver) -> None:
    assert "symlink_escape" in codes("npm ci", fs, cwd="/srv/dev/myapp/.cache")


def test_read_only_through_symlink(fs: LocalResolver) -> None:
    got = [v.code for v in check_read_only("cat /srv/dev/myapp/rel-shadow", rules_for("dev"), fs)]
    assert "denied_path" in got


def test_read_only_dir_symlink_to_home(fs: LocalResolver) -> None:
    got = [v.code for v in check_read_only("ls /srv/dev/other/home-link/.ssh", rules_for("dev"), fs)]
    assert "denied_path" in got


def test_read_only_plain_file_ok(fs: LocalResolver) -> None:
    assert check_read_only("cat /srv/dev/myapp/package.json", rules_for("dev"), fs) == ()


@pytest.mark.parametrize(
    ("cwd", "path", "expected"),
    [
        ("/srv/dev", "x", "/srv/dev/x"),
        ("/srv/dev", "../x", "/srv/x"),
        ("/srv/dev", "/a/../../b", "/b"),
        ("/srv/dev", "//etc", "/etc"),
        ("/srv/dev", "./././x/.", "/srv/dev/x"),
    ],
)
def test_lexical_join(cwd: str, path: str, expected: str) -> None:
    assert lexical_join(cwd, path) == expected


@pytest.mark.parametrize(
    ("token", "expected"),
    [
        ("/x", True),
        ("./x", True),
        ("../x", True),
        ("..", True),
        ("~", True),
        ("a/b", True),
        ("name", False),
        ("https://x/y", False),
        ("v1.4.2", False),
    ],
)
def test_is_path_like(token: str, expected: bool) -> None:
    assert is_path_like(token) is expected
