"""Section 16 rule 3: no shell=True, os.system or string-built commands. Plus: no invisible characters in
any source, config or fixture file (they can make code or rules read differently from what runs)."""

from __future__ import annotations

import ast
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "backend" / "src"
BANNED_CALLS = {
    ("os", "system"),
    ("os", "popen"),
    ("os", "execl"),
    ("os", "execlp"),
    ("os", "spawnl"),
    ("subprocess", "getoutput"),
    ("subprocess", "getstatusoutput"),
    ("pty", "spawn"),
}


def _python_files() -> list[Path]:
    return sorted(p for p in SRC.rglob("*.py"))


@pytest.mark.parametrize("path", _python_files(), ids=lambda p: str(p.relative_to(SRC)))
def test_no_shell_execution(path: Path) -> None:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for kw in node.keywords:
            assert not (
                kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
            ), f"{path}:{node.lineno}: shell=True"
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            assert (func.value.id, func.attr) not in BANNED_CALLS, (
                f"{path}:{node.lineno}: {func.value.id}.{func.attr}"
            )
            if (
                func.value.id == "subprocess"
                and node.args
                and isinstance(node.args[0], ast.Constant | ast.JoinedStr)
            ):
                pytest.fail(f"{path}:{node.lineno}: subprocess called with a string command")


def _text_files() -> list[Path]:
    exts = {".py", ".yaml", ".yml", ".json", ".toml", ".md"}
    skip = {".venv", ".git", "node_modules", ".mypy_cache", ".ruff_cache", ".pytest_cache", "prototypes"}
    return sorted(p for p in ROOT.rglob("*") if p.suffix in exts and p.is_file() and not skip & set(p.parts))


def test_no_invisible_or_bidi_characters_in_repo() -> None:
    bad = []
    for path in _text_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for ch in line:
                cat = unicodedata.category(ch)
                if cat in ("Cc", "Cf", "Zl", "Zp", "Co") or (cat == "Zs" and ch != " "):
                    bad.append(f"{path.relative_to(ROOT)}:{lineno}: U+{ord(ch):04X}")
    assert bad == []
