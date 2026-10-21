"""Input hygiene and tokenising (DECISIONS D-09).

Commands run as argv without a shell, so shell syntax is never needed and is refused outright, quoted or
not. After splitting, each argv element is checked by its position:

* program name, flags (the part before `=`), paths and URLs: ASCII only, which stops look-alike letters;
* other values (commit messages and the like): ASCII plus Latin-script letters such as æ ø å.

Invisible, control and bidi characters are refused everywhere.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

from warden.errors import InputRefused
from warden.plans.placeholders import contains_brace_pair, is_placeholder
from warden.policy.paths import is_path_like, is_url
from warden.text import codepoint, invisible_or_control, is_ascii_printable, is_latin_letter, is_nfc

FORBIDDEN_CHARS = frozenset(";|&`$><")
MAX_COMMAND_LEN = 4096
MAX_ARGS = 256


class LexRefused(InputRefused):
    code = "lex_refused"


@dataclass(frozen=True, slots=True)
class Lexed:
    raw: str
    argv: tuple[str, ...]

    @property
    def program(self) -> str:
        return self.argv[0]


def _ascii_only(token: str, index: int, what: str) -> None:
    for ch in token:
        if not is_ascii_printable(ch):
            raise LexRefused(
                f"argv[{index}] {token!r}: {what} must be ASCII, found {codepoint(ch)} {ch!r}",
                code="non_ascii_token",
            )


def _value_chars(token: str, index: int) -> None:
    if is_path_like(token) or is_url(token):
        _ascii_only(token, index, "paths and URLs")
        return
    for ch in token:
        if not (is_ascii_printable(ch) or is_latin_letter(ch)):
            raise LexRefused(
                f"argv[{index}] {token!r}: character {codepoint(ch)} {ch!r} isn't allowed "
                "(only ASCII and Latin letters such as æ ø å)",
                code="disallowed_char",
            )


def check_raw(command: str) -> None:
    if not is_nfc(command):
        raise LexRefused("command is not NFC-normalised", code="not_nfc")
    if len(command) > MAX_COMMAND_LEN:
        raise LexRefused(f"command is longer than {MAX_COMMAND_LEN} characters", code="too_long")
    for i, ch in enumerate(command):
        if ch in FORBIDDEN_CHARS:
            raise LexRefused(
                f"{ch!r} at position {i} isn't allowed: commands run without a shell, so use separate "
                "steps instead of pipes, chaining, substitution or redirects",
                code="forbidden_char",
            )
        if invisible_or_control(ch):
            raise LexRefused(
                f"invisible or control character {codepoint(ch)} at position {i}", code="disallowed_char"
            )


def lex(command: str) -> Lexed:
    check_raw(command)
    try:
        argv = shlex.split(command, comments=False, posix=True)
    except ValueError as exc:
        raise LexRefused(f"can't parse command: {exc}", code="parse_error") from exc
    if not argv:
        raise LexRefused("empty command", code="empty_command")
    if len(argv) > MAX_ARGS:
        raise LexRefused(f"more than {MAX_ARGS} arguments", code="too_long")

    end_of_options = False
    for i, tok in enumerate(argv):
        if contains_brace_pair(tok) and not is_placeholder(tok):
            raise LexRefused(
                f"argv[{i}] {tok!r}: '{{{{' and '}}}}' are only allowed as a whole placeholder such as "
                "{{step1.container_id}} or {{secret:NAME}}",
                code="bad_placeholder",
            )
        if i == 0:
            _ascii_only(tok, i, "program names")
            continue
        if not end_of_options and tok == "--":
            end_of_options = True
            continue
        if not end_of_options and tok.startswith("-") and tok != "-":
            if tok.startswith("--") and "=" in tok:
                name, value = tok.split("=", 1)
                _ascii_only(name, i, "flag names")
                _value_chars(value, i)
            else:
                _ascii_only(tok, i, "flags")
            continue
        _value_chars(tok, i)
    return Lexed(raw=command, argv=tuple(argv))
