"""Unicode rules shared by plans, policy and audit (DECISIONS D-08, D-09, D-21).

Text is NFC-normalised once at intake. After that, everything that is stored, shown and hashed is the
normalised form, and the checks below refuse anything that could hide or disguise what a human reads.
"""

from __future__ import annotations

import unicodedata

from warden.errors import InputRefused

# Categories that are never acceptable anywhere: control, format (zero-width, bidi), separators other
# than the ASCII space, private use, surrogates and unassigned code points.
_FORBIDDEN_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"})


def codepoint(ch: str) -> str:
    return f"U+{ord(ch):04X}"


def normalize(text: str) -> str:
    """NFC-normalise. Called once at intake; everything downstream sees the normalised text."""
    return unicodedata.normalize("NFC", text)


def is_nfc(text: str) -> bool:
    return unicodedata.is_normalized("NFC", text)


def invisible_or_control(ch: str) -> bool:
    if ch == " ":
        return False
    cat = unicodedata.category(ch)
    return cat in _FORBIDDEN_CATEGORIES or (cat == "Zs")


def check_free_text(text: str, *, field: str, max_len: int, allow_newlines: bool = False) -> None:
    """Goal, purpose, reasons, notes: printable text a human reads. Refuses invisible/control characters.

    Raises InputRefused naming the field and code point.
    """
    if not is_nfc(text):
        raise InputRefused(f"{field} is not NFC-normalised", code="not_nfc")
    if len(text) > max_len:
        raise InputRefused(f"{field} is longer than {max_len} characters", code="too_long")
    for i, ch in enumerate(text):
        if allow_newlines and ch == "\n":
            continue
        if invisible_or_control(ch):
            raise InputRefused(
                f"{field} contains an invisible or control character {codepoint(ch)} at position {i}",
                code="disallowed_char",
            )


def is_ascii_printable(ch: str) -> bool:
    return 0x20 <= ord(ch) <= 0x7E


def is_latin_letter(ch: str) -> bool:
    """Latin-1 Supplement and Latin Extended-A letters (æ ø å é ü ...). Excludes × and ÷."""
    o = ord(ch)
    if 0xC0 <= o <= 0xFF:
        return o not in (0xD7, 0xF7)
    return 0x100 <= o <= 0x17F
