package policy

import (
	"fmt"
	"unicode"
)

func codepoint(r rune) string { return fmt.Sprintf("U+%04X", r) }

// invisibleOrControl mirrors warden.text.invisible_or_control: control (Cc), format (Cf), line and
// paragraph separators, private use, surrogates, unassigned, and any space other than U+0020.
func invisibleOrControl(r rune) bool {
	if r == ' ' {
		return false
	}
	switch {
	case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Zl, r),
		unicode.Is(unicode.Zp, r), unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r),
		unicode.Is(unicode.Zs, r):
		return true
	}
	// Unassigned (Cn): not in any general category.
	return !unicode.In(r, unicode.L, unicode.M, unicode.N, unicode.P, unicode.S, unicode.Z, unicode.C)
}

func isASCIIPrintable(r rune) bool { return r >= 0x20 && r <= 0x7e }

// isLatinLetter: Latin-1 Supplement and Latin Extended-A letters, excluding × and ÷.
func isLatinLetter(r rune) bool {
	if r >= 0xc0 && r <= 0xff {
		return r != 0xd7 && r != 0xf7
	}
	return r >= 0x100 && r <= 0x17f
}
