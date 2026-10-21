package policy

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	maxCommandLen = 4096
	maxArgs       = 256
	forbidden     = ";|&`$><"
)

// Placeholder mirrors warden.plans.placeholders.PLACEHOLDER.
var Placeholder = regexp.MustCompile(`^\{\{(?:step(?P<step>[1-9][0-9]{0,3})\.(?P<name>[a-z][a-z0-9_]{0,31})|secret:(?P<secret>[A-Z][A-Z0-9_]{0,63}))\}\}$`)

// LexError is a refusal from the lexer, with a stable code.
type LexError struct{ Code, Message string }

func (e *LexError) Error() string { return e.Message }

func lexErr(code, format string, args ...any) *LexError {
	return &LexError{Code: code, Message: fmt.Sprintf(format, args...)}
}

func IsPlaceholder(tok string) bool { return Placeholder.MatchString(tok) }

func containsBracePair(tok string) bool {
	return strings.Contains(tok, "{{") || strings.Contains(tok, "}}")
}

func checkRaw(command string) error {
	if !utf8.ValidString(command) {
		return lexErr("disallowed_char", "command is not valid UTF-8")
	}
	if !norm.NFC.IsNormalString(command) {
		return lexErr("not_nfc", "command is not NFC-normalised")
	}
	if utf8.RuneCountInString(command) > maxCommandLen {
		return lexErr("too_long", "command is longer than %d characters", maxCommandLen)
	}
	i := 0
	for _, r := range command {
		if strings.ContainsRune(forbidden, r) {
			return lexErr("forbidden_char", "%q at position %d isn't allowed: commands run without a shell, "+
				"so use separate steps instead of pipes, chaining, substitution or redirects", string(r), i)
		}
		if invisibleOrControl(r) {
			return lexErr("disallowed_char", "invisible or control character %s at position %d", codepoint(r), i)
		}
		i++
	}
	return nil
}

// shlexSplit is Python's shlex.split(s, comments=False, posix=True).
func shlexSplit(s string) ([]string, error) {
	const (
		stNone = iota
		stWord
		stSingle
		stDouble
	)
	var out []string
	var cur strings.Builder
	state := stNone
	inToken := false
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch state {
		case stNone, stWord:
			switch {
			case c == ' ' || c == '\t' || c == '\r' || c == '\n':
				if inToken {
					out = append(out, cur.String())
					cur.Reset()
					inToken = false
				}
				state = stNone
			case c == '\'':
				state, inToken = stSingle, true
			case c == '"':
				state, inToken = stDouble, true
			case c == '\\':
				if i+1 >= len(runes) {
					return nil, fmt.Errorf("no escaped character")
				}
				i++
				cur.WriteRune(runes[i])
				state, inToken = stWord, true
			default:
				cur.WriteRune(c)
				state, inToken = stWord, true
			}
		case stSingle:
			if c == '\'' {
				state = stWord
			} else {
				cur.WriteRune(c)
			}
		case stDouble:
			switch {
			case c == '"':
				state = stWord
			case c == '\\' && i+1 < len(runes) && (runes[i+1] == '"' || runes[i+1] == '\\'):
				i++
				cur.WriteRune(runes[i])
			default:
				cur.WriteRune(c)
			}
		}
	}
	if state == stSingle || state == stDouble {
		return nil, fmt.Errorf("no closing quotation")
	}
	if inToken {
		out = append(out, cur.String())
	}
	return out, nil
}

func asciiOnly(tok string, index int, what string) error {
	for _, r := range tok {
		if !isASCIIPrintable(r) {
			return lexErr("non_ascii_token", "argv[%d] %q: %s must be ASCII, found %s %q", index, tok, what,
				codepoint(r), string(r))
		}
	}
	return nil
}

func valueChars(tok string, index int) error {
	if IsPathLike(tok) || IsURL(tok) {
		return asciiOnly(tok, index, "paths and URLs")
	}
	for _, r := range tok {
		if !isASCIIPrintable(r) && !isLatinLetter(r) {
			return lexErr("disallowed_char", "argv[%d] %q: character %s %q isn't allowed (only ASCII and "+
				"Latin letters such as æ ø å)", index, tok, codepoint(r), string(r))
		}
	}
	return nil
}

// Lex checks a command and splits it into argv (DECISIONS D-09).
func Lex(command string) ([]string, error) {
	if err := checkRaw(command); err != nil {
		return nil, err
	}
	argv, err := shlexSplit(command)
	if err != nil {
		return nil, lexErr("parse_error", "can't parse command: %v", err)
	}
	if len(argv) == 0 {
		return nil, lexErr("empty_command", "empty command")
	}
	if len(argv) > maxArgs {
		return nil, lexErr("too_long", "more than %d arguments", maxArgs)
	}
	endOfOptions := false
	for i, tok := range argv {
		if containsBracePair(tok) && !IsPlaceholder(tok) {
			return nil, lexErr("bad_placeholder", "argv[%d] %q: '{{' and '}}' are only allowed as a whole "+
				"placeholder such as {{step1.container_id}} or {{secret:NAME}}", i, tok)
		}
		if i == 0 {
			if err := asciiOnly(tok, i, "program names"); err != nil {
				return nil, err
			}
			continue
		}
		if !endOfOptions && tok == "--" {
			endOfOptions = true
			continue
		}
		if !endOfOptions && strings.HasPrefix(tok, "-") && tok != "-" {
			if strings.HasPrefix(tok, "--") && strings.Contains(tok, "=") {
				name, value, _ := strings.Cut(tok, "=")
				if err := asciiOnly(name, i, "flag names"); err != nil {
					return nil, err
				}
				if err := valueChars(value, i); err != nil {
					return nil, err
				}
			} else if err := asciiOnly(tok, i, "flags"); err != nil {
				return nil, err
			}
			continue
		}
		if err := valueChars(tok, i); err != nil {
			return nil, err
		}
	}
	return argv, nil
}

var shellUnsafe = regexp.MustCompile(`[^A-Za-z0-9_@%+=:,./-]`)

// shlexJoin is Python's shlex.join.
func shlexJoin(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		switch {
		case a == "":
			parts[i] = "''"
		case !shellUnsafe.MatchString(a):
			parts[i] = a
		default:
			parts[i] = "'" + strings.ReplaceAll(a, "'", `'"'"'`) + "'"
		}
	}
	return strings.Join(parts, " ")
}
