// Package canonical implements Warden's canonical JSON (DECISIONS D-08) and plan hashing.
//
// It must produce byte-for-byte the same output as backend/src/warden/plans/canonical.py: sorted keys, no
// insignificant whitespace, UTF-8 without escaping non-ASCII, integers only (within ±2^53-1), strings
// already NFC. Both implementations run policy-fixtures/canonical_vectors.json.
package canonical

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const maxSafeInt = 1<<53 - 1

// ErrNotCanonical is wrapped by every error from this package.
var ErrNotCanonical = errors.New("not canonical")

func fail(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrNotCanonical, fmt.Sprintf(format, args...))
}

// Decode parses JSON into plain values (map[string]any, []any, string, json.Number, bool, nil).
// Duplicate keys, floats, unsafe integers, non-NFC strings and trailing data are refused.
func Decode(data []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fail("trailing data after JSON value")
	}
	return v, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fail("invalid JSON: %v", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			obj := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fail("invalid JSON: %v", err)
				}
				key, ok := kt.(string)
				if !ok {
					return nil, fail("object key is not a string")
				}
				if _, dup := obj[key]; dup {
					return nil, fail("duplicate key %q", key)
				}
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				obj[key] = val
			}
			if _, err := dec.Token(); err != nil {
				return nil, fail("invalid JSON: %v", err)
			}
			return obj, nil
		case '[':
			arr := []any{}
			for dec.More() {
				val, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fail("invalid JSON: %v", err)
			}
			return arr, nil
		}
		return nil, fail("unexpected delimiter %v", t)
	default:
		return t, nil
	}
}

// Marshal encodes a decoded value (see Decode) canonically.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v, "$"); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func encode(buf *bytes.Buffer, v any, path string) error {
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			return fail("%s: floats are not allowed", path)
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok || n.CmpAbs(big.NewInt(maxSafeInt)) > 0 {
			return fail("%s: integer outside the safe range", path)
		}
		buf.WriteString(n.String())
	case int:
		return encode(buf, json.Number(fmt.Sprint(t)), path)
	case int64:
		return encode(buf, json.Number(fmt.Sprint(t)), path)
	case string:
		return encodeString(buf, t, path)
	case []any:
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encode(buf, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys) // byte order of UTF-8 == code point order, same as Python
		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := encodeString(buf, k, path); err != nil {
				return err
			}
			buf.WriteByte(':')
			if err := encode(buf, t[k], path+"."+k); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fail("%s: unsupported type %T", path, v)
	}
	return nil
}

// encodeString matches Python's json.dumps(..., ensure_ascii=False).
func encodeString(buf *bytes.Buffer, s, path string) error {
	if !utf8.ValidString(s) {
		return fail("%s: invalid UTF-8", path)
	}
	if !norm.NFC.IsNormalString(s) {
		return fail("%s: string is not NFC-normalised", path)
	}
	buf.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			buf.WriteString(`\"`)
		case '\\':
			buf.WriteString(`\\`)
		case '\n':
			buf.WriteString(`\n`)
		case '\r':
			buf.WriteString(`\r`)
		case '\t':
			buf.WriteString(`\t`)
		case '\b':
			buf.WriteString(`\b`)
		case '\f':
			buf.WriteString(`\f`)
		default:
			if r < 0x20 {
				fmt.Fprintf(buf, `\u%04x`, r)
			} else {
				buf.WriteRune(r)
			}
		}
	}
	buf.WriteByte('"')
	return nil
}

// Canonicalize decodes and re-encodes JSON bytes.
func Canonicalize(data []byte) ([]byte, error) {
	v, err := Decode(data)
	if err != nil {
		return nil, err
	}
	return Marshal(v)
}

// SHA256Tagged returns "sha256:<hex>".
func SHA256Tagged(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Hash returns the tagged SHA-256 of the canonical form of v.
func Hash(v any) (string, error) {
	b, err := Marshal(v)
	if err != nil {
		return "", err
	}
	return SHA256Tagged(b), nil
}
