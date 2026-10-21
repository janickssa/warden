package canonical

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func fixtures(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures")
}

func TestSharedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixtures(t), "canonical_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Name      string          `json:"name"`
		Value     json.RawMessage `json:"value"`
		Canonical string          `json:"canonical"`
		SHA256    string          `json:"sha256"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vectors {
		got, err := Canonicalize(v.Value)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if string(got) != v.Canonical {
			t.Errorf("%s:\n got %s\nwant %s", v.Name, got, v.Canonical)
		}
		sum := sha256.Sum256(got)
		if hex.EncodeToString(sum[:]) != v.SHA256 {
			t.Errorf("%s: sha256 mismatch", v.Name)
		}
	}
}

func TestRefuses(t *testing.T) {
	cases := map[string]string{
		"float":        `{"a":1.5}`,
		"exponent":     `{"a":1e3}`,
		"unsafe int":   `{"a":9007199254740992}`,
		"duplicate":    `{"a":1,"a":2}`,
		"nested dup":   `{"x":{"b":1,"b":1}}`,
		"non-NFC":      "{\"m\":\"a\u030a\"}",
		"trailing":     `{"a":1} {}`,
		"invalid json": `{"a":`,
	}
	for name, in := range cases {
		if _, err := Canonicalize([]byte(in)); !errors.Is(err, ErrNotCanonical) {
			t.Errorf("%s: expected ErrNotCanonical, got %v", name, err)
		}
	}
}

func TestControlCharsEscapedLikePython(t *testing.T) {
	got, err := Canonicalize([]byte(`{"a":"x\u0001\n\t\u001f"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":"x\u0001\n\t\u001f"}` {
		t.Fatalf("got %s", got)
	}
}
