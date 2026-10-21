package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/janickssa/warden/agent/internal/canonical"
)

type vectors struct {
	OnlinePublic string         `json:"online_public"`
	OnlineKeyID  string         `json:"online_key_id"`
	BundleV1     map[string]any `json:"bundle_v1"`
	BundleV2     map[string]any `json:"bundle_v2_tighten"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures", "agent_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func encode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(buf.Bytes())
}

func clone(t *testing.T, m map[string]any) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(encode(t, m), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func opts(installed int) Options {
	return Options{InstalledVersion: installed, OwnTarget: "dev", AgentVersion: "0.1.0"}
}

func trust(v vectors) Trust { return Trust{OnlineKeyID: v.OnlineKeyID, OnlinePublic: v.OnlinePublic} }

func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	be, ok := err.(*Error)
	if !ok || be.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func TestPythonSignedBundleVerifies(t *testing.T) {
	v := loadVectors(t)
	got, err := Verify(encode(t, v.BundleV1), trust(v), opts(0))
	if err != nil {
		t.Fatal(err)
	}
	if got.Bundle.Version != 1 || got.Rules.Target != "dev" || len(got.ApprovalKeys) != 1 {
		t.Fatalf("unexpected bundle %+v", got.Bundle)
	}
	if _, err := Verify(encode(t, v.BundleV2), trust(v), opts(1)); err != nil {
		t.Fatal(err)
	}
}

func TestRefusals(t *testing.T) {
	v := loadVectors(t)
	tr := trust(v)

	unsigned := clone(t, v.BundleV1)
	unsigned["signatures"] = []any{}
	_, err := Verify(encode(t, unsigned), tr, opts(0))
	expectCode(t, err, "unsigned")

	tampered := clone(t, v.BundleV1)
	tampered["rules"].(map[string]any)["deny_paths"] = []any{}
	_, err = Verify(encode(t, tampered), tr, opts(0))
	expectCode(t, err, "bad_signature")

	extra := clone(t, v.BundleV1)
	extra["surprise"] = true
	_, err = Verify(encode(t, extra), tr, opts(0))
	expectCode(t, err, "unknown_field")

	_, err = Verify(encode(t, v.BundleV1), tr, Options{OwnTarget: "dev2", AgentVersion: "0.1.0"})
	expectCode(t, err, "wrong_target")

	_, err = Verify(encode(t, v.BundleV1), tr, opts(1)) // same version again
	expectCode(t, err, "old_version")
	_, err = Verify(encode(t, v.BundleV2), tr, opts(5)) // older than installed
	expectCode(t, err, "old_version")

	_, err = Verify(encode(t, v.BundleV1), tr, Options{OwnTarget: "dev", AgentVersion: "0.0.9"})
	expectCode(t, err, "agent_too_old")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other := Trust{OnlineKeyID: v.OnlineKeyID, OnlinePublic: base64.RawURLEncoding.EncodeToString(pub)}
	_, err = Verify(encode(t, v.BundleV1), other, opts(0))
	expectCode(t, err, "bad_signature")

	dup := bytes.Replace(encode(t, v.BundleV1), []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
	_, err = Verify(dup, tr, opts(0))
	expectCode(t, err, "bad_bundle")
}

func TestInitialOnlyAtEnrollment(t *testing.T) {
	v := loadVectors(t)
	b := clone(t, v.BundleV1)
	b["version"] = 7 // signature now invalid too, but the sequencing check comes first
	_, err := Verify(encode(t, b), trust(v), opts(3))
	expectCode(t, err, "bad_change")
}

// A loosening bundle signed only by the online key (the only key a compromised Warden has) is refused.
func TestLoosenNeedsOfflineKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tr := Trust{OnlineKeyID: "ed25519:test", OnlinePublic: base64.RawURLEncoding.EncodeToString(pub)}
	v := loadVectors(t)
	b := clone(t, v.BundleV2)
	b["change"] = "loosen"
	delete(b, "signatures")
	body := mustCanonical(t, b)
	sig := ed25519.Sign(priv, append([]byte(domain), body...))
	b["signatures"] = []any{map[string]any{"key": "online", "key_id": "ed25519:test", "alg": "ed25519",
		"sig": "ed25519:" + base64.RawURLEncoding.EncodeToString(sig)}}
	_, err := Verify(encode(t, b), tr, opts(1))
	expectCode(t, err, "needs_offline_signature")

	// Same bundle as "tighten" is accepted, proving the signature itself is fine.
	b2 := clone(t, b)
	b2["change"] = "tighten"
	delete(b2, "signatures")
	sig2 := ed25519.Sign(priv, append([]byte(domain), mustCanonical(t, b2)...))
	b2["signatures"] = []any{map[string]any{"key": "online", "key_id": "ed25519:test", "alg": "ed25519",
		"sig": "ed25519:" + base64.RawURLEncoding.EncodeToString(sig2)}}
	if _, err := Verify(encode(t, b2), tr, opts(1)); err != nil {
		t.Fatal(err)
	}
}

func TestAtLeast(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"1.3.2", "1.3.0", true}, {"1.3.0", "1.3.0", true}, {"1.2.9", "1.3.0", false}, {"2.0.0", "1.9.9", true}, {"x", "1.0.0", false}}
	for _, c := range cases {
		if AtLeast(c.a, c.b) != c.want {
			t.Errorf("AtLeast(%s, %s) != %v", c.a, c.b, c.want)
		}
	}
}

func TestWriteFileAtomic(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bundle.json")
	if err := WriteFileAtomic(p, []byte("a"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("b"), 0o600); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(data) != "b" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("got %q %v", data, fi.Mode())
	}
}

func mustCanonical(t *testing.T, v map[string]any) []byte {
	t.Helper()
	generic, err := canonical.Decode(encode(t, v))
	if err != nil {
		t.Fatal(err)
	}
	out, err := canonical.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
