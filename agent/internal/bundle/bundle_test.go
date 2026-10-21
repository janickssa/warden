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

func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	be, ok := err.(*Error)
	if !ok || be.Code != code {
		t.Fatalf("expected %s, got %v", code, err)
	}
}

func enrollOpts() Options { return Options{OwnTarget: "dev", AgentVersion: "0.1.0"} }

func after(cur *Verified) Options {
	return Options{Current: cur, OwnTarget: "dev", AgentVersion: "0.1.0"}
}

// --- Python-signed vectors -------------------------------------------------------------------------

func TestPythonSignedBundlesVerify(t *testing.T) {
	v := loadVectors(t)
	tr := Trust{OnlineKeyID: v.OnlineKeyID, OnlinePublic: v.OnlinePublic}
	v1, err := Verify(encode(t, v.BundleV1), tr, enrollOpts())
	if err != nil {
		t.Fatal(err)
	}
	if v1.Bundle.Version != 1 || v1.Rules.Target != "dev" || len(v1.ApprovalKeys) != 1 || v1.Class != "initial" {
		t.Fatalf("unexpected bundle %+v", v1.Bundle)
	}
	v2, err := Verify(encode(t, v.BundleV2), tr, after(v1))
	if err != nil {
		t.Fatal(err)
	}
	if v2.Class != "none" {
		t.Fatalf("same rules should classify as none, got %s", v2.Class)
	}
}

func TestRefusals(t *testing.T) {
	v := loadVectors(t)
	tr := Trust{OnlineKeyID: v.OnlineKeyID, OnlinePublic: v.OnlinePublic}
	v1, err := Verify(encode(t, v.BundleV1), tr, enrollOpts())
	if err != nil {
		t.Fatal(err)
	}

	unsigned := clone(t, v.BundleV1)
	unsigned["signatures"] = []any{}
	_, err = Verify(encode(t, unsigned), tr, enrollOpts())
	expectCode(t, err, "unsigned")

	tampered := clone(t, v.BundleV1)
	tampered["rules"].(map[string]any)["deny_paths"] = []any{}
	_, err = Verify(encode(t, tampered), tr, enrollOpts())
	expectCode(t, err, "bad_signature")

	extra := clone(t, v.BundleV1)
	extra["surprise"] = true
	_, err = Verify(encode(t, extra), tr, enrollOpts())
	expectCode(t, err, "unknown_field")

	_, err = Verify(encode(t, v.BundleV1), tr, Options{OwnTarget: "dev2", AgentVersion: "0.1.0"})
	expectCode(t, err, "wrong_target")

	_, err = Verify(encode(t, v.BundleV1), tr, after(v1)) // same version again
	expectCode(t, err, "old_version")

	_, err = Verify(encode(t, v.BundleV1), tr, Options{OwnTarget: "dev", AgentVersion: "0.0.9"})
	expectCode(t, err, "agent_too_old")

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	other := Trust{OnlineKeyID: v.OnlineKeyID, OnlinePublic: base64.RawURLEncoding.EncodeToString(pub)}
	_, err = Verify(encode(t, v.BundleV1), other, enrollOpts())
	expectCode(t, err, "bad_signature")

	dup := bytes.Replace(encode(t, v.BundleV1), []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)
	_, err = Verify(dup, tr, enrollOpts())
	expectCode(t, err, "bad_bundle")

	_, err = Verify(encode(t, v.BundleV2), tr, enrollOpts()) // non-initial at enrollment
	expectCode(t, err, "bad_change")
}

// --- Bundles signed here, to exercise tighten/loosen -----------------------------------------------

type signer struct {
	t       *testing.T
	online  ed25519.PrivateKey
	offline ed25519.PrivateKey
	backup  ed25519.PrivateKey
	trust   Trust
	base    map[string]any // the Python v1 bundle content, unsigned
}

func newSigner(t *testing.T) *signer {
	v := loadVectors(t)
	pubOn, privOn, _ := ed25519.GenerateKey(rand.Reader)
	pubOff, privOff, _ := ed25519.GenerateKey(rand.Reader)
	pubBk, privBk, _ := ed25519.GenerateKey(rand.Reader)
	b64 := base64.RawURLEncoding.EncodeToString
	base := clone(t, v.BundleV1)
	delete(base, "signatures")
	return &signer{t: t, online: privOn, offline: privOff, backup: privBk, base: base, trust: Trust{
		OnlineKeyID: "ed25519:on", OnlinePublic: b64(pubOn),
		OfflineKeys: []KeyRef{{KeyID: "ed25519:off", Public: b64(pubOff)}, {KeyID: "ed25519:bk", Public: b64(pubBk)}},
	}}
}

// make builds a bundle: edit changes the rules, extra signers are "offline" or "backup".
func (s *signer) make(version int, change string, edit func(rules map[string]any), extra ...string) []byte {
	b := clone(s.t, s.base)
	b["version"] = version
	b["change"] = change
	if edit != nil {
		edit(b["rules"].(map[string]any))
	}
	msg := append([]byte(domain), mustCanonical(s.t, b)...)
	sign := func(key, id string, priv ed25519.PrivateKey) map[string]any {
		return map[string]any{"key": key, "key_id": id, "alg": "ed25519",
			"sig": "ed25519:" + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, msg))}
	}
	sigs := []any{sign("online", "ed25519:on", s.online)}
	for _, e := range extra {
		switch e {
		case "offline":
			sigs = append(sigs, sign("offline", "ed25519:off", s.offline))
		case "backup":
			sigs = append(sigs, sign("offline", "ed25519:bk", s.backup))
		case "stranger":
			_, p, _ := ed25519.GenerateKey(rand.Reader)
			sigs = append(sigs, sign("offline", "ed25519:off", p))
		}
	}
	b["signatures"] = sigs
	return encode(s.t, b)
}

func (s *signer) enrolled() *Verified {
	v1, err := Verify(s.make(1, "initial", nil), s.trust, enrollOpts())
	if err != nil {
		s.t.Fatal(err)
	}
	return v1
}

func removeEtc(r map[string]any) {
	r["deny_paths"] = []any{"/root", "/home", "/var/lib/docker", "/srv/prod"}
}
func addDeny(r map[string]any) {
	r["deny_paths"] = append(r["deny_paths"].([]any), "/srv/dev/secret")
}

func TestTighteningNeedsOnlyTheOnlineKey(t *testing.T) {
	s := newSigner(t)
	got, err := Verify(s.make(2, "tighten", addDeny), s.trust, after(s.enrolled()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != "tighten" {
		t.Fatalf("class %s", got.Class)
	}
}

// A compromised Warden labels a loosening as "tighten" and signs it with the online key only.
func TestMislabelledLooseningRefused(t *testing.T) {
	s := newSigner(t)
	_, err := Verify(s.make(2, "tighten", removeEtc), s.trust, after(s.enrolled()))
	expectCode(t, err, "needs_offline_signature")
	addProgram := func(r map[string]any) {
		r["allow"].(map[string]any)["rm"] = map[string]any{"subcommands": nil, "flags_deny": []any{}}
	}
	_, err = Verify(s.make(2, "tighten", addProgram), s.trust, after(s.enrolled()))
	expectCode(t, err, "needs_offline_signature")
	liftLockdown := func(r map[string]any) { r["lockdown"] = false }
	locked := func(r map[string]any) { r["lockdown"] = true }
	cur, err := Verify(s.make(2, "tighten", locked), s.trust, after(s.enrolled()))
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(s.make(3, "tighten", liftLockdown), s.trust, after(cur))
	expectCode(t, err, "needs_offline_signature")
}

func TestLooseningWithOfflineSignatureAccepted(t *testing.T) {
	s := newSigner(t)
	got, err := Verify(s.make(2, "loosen", removeEtc, "offline"), s.trust, after(s.enrolled()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != "loosen" {
		t.Fatalf("class %s", got.Class)
	}
	if _, err := Verify(s.make(2, "loosen", removeEtc, "backup"), s.trust, after(s.enrolled())); err != nil {
		t.Fatalf("backup offline key should be accepted: %v", err)
	}
}

func TestOfflineSignatureFromUnknownKeyRefused(t *testing.T) {
	s := newSigner(t)
	_, err := Verify(s.make(2, "loosen", removeEtc, "stranger"), s.trust, after(s.enrolled()))
	expectCode(t, err, "needs_offline_signature")
}

func TestNoOfflineKeyMeansNothingCanLoosen(t *testing.T) {
	s := newSigner(t)
	tr := s.trust
	tr.OfflineKeys = nil
	v1, err := Verify(s.make(1, "initial", nil), tr, enrollOpts())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(s.make(2, "loosen", removeEtc, "offline"), tr, after(v1))
	expectCode(t, err, "needs_offline_signature")
}

func TestLooseLabelRaisesTheBar(t *testing.T) {
	s := newSigner(t)
	_, err := Verify(s.make(2, "loosen", addDeny), s.trust, after(s.enrolled()))
	expectCode(t, err, "needs_offline_signature")
}

func TestInitialOnlyAtEnrollment(t *testing.T) {
	s := newSigner(t)
	_, err := Verify(s.make(5, "initial", nil), s.trust, after(s.enrolled()))
	expectCode(t, err, "bad_change")
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
