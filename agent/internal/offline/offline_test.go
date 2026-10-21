package offline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/janickssa/warden/agent/internal/bundle"
	"github.com/janickssa/warden/agent/internal/canonical"
)

const testN = 1 << 14

var pass = []byte("correct horse battery")

func TestGenerateUnlock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offline.key")
	f, err := Generate(path, pass, testN)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode().Perm())
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := loaded.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	if KeyID(priv.Public().(ed25519.PublicKey)) != f.KeyID || loaded.Public != f.Public {
		t.Fatal("key mismatch")
	}
	data, _ := os.ReadFile(path)
	if bytes.Contains(data, []byte(base64.RawURLEncoding.EncodeToString(priv.Seed()))) {
		t.Fatal("seed stored in clear")
	}
}

func TestWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offline.key")
	if _, err := Generate(path, pass, testN); err != nil {
		t.Fatal(err)
	}
	f, _ := Load(path)
	if _, err := f.Unlock([]byte("correct horse battery!")); err == nil {
		t.Fatal("wrong passphrase unlocked the key")
	}
}

func TestTamperedKeyIDRefused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offline.key")
	if _, err := Generate(path, pass, testN); err != nil {
		t.Fatal(err)
	}
	f, _ := Load(path)
	f.KeyID = "ed25519:0000000000000000"
	if _, err := f.Unlock(pass); err == nil {
		t.Fatal("key id is bound as associated data")
	}
}

func TestNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "offline.key")
	if _, err := Generate(path, pass, testN); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	if _, err := Generate(path, pass, testN); err == nil {
		t.Fatal("overwrote an existing key")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("key file changed")
	}
}

func TestShortPassphraseAndWeakKDFRefused(t *testing.T) {
	dir := t.TempDir()
	if _, err := Generate(filepath.Join(dir, "a.key"), []byte("short"), testN); err == nil {
		t.Fatal("short passphrase accepted")
	}
	if _, err := Generate(filepath.Join(dir, "b.key"), pass, 1<<10); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "b.key")); err == nil {
		t.Fatal("weak scrypt cost accepted on load")
	}
}

// --- warden-sign output accepted by the agent ---------------------------------------------------

type world struct {
	t       *testing.T
	online  ed25519.PrivateKey
	offline ed25519.PrivateKey
	trust   bundle.Trust
	base    map[string]any
}

func newWorld(t *testing.T) *world {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures", "agent_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		BundleV1 map[string]any `json:"bundle_v1"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	delete(v.BundleV1, "signatures")
	pubOn, privOn, _ := ed25519.GenerateKey(rand.Reader)
	path := filepath.Join(t.TempDir(), "offline.key")
	f, err := Generate(path, pass, testN)
	if err != nil {
		t.Fatal(err)
	}
	privOff, err := f.Unlock(pass)
	if err != nil {
		t.Fatal(err)
	}
	return &world{t: t, online: privOn, offline: privOff, base: v.BundleV1, trust: bundle.Trust{
		OnlineKeyID: "ed25519:on", OnlinePublic: b64.EncodeToString(pubOn),
		OfflineKeys: []bundle.KeyRef{{KeyID: f.KeyID, Public: f.Public}},
	}}
}

func encode(t *testing.T, v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(buf.Bytes())
}

func (w *world) clone() map[string]any {
	var out map[string]any
	if err := json.Unmarshal(encode(w.t, w.base), &out); err != nil {
		w.t.Fatal(err)
	}
	return out
}

// onlineSigned returns the bundle as Warden would: signed with the online key only.
func (w *world) onlineSigned(version int, change string, edit func(map[string]any)) map[string]any {
	b := w.clone()
	b["version"] = version
	b["change"] = change
	if edit != nil {
		edit(b["rules"].(map[string]any))
	}
	generic, err := canonical.Decode(encode(w.t, b))
	if err != nil {
		w.t.Fatal(err)
	}
	body, err := canonical.Marshal(generic)
	if err != nil {
		w.t.Fatal(err)
	}
	msg := append([]byte(bundleDomain), body...)
	b["signatures"] = []any{map[string]any{"key": "online", "key_id": "ed25519:on", "alg": "ed25519",
		"sig": "ed25519:" + b64.EncodeToString(ed25519.Sign(w.online, msg))}}
	return b
}

func (w *world) publishFile(prev map[string]any, next map[string]any) []byte {
	return encode(w.t, map[string]any{"v": 1, "version": next["version"], "items": []any{map[string]any{
		"target":   next["target"],
		"previous": map[string]any{"rules": prev["rules"], "approval_keys": prev["approval_keys"]},
		"bundle":   next,
	}}})
}

func removeEtc(r map[string]any) {
	r["deny_paths"] = []any{"/root", "/home", "/var/lib/docker", "/srv/prod"}
}

func TestSignedLooseningAcceptedByAgent(t *testing.T) {
	w := newWorld(t)
	v1raw := w.onlineSigned(1, "initial", nil)
	v1, err := bundle.Verify(encode(t, v1raw), w.trust, bundle.Options{OwnTarget: "dev", AgentVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	v2 := w.onlineSigned(2, "loosen", removeEtc)
	opts := bundle.Options{Current: v1, OwnTarget: "dev", AgentVersion: "0.1.0"}

	_, err = bundle.Verify(encode(t, v2), w.trust, opts)
	if err == nil || !strings.Contains(err.Error(), "needs_offline_signature") {
		t.Fatalf("online-only loosening: %v", err)
	}

	pf, reviews, err := Inspect(w.publishFile(v1raw, v2))
	if err != nil {
		t.Fatal(err)
	}
	if len(reviews) != 1 || reviews[0].Class != "loosen" || len(reviews[0].Changes) == 0 {
		t.Fatalf("review %+v", reviews)
	}
	sf := Sign(pf, reviews, w.offline)
	if sf.KeyID != w.trust.OfflineKeys[0].KeyID || len(sf.Signatures) != 1 {
		t.Fatalf("sig file %+v", sf)
	}
	// What `warden policy sign-upload` does: append the offline signature.
	v2["signatures"] = append(v2["signatures"].([]any), map[string]any{
		"key": "offline", "key_id": sf.KeyID, "alg": "ed25519", "sig": sf.Signatures[0].Sig})
	got, err := bundle.Verify(encode(t, v2), w.trust, opts)
	if err != nil {
		t.Fatal(err)
	}
	if got.Class != "loosen" {
		t.Fatalf("class %s", got.Class)
	}
}

// The signer computes the class itself: a loosening labelled "tighten" is shown as a loosening.
func TestInspectIgnoresWardensLabel(t *testing.T) {
	w := newWorld(t)
	v1 := w.onlineSigned(1, "initial", nil)
	_, reviews, err := Inspect(w.publishFile(v1, w.onlineSigned(2, "tighten", removeEtc)))
	if err != nil {
		t.Fatal(err)
	}
	if reviews[0].Class != "loosen" {
		t.Fatalf("class %s", reviews[0].Class)
	}
}

func TestInspectRefusesMalformedFiles(t *testing.T) {
	w := newWorld(t)
	v1 := w.onlineSigned(1, "initial", nil)
	v2 := w.onlineSigned(2, "loosen", removeEtc)
	good := w.publishFile(v1, v2)
	var m map[string]any
	_ = json.Unmarshal(good, &m)

	bad := []func(map[string]any){
		func(m map[string]any) { m["extra"] = true },
		func(m map[string]any) { m["v"] = 2 },
		func(m map[string]any) { m["items"] = []any{} },
		func(m map[string]any) { m["version"] = 3 },
		func(m map[string]any) { m["items"].([]any)[0].(map[string]any)["target"] = "prod" },
		func(m map[string]any) {
			m["items"].([]any)[0].(map[string]any)["bundle"].(map[string]any)["sneaky"] = 1
		},
	}
	for i, mut := range bad {
		var c map[string]any
		_ = json.Unmarshal(good, &c)
		mut(c)
		if _, _, err := Inspect(encode(t, c)); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, _, err := Inspect(good); err != nil {
		t.Fatal(err)
	}
}
