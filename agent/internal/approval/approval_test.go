package approval

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
	"time"

	"github.com/janickssa/warden/agent/internal/bundle"
	"github.com/janickssa/warden/agent/internal/canonical"
)

type vectors struct {
	OnlinePublic string          `json:"online_public"`
	OnlineKeyID  string          `json:"online_key_id"`
	BundleV1     json.RawMessage `json:"bundle_v1"`
	Run          json.RawMessage `json:"run"`
}

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func setup(t *testing.T) (Run, map[string]ed25519.PublicKey, map[string]any) {
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
	ver, err := bundle.Verify(v.BundleV1, bundle.Trust{OnlineKeyID: v.OnlineKeyID, OnlinePublic: v.OnlinePublic},
		bundle.Options{OwnTarget: "dev", AgentVersion: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	var run Run
	if err := json.Unmarshal(v.Run, &run); err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(v.Run, &generic); err != nil {
		t.Fatal(err)
	}
	return run, ver.ApprovalKeys, generic
}

func code(err error) string {
	if e, ok := err.(*Error); ok {
		return e.Code
	}
	return ""
}

func reencode(t *testing.T, v any) json.RawMessage {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(buf.Bytes())
}

func TestPythonApprovedPlanVerifies(t *testing.T) {
	run, keys, _ := setup(t)
	tpl, err := Verify(run, keys, "dev", t0.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if tpl.PlanID != "pln_01JB7Q3K0000000000000000AA" || len(tpl.Steps) != 2 || tpl.Steps[1].Command != "npm test" {
		t.Fatalf("unexpected template %+v", tpl)
	}
}

func TestTamperedStepRefused(t *testing.T) {
	run, keys, generic := setup(t)
	tpl := generic["template"].(map[string]any)
	tpl["steps"].([]any)[1].(map[string]any)["command"] = "npm publish"
	run.Template = reencode(t, tpl)
	if _, err := Verify(run, keys, "dev", t0); code(err) != "hash_mismatch" {
		t.Fatalf("got %v", err)
	}
}

func TestTamperedHashAndSignatureRefused(t *testing.T) {
	run, keys, generic := setup(t)
	// A tampering dispatcher edits a step AND rewrites both hashes to match. Only the signature stops it.
	tpl := generic["template"].(map[string]any)
	tpl["steps"].([]any)[1].(map[string]any)["command"] = "npm publish"
	run.Template = reencode(t, tpl)
	decoded, err := canonical.Decode(run.Template)
	if err != nil {
		t.Fatal(err)
	}
	h, err := canonical.Hash(decoded)
	if err != nil {
		t.Fatal(err)
	}
	run.PlanHash, run.Approval.Hash = h, h
	if _, err := Verify(run, keys, "dev", t0); code(err) != "bad_signature" {
		t.Fatalf("got %v", err)
	}
}

func TestRetargetedPlanRefused(t *testing.T) {
	run, keys, _ := setup(t)
	if _, err := Verify(run, keys, "dev2", t0); code(err) != "wrong_target" {
		t.Fatalf("got %v", err)
	}
}

func TestExpiredRefused(t *testing.T) {
	run, keys, _ := setup(t)
	if _, err := Verify(run, keys, "dev", t0.Add(30*time.Minute)); code(err) != "expired" {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownKeyRefused(t *testing.T) {
	run, _, _ := setup(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := Verify(run, map[string]ed25519.PublicKey{"ed25519:other": pub}, "dev", t0); code(err) != "unknown_key" {
		t.Fatalf("got %v", err)
	}
}

func TestForgedSignatureRefused(t *testing.T) {
	run, keys, _ := setup(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	run.Approval.Signature.Sig = "ed25519:" + encodeSig(ed25519.Sign(priv, []byte("anything")))
	if _, err := Verify(run, keys, "dev", t0); code(err) != "bad_signature" {
		t.Fatalf("got %v", err)
	}
	run2, keys2, _ := setup(t)
	run2.Approval.ExpiresAt = "2027-01-01T00:00:00+00:00" // extend the window: signature no longer matches
	if _, err := Verify(run2, keys2, "dev", t0); code(err) != "bad_signature" {
		t.Fatalf("got %v", err)
	}
	run3, keys3, _ := setup(t)
	run3.Approval.Signature.By = "passkey:mallory"
	if _, err := Verify(run3, keys3, "dev", t0); code(err) != "bad_signature" {
		t.Fatalf("got %v", err)
	}
}

func TestUnknownTemplateFieldRefused(t *testing.T) {
	run, keys, generic := setup(t)
	tpl := generic["template"].(map[string]any)
	tpl["shell"] = true
	run.Template = reencode(t, tpl)
	if _, err := Verify(run, keys, "dev", t0); err == nil {
		t.Fatal("accepted")
	}
}

func encodeSig(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
