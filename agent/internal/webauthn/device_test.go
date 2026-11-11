package webauthn

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/janickssa/warden/agent/internal/policy"
)

// The iPhone's Face ID device key (M8) builds its own WebAuthn assertions; the agent must treat them exactly
// like a passkey's (policy-fixtures/ios_webauthn_vectors.json, made by backend/tests/test_ios_vectors.py).
func TestIPhoneDeviceKeyAssertionVerifies(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures", "ios_webauthn_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		RPID         string          `json:"rp_id"`
		Origin       string          `json:"origin"`
		CredentialID string          `json:"credential_id"`
		Approver     policy.Approver `json:"approver"`
		Assertion    struct {
			MessageSHA256 string `json:"message_sha256_hex"`
			ClientData    string `json:"client_data_json"`
			AuthData      string `json:"authenticator_data_hex"`
			Signature     string `json:"signature"`
		} `json:"assertion"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	auth, _ := hex.DecodeString(v.Assertion.AuthData)
	challenge, _ := hex.DecodeString(v.Assertion.MessageSHA256)
	b64 := base64.RawURLEncoding.EncodeToString
	a := Assertion{
		CredentialID:      v.CredentialID,
		AuthenticatorData: b64(auth),
		ClientDataJSON:    b64([]byte(v.Assertion.ClientData)),
		Signature:         v.Assertion.Signature,
	}
	trust := policy.Approvals{Approvers: []policy.Approver{v.Approver}, WebAuthn: policy.WebAuthn{RPID: v.RPID, Origins: []string{v.Origin}}}
	name, err := Verify(a, challenge, trust)
	if err != nil || name != "iPhone" {
		t.Fatalf("got %q, %v", name, err)
	}
	wrong := append([]byte{}, challenge...)
	wrong[0] ^= 1
	if _, err := Verify(a, wrong, trust); err == nil {
		t.Fatal("an assertion over another approval verified")
	}
}
