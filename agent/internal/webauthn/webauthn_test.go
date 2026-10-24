package webauthn

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/janickssa/warden/agent/internal/policy"
)

type vectors struct {
	Message  string          `json:"message"`
	WebAuthn policy.WebAuthn `json:"webauthn"`
	Cases    []struct {
		Alg       int             `json:"alg"`
		Approver  policy.Approver `json:"approver"`
		Assertion Assertion       `json:"assertion"`
	} `json:"cases"`
}

func load(t *testing.T) vectors {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures", "webauthn_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func flip(s string, i int) string {
	b, _ := decode(s)
	b[i] ^= 0x01
	return b64.EncodeToString(b)
}

func TestPythonAssertionsVerify(t *testing.T) {
	v := load(t)
	challenge := sha256.Sum256([]byte(v.Message))
	for _, c := range v.Cases {
		trust := policy.Approvals{E2E: true, Approvers: []policy.Approver{c.Approver}, WebAuthn: v.WebAuthn}
		name, err := Verify(c.Assertion, challenge[:], trust)
		if err != nil {
			t.Fatalf("alg %d: %v", c.Alg, err)
		}
		if name != c.Approver.Name {
			t.Fatalf("name %q", name)
		}
	}
}

func TestRefusals(t *testing.T) {
	v := load(t)
	challenge := sha256.Sum256([]byte(v.Message))
	other := sha256.Sum256([]byte(v.Message + "x"))
	for _, c := range v.Cases {
		base := policy.Approvals{E2E: true, Approvers: []policy.Approver{c.Approver}, WebAuthn: v.WebAuthn}
		cases := map[string]func() (Assertion, []byte, policy.Approvals){
			"other challenge": func() (Assertion, []byte, policy.Approvals) { return c.Assertion, other[:], base },
			"unknown passkey": func() (Assertion, []byte, policy.Approvals) {
				tr := base
				tr.Approvers = nil
				return c.Assertion, challenge[:], tr
			},
			"other rp": func() (Assertion, []byte, policy.Approvals) {
				tr := base
				tr.WebAuthn = policy.WebAuthn{RPID: "evil.example.com", Origins: base.WebAuthn.Origins}
				return c.Assertion, challenge[:], tr
			},
			"other origin": func() (Assertion, []byte, policy.Approvals) {
				tr := base
				tr.WebAuthn = policy.WebAuthn{RPID: base.WebAuthn.RPID, Origins: []string{"https://evil.example.com"}}
				return c.Assertion, challenge[:], tr
			},
			"no rp in bundle": func() (Assertion, []byte, policy.Approvals) {
				tr := base
				tr.WebAuthn = policy.WebAuthn{}
				return c.Assertion, challenge[:], tr
			},
			"no user verification": func() (Assertion, []byte, policy.Approvals) {
				a := c.Assertion
				ad, _ := decode(a.AuthenticatorData)
				ad[32] &^= flagUV
				a.AuthenticatorData = b64.EncodeToString(ad)
				return a, challenge[:], base
			},
			"tampered signature": func() (Assertion, []byte, policy.Approvals) {
				a := c.Assertion
				a.Signature = flip(a.Signature, 10)
				return a, challenge[:], base
			},
			"tampered client data": func() (Assertion, []byte, policy.Approvals) {
				a := c.Assertion
				cd, _ := decode(a.ClientDataJSON)
				a.ClientDataJSON = b64.EncodeToString([]byte(strings.Replace(string(cd), "webauthn.get", "webauthn.create", 1)))
				return a, challenge[:], base
			},
			"wrong algorithm label": func() (Assertion, []byte, policy.Approvals) {
				tr := base
				ap := c.Approver
				ap.Alg = algES256
				if c.Alg == algES256 {
					ap.Alg = algEdDSA
				}
				tr.Approvers = []policy.Approver{ap}
				return c.Assertion, challenge[:], tr
			},
		}
		for name, mk := range cases {
			a, ch, tr := mk()
			if _, err := Verify(a, ch, tr); err == nil {
				t.Errorf("alg %d: %s accepted", c.Alg, name)
			}
		}
	}
}
