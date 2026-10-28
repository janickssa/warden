// Package approval verifies a plan sent by Warden before anything runs (invariants 2, 3 and 10):
// the template's canonical hash, the approved hash, the target, the approval signature and its window, and,
// with approvals.e2e on, a passkey assertion over the same approval from an approver in the bundle.
package approval

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/janickssa/warden/agent/internal/bundle"
	"github.com/janickssa/warden/agent/internal/canonical"
	"github.com/janickssa/warden/agent/internal/policy"
	"github.com/janickssa/warden/agent/internal/webauthn"
)

const (
	domain = "warden-approval-v1\n"
	signer = "warden-approval-key"
)

type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

type Signature struct {
	By    string `json:"by"`
	KeyID string `json:"key_id"`
	Sig   string `json:"sig"`
}

type Approval struct {
	By        string              `json:"by"`
	At        string              `json:"at"`
	ExpiresAt string              `json:"expires_at"`
	Hash      string              `json:"hash"`
	Signature Signature           `json:"signature"`
	Passkey   *webauthn.Assertion `json:"passkey"`
}

// Run is the `run` message body. A scheduled run carries Schedule instead of a plan approval.
type Run struct {
	Template json.RawMessage `json:"template"`
	PlanHash string          `json:"plan_hash"`
	Approval Approval        `json:"approval"`
	Schedule *ScheduleRun    `json:"schedule,omitempty"`
}

// Template is the hashed plan (backend Plan.template()).
type Template struct {
	V       int           `json:"v"`
	PlanID  string        `json:"plan_id"`
	Target  string        `json:"target"`
	Goal    string        `json:"goal"`
	Revises *string       `json:"revises"`
	Steps   []policy.Step `json:"steps"`
}

// Verify returns the template if every check passes.
func Verify(run Run, keys map[string]ed25519.PublicKey, trust policy.Approvals, ownTarget string, now time.Time) (*Template, error) {
	generic, err := canonical.Decode(run.Template)
	if err != nil {
		return nil, refuse("bad_template", "%v", err)
	}
	hash, err := canonical.Hash(generic)
	if err != nil {
		return nil, refuse("bad_template", "%v", err)
	}
	if hash != run.PlanHash || hash != run.Approval.Hash {
		return nil, refuse("hash_mismatch", "plan doesn't match the approved hash")
	}
	dec := json.NewDecoder(bytes.NewReader(run.Template))
	dec.DisallowUnknownFields()
	var t Template
	if err := dec.Decode(&t); err != nil {
		return nil, refuse("bad_template", "%v", err)
	}
	if t.V != 1 || len(t.Steps) == 0 {
		return nil, refuse("bad_template", "unsupported template")
	}
	if t.Target != ownTarget {
		return nil, refuse("wrong_target", "plan is for %q, this agent is %q", t.Target, ownTarget)
	}
	for i, s := range t.Steps {
		if s.N != i+1 {
			return nil, refuse("bad_template", "steps must be numbered 1, 2, 3, …")
		}
	}
	a := run.Approval
	if a.Signature.By != signer {
		return nil, refuse("bad_signature", "approval signed by %q, expected the approval key", a.Signature.By)
	}
	pub, ok := keys[a.Signature.KeyID]
	if !ok {
		return nil, refuse("unknown_key", "approval key %s isn't in this agent's bundle", a.Signature.KeyID)
	}
	payload := map[string]any{
		"v": json.Number("1"), "plan_hash": hash, "plan_id": t.PlanID, "target": t.Target,
		"approved_at": a.At, "expires_at": a.ExpiresAt, "by": a.By,
	}
	body, err := canonical.Marshal(payload)
	if err != nil {
		return nil, refuse("bad_signature", "%v", err)
	}
	message := append([]byte(domain), body...)
	raw, err := bundle.DecodeSig(a.Signature.Sig)
	if err != nil || !ed25519.Verify(pub, message, raw) {
		return nil, refuse("bad_signature", "approval signature is invalid")
	}
	if trust.E2E && a.Passkey == nil {
		return nil, refuse("passkey_required", "end-to-end signing is on: this approval has no passkey signature")
	}
	if a.Passkey != nil { // checked whenever present, so a bad one is never ignored
		challenge := sha256.Sum256(message)
		if _, err := webauthn.Verify(*a.Passkey, challenge[:], trust); err != nil {
			return nil, refuse("bad_passkey", "%v", err)
		}
	}
	expires, err := time.Parse(time.RFC3339Nano, a.ExpiresAt)
	if err != nil {
		return nil, refuse("bad_signature", "invalid expires_at")
	}
	if !now.Before(expires) {
		return nil, refuse("expired", "approval expired at %s", a.ExpiresAt)
	}
	return &t, nil
}
