// Package bundle verifies and stores signed policy bundles (README 7A, invariant 11, section 16 rule 12).
//
// A bundle is accepted only if: it decodes strictly (no unknown fields, no duplicate keys), its schema is
// known, it names this agent's target, its version is higher than the installed one, the agent is new
// enough, and it carries valid signatures for its change class (loosening needs the offline key).
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/janickssa/warden/agent/internal/canonical"
	"github.com/janickssa/warden/agent/internal/policy"
)

const (
	Schema = 1
	domain = "warden-bundle-v1\n"
)

// Error is a refusal with a stable code.
type Error struct{ Code, Msg string }

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func refuse(code, format string, args ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, args...)}
}

type KeyRef struct {
	KeyID  string `json:"key_id"`
	Public string `json:"public"`
}

type Signature struct {
	Key   string `json:"key"`
	KeyID string `json:"key_id"`
	Alg   string `json:"alg"`
	Sig   string `json:"sig"`
}

type Bundle struct {
	Schema          int             `json:"schema"`
	Version         int             `json:"version"`
	IssuedAt        string          `json:"issued_at"`
	Target          string          `json:"target"`
	MinAgentVersion string          `json:"min_agent_version"`
	Change          string          `json:"change"`
	Rules           json.RawMessage `json:"rules"`
	ApprovalKeys    []KeyRef        `json:"approval_keys"`
	Signatures      []Signature     `json:"signatures"`
}

// Trust is what the agent pinned at enrollment, through the CA-pinned channel the human confirmed.
type Trust struct {
	OnlineKeyID  string `json:"online_key_id"`
	OnlinePublic string `json:"online_public"`
	// Offline keys (primary and backup). Either can sign a loosening. Without one, nothing can loosen.
	OfflineKeys []KeyRef `json:"offline_keys"`
}

// Verified is an accepted bundle.
type Verified struct {
	Class        string // what the agent itself computed: initial, none, tighten or loosen
	Changes      []string
	Bundle       *Bundle
	Rules        *policy.Rules
	SHA256       string
	Canonical    []byte
	ApprovalKeys map[string]ed25519.PublicKey
}

func decodeKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid ed25519 public key")
	}
	return ed25519.PublicKey(raw), nil
}

// DecodeSig decodes "ed25519:<base64url>".
func DecodeSig(s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, "ed25519:")
	if !ok {
		return nil, fmt.Errorf("unsupported signature algorithm")
	}
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, fmt.Errorf("malformed signature")
	}
	return raw, nil
}

func versionTuple(v string) ([3]int, bool) {
	var out [3]int
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

// AtLeast reports whether version a >= b (both x.y.z).
func AtLeast(a, b string) bool {
	x, ok1 := versionTuple(a)
	y, ok2 := versionTuple(b)
	if !ok1 || !ok2 {
		return false
	}
	for i := 0; i < 3; i++ {
		if x[i] != y[i] {
			return x[i] > y[i]
		}
	}
	return true
}

func verifySig(sigs []Signature, key, keyID string, pub ed25519.PublicKey, msg []byte) bool {
	for _, s := range sigs {
		if s.Key != key || s.KeyID != keyID || s.Alg != "ed25519" {
			continue
		}
		raw, err := DecodeSig(s.Sig)
		if err != nil {
			return false
		}
		return ed25519.Verify(pub, msg, raw)
	}
	return false
}

// Options control sequencing checks.
//
// Current is the bundle the agent enforces now (nil only at enrollment): the new bundle is classified
// against it. Installed=true re-verifies the bundle already on disk at start-up.
type Options struct {
	Current      *Verified
	OwnTarget    string
	AgentVersion string
	Installed    bool
}

func (o Options) installedVersion() int {
	if o.Current == nil {
		return 0
	}
	return o.Current.Bundle.Version
}

func verifyOffline(sigs []Signature, keys []KeyRef, msg []byte) bool {
	for _, k := range keys {
		pub, err := decodeKey(k.Public)
		if err != nil {
			continue
		}
		if verifySig(sigs, "offline", k.KeyID, pub, msg) {
			return true
		}
	}
	return false
}

// Verify checks a bundle received from Warden (or re-checks the stored one).
func Verify(raw []byte, trust Trust, opt Options) (*Verified, error) {
	generic, err := canonical.Decode(raw)
	if err != nil {
		return nil, refuse("bad_bundle", "%v", err)
	}
	obj, ok := generic.(map[string]any)
	if !ok {
		return nil, refuse("bad_bundle", "bundle is not an object")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, refuse("unknown_field", "%v", err)
	}
	if b.Schema != Schema {
		return nil, refuse("bad_bundle", "unsupported schema %d", b.Schema)
	}
	if len(b.Signatures) == 0 {
		return nil, refuse("unsigned", "bundle has no signatures")
	}
	if b.Target != opt.OwnTarget {
		return nil, refuse("wrong_target", "bundle is for %q, this agent is %q", b.Target, opt.OwnTarget)
	}
	if !AtLeast(opt.AgentVersion, b.MinAgentVersion) {
		return nil, refuse("agent_too_old", "bundle needs agent %s, this is %s", b.MinAgentVersion, opt.AgentVersion)
	}
	if !opt.Installed {
		if b.Version <= opt.installedVersion() {
			return nil, refuse("old_version", "bundle v%d is not newer than installed v%d", b.Version, opt.installedVersion())
		}
		// At enrollment the agent takes whatever version is current (it arrives through the CA-pinned channel
		// the human confirmed); "initial" is never accepted as an update.
		if b.Change == "initial" && opt.Current != nil {
			return nil, refuse("bad_change", "an initial bundle is accepted at enrollment only")
		}
	}
	switch b.Change {
	case "initial", "tighten", "loosen":
	default:
		return nil, refuse("bad_change", "unknown change class %q", b.Change)
	}

	unsigned := make(map[string]any, len(obj))
	for k, val := range obj {
		if k != "signatures" {
			unsigned[k] = val
		}
	}
	body, err := canonical.Marshal(unsigned)
	if err != nil {
		return nil, refuse("bad_bundle", "%v", err)
	}
	msg := append([]byte(domain), body...)
	onlinePub, err := decodeKey(trust.OnlinePublic)
	if err != nil {
		return nil, refuse("bad_trust", "online key: %v", err)
	}
	if !verifySig(b.Signatures, "online", trust.OnlineKeyID, onlinePub, msg) {
		return nil, refuse("bad_signature", "no valid online-key signature")
	}

	rules, err := policy.ParseRules(b.Rules)
	if err != nil {
		return nil, refuse("bad_rules", "%v", err)
	}
	if rules.Target != b.Target {
		return nil, refuse("wrong_target", "rules are for %q", rules.Target)
	}

	// The agent decides for itself whether this loosens anything; the bundle's label can't lower the bar.
	class, changes := "initial", []string(nil)
	if opt.Current != nil {
		class, changes = Classify(opt.Current.Rules, rules, opt.Current.Bundle.ApprovalKeys, b.ApprovalKeys)
	}
	if class == "loosen" || b.Change == "loosen" {
		if !verifyOffline(b.Signatures, trust.OfflineKeys, msg) {
			return nil, refuse("needs_offline_signature", "this bundle loosens policy and has no valid offline-key signature (%d change(s))", len(changes))
		}
	}
	keys := map[string]ed25519.PublicKey{}
	for _, k := range b.ApprovalKeys {
		pub, err := decodeKey(k.Public)
		if err != nil {
			return nil, refuse("bad_bundle", "approval key %s: %v", k.KeyID, err)
		}
		keys[k.KeyID] = pub
	}
	full, err := canonical.Marshal(obj)
	if err != nil {
		return nil, refuse("bad_bundle", "%v", err)
	}
	return &Verified{Class: class, Changes: changes, Bundle: &b, Rules: rules, SHA256: canonical.SHA256Tagged(full), Canonical: full, ApprovalKeys: keys}, nil
}

// WriteFileAtomic writes, fsyncs, renames and fsyncs the directory.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
