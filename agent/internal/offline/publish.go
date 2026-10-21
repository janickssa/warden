package offline

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/janickssa/warden/agent/internal/bundle"
	"github.com/janickssa/warden/agent/internal/canonical"
	"github.com/janickssa/warden/agent/internal/policy"
)

const bundleDomain = "warden-bundle-v1\n"

// PublishFile is what `warden policy pending --out` writes: every target's new bundle (already signed
// with the online key) and the rules it replaces, so the signer can compute the diff itself.
type PublishFile struct {
	V       int    `json:"v"`
	Version int    `json:"version"`
	Items   []Item `json:"items"`
}

type Item struct {
	Target   string          `json:"target"`
	Previous *Content        `json:"previous"`
	Bundle   json.RawMessage `json:"bundle"`
}

type Content struct {
	Rules        json.RawMessage `json:"rules"`
	ApprovalKeys []bundle.KeyRef `json:"approval_keys"`
}

// SigFile is what warden-sign writes and `warden policy sign-upload` reads.
type SigFile struct {
	V          int         `json:"v"`
	Version    int         `json:"version"`
	KeyID      string      `json:"key_id"`
	Signatures []TargetSig `json:"signatures"`
}

type TargetSig struct {
	Target string `json:"target"`
	Sig    string `json:"sig"`
}

// Review describes one target's change as computed here, not as Warden describes it.
type Review struct {
	Target  string
	Class   string
	Changes []string
	message []byte
}

func strict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// Inspect parses a publish file and computes each target's classification and changes locally.
func Inspect(data []byte) (*PublishFile, []Review, error) {
	var pf PublishFile
	if err := strict(data, &pf); err != nil {
		return nil, nil, fmt.Errorf("publish file: %w", err)
	}
	if pf.V != 1 || len(pf.Items) == 0 {
		return nil, nil, errors.New("unsupported or empty publish file")
	}
	var reviews []Review
	for _, it := range pf.Items {
		generic, err := canonical.Decode(it.Bundle)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", it.Target, err)
		}
		obj, ok := generic.(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("%s: bundle is not an object", it.Target)
		}
		var b bundle.Bundle
		if err := strict(it.Bundle, &b); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", it.Target, err)
		}
		if b.Target != it.Target || b.Version != pf.Version {
			return nil, nil, fmt.Errorf("%s: bundle target/version doesn't match the file", it.Target)
		}
		newRules, err := policy.ParseRules(b.Rules)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", it.Target, err)
		}
		r := Review{Target: it.Target, Class: "initial"}
		if it.Previous != nil {
			oldRules, err := policy.ParseRules(it.Previous.Rules)
			if err != nil {
				return nil, nil, fmt.Errorf("%s previous: %w", it.Target, err)
			}
			r.Class, r.Changes = bundle.Classify(oldRules, newRules, it.Previous.ApprovalKeys, b.ApprovalKeys)
		}
		unsigned := map[string]any{}
		for k, val := range obj {
			if k != "signatures" {
				unsigned[k] = val
			}
		}
		body, err := canonical.Marshal(unsigned)
		if err != nil {
			return nil, nil, err
		}
		r.message = append([]byte(bundleDomain), body...)
		reviews = append(reviews, r)
	}
	return &pf, reviews, nil
}

// Sign signs every bundle in the file.
func Sign(pf *PublishFile, reviews []Review, priv ed25519.PrivateKey) SigFile {
	out := SigFile{V: 1, Version: pf.Version, KeyID: KeyID(priv.Public().(ed25519.PublicKey))}
	for _, r := range reviews {
		out.Signatures = append(out.Signatures, TargetSig{Target: r.Target,
			Sig: "ed25519:" + b64.EncodeToString(ed25519.Sign(priv, r.message))})
	}
	return out
}
