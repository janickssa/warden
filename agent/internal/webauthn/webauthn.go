// Package webauthn verifies a passkey assertion over an approval, for end-to-end signing (README 10.0).
//
// The agent doesn't trust Warden's word that a human approved: with approvals.e2e on, the approval must carry
// a WebAuthn assertion whose challenge is SHA-256 of the approval message, made by a passkey listed in the
// signed bundle, for the bundle's relying party and one of its origins, with user presence and user
// verification. Only ES256 and Ed25519 keys are accepted.
package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/janickssa/warden/agent/internal/policy"
)

const (
	flagUP   = 0x01
	flagUV   = 0x04
	algES256 = -7
	algEdDSA = -8
)

// Assertion is the stored passkey signature (backend PasskeyAssertion), base64url without padding.
type Assertion struct {
	CredentialID      string `json:"credential_id"`
	AuthenticatorData string `json:"authenticator_data"`
	ClientDataJSON    string `json:"client_data_json"`
	Signature         string `json:"signature"`
}

var b64 = base64.RawURLEncoding

func decode(s string) ([]byte, error) {
	if b, err := b64.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

// Verify checks a over challenge for the given approval trust. It returns the approver's name.
func Verify(a Assertion, challenge []byte, trust policy.Approvals) (string, error) {
	var approver *policy.Approver
	for i := range trust.Approvers {
		if subtle.ConstantTimeCompare([]byte(trust.Approvers[i].CredentialID), []byte(a.CredentialID)) == 1 {
			approver = &trust.Approvers[i]
			break
		}
	}
	if approver == nil {
		return "", errors.New("passkey isn't an approver in this agent's bundle")
	}
	if trust.WebAuthn.RPID == "" || len(trust.WebAuthn.Origins) == 0 {
		return "", errors.New("bundle has no WebAuthn relying party")
	}
	cdj, err := decode(a.ClientDataJSON)
	if err != nil {
		return "", fmt.Errorf("client data: %w", err)
	}
	var cd clientData
	if err := json.Unmarshal(cdj, &cd); err != nil {
		return "", fmt.Errorf("client data: %w", err)
	}
	if cd.Type != "webauthn.get" {
		return "", fmt.Errorf("client data type %q", cd.Type)
	}
	want := b64.EncodeToString(challenge)
	if subtle.ConstantTimeCompare([]byte(cd.Challenge), []byte(want)) != 1 {
		return "", errors.New("passkey signed a different challenge than this approval")
	}
	if cd.CrossOrigin {
		return "", errors.New("cross-origin assertion")
	}
	originOK := false
	for _, o := range trust.WebAuthn.Origins {
		if cd.Origin == o {
			originOK = true
		}
	}
	if !originOK {
		return "", fmt.Errorf("origin %q isn't allowed", cd.Origin)
	}
	ad, err := decode(a.AuthenticatorData)
	if err != nil || len(ad) < 37 {
		return "", errors.New("malformed authenticator data")
	}
	rp := sha256.Sum256([]byte(trust.WebAuthn.RPID))
	if !bytes.Equal(ad[:32], rp[:]) {
		return "", errors.New("assertion is for another relying party")
	}
	if ad[32]&flagUP == 0 || ad[32]&flagUV == 0 {
		return "", errors.New("assertion lacks user presence or user verification")
	}
	sig, err := decode(a.Signature)
	if err != nil {
		return "", errors.New("malformed signature")
	}
	der, err := decode(approver.Public)
	if err != nil {
		return "", errors.New("approver key isn't base64url")
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", fmt.Errorf("approver key: %w", err)
	}
	cdHash := sha256.Sum256(cdj)
	signed := append(append([]byte{}, ad...), cdHash[:]...)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if approver.Alg != algES256 || k.Curve != elliptic.P256() {
			return "", errors.New("approver key doesn't match its algorithm")
		}
		digest := sha256.Sum256(signed)
		if !ecdsa.VerifyASN1(k, digest[:], sig) {
			return "", errors.New("passkey signature is invalid")
		}
	case ed25519.PublicKey:
		if approver.Alg != algEdDSA {
			return "", errors.New("approver key doesn't match its algorithm")
		}
		if !ed25519.Verify(k, signed, sig) {
			return "", errors.New("passkey signature is invalid")
		}
	default:
		return "", errors.New("unsupported approver key type")
	}
	return approver.Name, nil
}
