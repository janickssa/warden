// Package enroll performs one-time enrollment (README 7A): generate the agent's own ed25519 key, pin
// Warden's CA by the fingerprint inside the token, send the public key, print the fingerprint for the
// human to compare, and wait for the client certificate, trust anchors and the first policy bundle.
package enroll

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/janickssa/warden/agent/internal/bundle"
	"github.com/janickssa/warden/agent/internal/state"
)

const tokenPrefix = "wdn_enr_"

// Fingerprint matches warden.ca.fingerprint: "SHA256:" + first 16 bytes of SHA-256, colon-separated.
func Fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	parts := make([]string, 16)
	for i := 0; i < 16; i++ {
		parts[i] = fmt.Sprintf("%02x", sum[i])
	}
	return "SHA256:" + strings.Join(parts, ":")
}

func caPrefix(token string) (string, error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return "", errors.New("that isn't a Warden enrollment token")
	}
	i := strings.LastIndex(token, ".")
	if i < 0 || len(token)-i-1 != 32 {
		return "", errors.New("token has no CA fingerprint")
	}
	return token[i+1:], nil
}

// pinnedTLS accepts only a server whose chain contains a CA with the given fingerprint prefix, and whose
// leaf certificate verifies against that CA.
func pinnedTLS(prefix string) *tls.Config {
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return errors.New("no server certificate")
			}
			var ca *x509.Certificate
			for _, der := range raw[1:] {
				sum := sha256.Sum256(der)
				if strings.HasPrefix(hex.EncodeToString(sum[:]), prefix) {
					c, err := x509.ParseCertificate(der)
					if err != nil {
						return err
					}
					ca = c
				}
			}
			if ca == nil {
				return errors.New("server's CA doesn't match the token: wrong server?")
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return err
			}
			pool := x509.NewCertPool()
			pool.AddCert(ca)
			_, err = leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
			return err
		},
	}
}

type reply struct {
	Type        string          `json:"type"`
	Reason      string          `json:"reason"`
	Fingerprint string          `json:"fingerprint"`
	Name        string          `json:"name"`
	AgentID     string          `json:"agent_id"`
	CertPEM     string          `json:"cert_pem"`
	CAPEM       string          `json:"ca_pem"`
	Trust       bundle.Trust    `json:"trust"`
	Bundle      json.RawMessage `json:"bundle"`
}

// Run enrolls into dir. out receives the fingerprint and progress for the human.
func Run(ctx context.Context, server, token string, dir state.Dir, version string, out io.Writer) error {
	prefix, err := caPrefix(token)
	if err != nil {
		return err
	}
	if _, err := os.Stat(dir.File("cert.pem")); err == nil {
		return errors.New("this agent is already enrolled; remove the state directory to enroll again")
	}
	if err := os.MkdirAll(dir.Path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir.Path, 0o700); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	if err := bundle.WriteFileAtomic(dir.File("key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return err
	}
	fp := Fingerprint(pub)
	fmt.Fprintf(out, "This agent's fingerprint: %s\n", fp)

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: pinnedTLS(prefix)}}
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	c, _, err := websocket.Dial(dialCtx, strings.TrimRight(server, "/")+"/enroll", &websocket.DialOptions{HTTPClient: client})
	cancel()
	if err != nil {
		return fmt.Errorf("can't reach Warden: %w", err)
	}
	defer c.CloseNow()
	c.SetReadLimit(4 * 1024 * 1024)
	msg, _ := json.Marshal(map[string]string{"type": "enroll", "token": token,
		"public_key": base64.RawURLEncoding.EncodeToString(pub), "agent_version": version})
	if err := c.Write(ctx, websocket.MessageText, msg); err != nil {
		return err
	}
	waitCtx, cancelWait := context.WithTimeout(ctx, 16*time.Minute)
	defer cancelWait()
	for {
		_, data, err := c.Read(waitCtx)
		if err != nil {
			return fmt.Errorf("enrollment interrupted: %w", err)
		}
		var r reply
		if err := json.Unmarshal(data, &r); err != nil {
			return err
		}
		switch r.Type {
		case "enroll_pending":
			if r.Fingerprint != fp {
				return fmt.Errorf("Warden received fingerprint %s, not ours (%s): someone is in between", r.Fingerprint, fp)
			}
			fmt.Fprintf(out, "Waiting for confirmation of %s. Compare the fingerprint above with `warden agent pending`, then run:\n  warden agent confirm %s --fingerprint %s\n", r.Name, r.Name, fp)
		case "enroll_failed":
			return fmt.Errorf("enrollment refused: %s", r.Reason)
		case "enroll_ok":
			return finish(dir, server, prefix, r, version, out)
		default:
			return fmt.Errorf("unexpected reply %q", r.Type)
		}
	}
}

func finish(dir state.Dir, server, prefix string, r reply, version string, out io.Writer) error {
	caSum := sha256.Sum256(firstDER(r.CAPEM))
	if !strings.HasPrefix(hex.EncodeToString(caSum[:]), prefix) {
		return errors.New("Warden sent a CA that doesn't match the token")
	}
	cfg := &state.Config{Server: server, Name: r.Name, Trust: r.Trust}
	v, err := bundle.Verify(r.Bundle, cfg.Trust, bundle.Options{OwnTarget: r.Name, AgentVersion: version})
	if err != nil {
		return fmt.Errorf("first policy bundle refused: %w", err)
	}
	for name, data := range map[string][]byte{"cert.pem": []byte(r.CertPEM), "ca.pem": []byte(r.CAPEM), "bundle.json": v.Canonical} {
		if err := bundle.WriteFileAtomic(dir.File(name), data, 0o600); err != nil {
			return err
		}
	}
	if err := dir.SaveConfig(cfg); err != nil {
		return err
	}
	fmt.Fprintf(out, "Enrolled as %s (%s) · policy v%d. Start it with: systemctl enable --now warden-agent\n", r.Name, r.AgentID, v.Bundle.Version)
	return nil
}

func firstDER(p string) []byte {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil
	}
	return block.Bytes
}
