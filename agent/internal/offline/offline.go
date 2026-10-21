// Package offline is the offline policy key used by warden-sign (README 7A, DECISIONS D-04/D-05).
//
// The key never lives on a server. On disk it's an ed25519 seed encrypted with XChaCha20-Poly1305 under a
// key derived from the passphrase with scrypt. The public half is stored in clear so `pubkey` needs no
// passphrase.
package offline

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const (
	DefaultN = 1 << 17 // 128 MB of memory per attempt
	r        = 8
	p        = 1
)

var b64 = base64.RawURLEncoding

// File is the on-disk format.
type File struct {
	V          int    `json:"v"`
	KDF        string `json:"kdf"`
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
	KeyID      string `json:"key_id"`
	Public     string `json:"public"`
}

// KeyID matches warden.keys.key_id_for.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "ed25519:" + hex.EncodeToString(sum[:])[:16]
}

func derive(pass []byte, salt []byte, n int) ([]byte, error) {
	return scrypt.Key(pass, salt, n, r, p, chacha20poly1305.KeySize)
}

// Generate creates a new key file at path (never overwrites).
func Generate(path string, pass []byte, n int) (*File, error) {
	if len(pass) < 12 {
		return nil, errors.New("use a passphrase of at least 12 characters")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	k, err := derive(pass, salt, n)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	id := KeyID(pub)
	f := &File{V: 1, KDF: "scrypt", N: n, R: r, P: p, Salt: b64.EncodeToString(salt), Nonce: b64.EncodeToString(nonce),
		Ciphertext: b64.EncodeToString(aead.Seal(nil, nonce, priv.Seed(), []byte(id))), KeyID: id, Public: b64.EncodeToString(pub)}
	data, _ := json.MarshalIndent(f, "", "  ")
	out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	defer out.Close()
	if _, err := out.Write(append(data, '\n')); err != nil {
		return nil, err
	}
	return f, out.Sync()
}

// Load reads a key file without decrypting it.
func Load(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.V != 1 || f.KDF != "scrypt" || f.R != r || f.P != p || f.N < 1<<14 {
		return nil, errors.New("unsupported key file")
	}
	return &f, nil
}

// Unlock decrypts the private key.
func (f *File) Unlock(pass []byte) (ed25519.PrivateKey, error) {
	salt, err1 := b64.DecodeString(f.Salt)
	nonce, err2 := b64.DecodeString(f.Nonce)
	ct, err3 := b64.DecodeString(f.Ciphertext)
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, fmt.Errorf("corrupt key file: %w", err)
	}
	k, err := derive(pass, salt, f.N)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(k)
	if err != nil {
		return nil, err
	}
	seed, err := aead.Open(nil, nonce, ct, []byte(f.KeyID))
	if err != nil {
		return nil, errors.New("wrong passphrase (or the key file was changed)")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	if KeyID(priv.Public().(ed25519.PublicKey)) != f.KeyID {
		return nil, errors.New("key file is inconsistent")
	}
	return priv, nil
}
