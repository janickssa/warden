// warden-sign holds the offline policy key on your own machine (README 7A). It never runs on a server.
//
//	warden-sign keygen --out ~/.warden/offline.key
//	warden-sign pubkey --key ~/.warden/offline.key
//	warden-sign sign bundle-v43.json --key ~/.warden/offline.key [--out bundle-v43.sig.json]
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/janickssa/warden/agent/internal/offline"
)

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: warden-sign keygen|pubkey|sign [flags]")
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	keyPath := fs.String("key", "", "offline key file")
	out := fs.String("out", "", "output file")
	passFile := fs.String("passphrase-file", "", "read the passphrase from this file instead of the terminal")
	yes := fs.Bool("yes", false, "sign without asking (only with --passphrase-file; for automation you trust)")
	scryptN := fs.Int("scrypt-n", offline.DefaultN, "scrypt cost (keygen)")
	var positional []string
	for len(args) > 0 {
		_ = fs.Parse(args)
		args = fs.Args()
		if len(args) > 0 {
			positional = append(positional, args[0])
			args = args[1:]
		}
	}

	switch cmd {
	case "keygen":
		if *out == "" {
			log.Fatal("keygen needs --out")
		}
		pass := passphrase(*passFile, true)
		f, err := offline.Generate(*out, pass, *scryptN)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Offline key created: %s\nkey_id: %s\npublic: %s\n\nRegister the public key on the warden guest:\n  warden keys offline register --public %s\nKeep a backup key on a second device: run keygen again with another --out and register it with --backup.\n",
			*out, f.KeyID, f.Public, f.Public)
	case "pubkey":
		f, err := offline.Load(*keyPath)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("key_id: %s\npublic: %s\n", f.KeyID, f.Public)
	case "sign":
		if len(positional) != 1 || *keyPath == "" {
			log.Fatal("usage: warden-sign sign <publish file> --key <offline key>")
		}
		data, err := os.ReadFile(positional[0])
		if err != nil {
			log.Fatal(err)
		}
		pf, reviews, err := offline.Inspect(data)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Policy v%d · %d target(s). Changes computed here from the rules in the file:\n\n", pf.Version, len(reviews))
		for _, r := range reviews {
			fmt.Printf("  %s · %s\n", r.Target, r.Class)
			for _, c := range r.Changes {
				fmt.Printf("    %s\n", c)
			}
		}
		fmt.Println()
		if !*yes || *passFile == "" {
			if !confirm(fmt.Sprintf("Sign policy v%d with the offline key? [y/N] ", pf.Version)) {
				log.Fatal("not signed")
			}
		}
		f, err := offline.Load(*keyPath)
		if err != nil {
			log.Fatal(err)
		}
		priv, err := f.Unlock(passphrase(*passFile, false))
		if err != nil {
			log.Fatal(err)
		}
		sig := offline.Sign(pf, reviews, priv)
		dest := *out
		if dest == "" {
			dest = strings.TrimSuffix(positional[0], ".json") + ".sig.json"
		}
		body, _ := json.MarshalIndent(sig, "", "  ")
		if err := os.WriteFile(dest, append(body, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("Signed. Upload %s with: warden policy sign-upload %s\n", dest, dest)
	default:
		log.Fatalf("unknown command %q", cmd)
	}
}

func passphrase(file string, twice bool) []byte {
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			log.Fatal(err)
		}
		return bytes.TrimRight(data, "\r\n")
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		log.Fatal("no terminal for the passphrase; use --passphrase-file")
	}
	read := func(prompt string) []byte {
		fmt.Fprint(os.Stderr, prompt)
		p, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			log.Fatal(err)
		}
		return p
	}
	p := read("Passphrase: ")
	if twice && !bytes.Equal(p, read("Repeat passphrase: ")) {
		log.Fatal(errors.New("passphrases don't match"))
	}
	return p
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.EqualFold(strings.TrimSpace(line), "y")
}
