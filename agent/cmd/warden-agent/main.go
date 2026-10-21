// warden-agent runs on each target (README 7A). It connects out to Warden over mTLS, re-checks every
// approved plan against its own signed policy and runs argv without a shell.
//
//	warden-agent enroll --server wss://<warden>:8443 --token <token> [--state DIR]
//	warden-agent run [--state DIR]
//	warden-agent version
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/janickssa/warden/agent/internal/conn"
	"github.com/janickssa/warden/agent/internal/enroll"
	"github.com/janickssa/warden/agent/internal/state"
)

// Version is set at build time with -ldflags "-X main.Version=…".
var Version = "0.1.0"

const defaultState = "/var/lib/warden-agent"

func usage() {
	fmt.Fprintf(os.Stderr, "usage: warden-agent enroll|run|version|fingerprint [flags]\n")
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	if cmd == "version" {
		fmt.Println(Version)
		return
	}
	if os.Geteuid() == 0 {
		log.Fatal("warden-agent refuses to run as root; run it as the unprivileged `warden` user")
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	stateDir := fs.String("state", defaultState, "state directory")
	server := fs.String("server", "", "Warden agent endpoint, e.g. wss://warden.lan:8443 (enroll)")
	token := fs.String("token", "", "one-time enrollment token from `warden agent add` (enroll)")
	_ = fs.Parse(args)
	dir := state.Dir{Path: *stateDir}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "enroll":
		if *server == "" || *token == "" {
			log.Fatal("enroll needs --server and --token")
		}
		if err := enroll.Run(ctx, *server, *token, dir, Version, os.Stdout); err != nil {
			log.Fatal(err)
		}
	case "fingerprint":
		fp, err := fingerprint(dir)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(fp)
	case "run":
		if err := dir.CheckPrivate(); err != nil {
			log.Fatal(err)
		}
		cfg, err := dir.LoadConfig()
		if err != nil {
			log.Fatalf("not enrolled? %v", err)
		}
		home, err := os.UserHomeDir()
		if err != nil {
			home = dir.Path
		}
		if err := os.MkdirAll(home, 0o700); err != nil {
			log.Fatalf("can't create HOME %s: %v", home, err)
		}
		a := &conn.Agent{Dir: dir, Cfg: cfg, Version: Version, Home: home}
		if err := a.LoadBundle(); err != nil {
			log.Fatal(err)
		}
		if err := a.Run(ctx); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
	}
}

func fingerprint(dir state.Dir) (string, error) {
	data, err := os.ReadFile(dir.File("key.pem"))
	if err != nil {
		return "", err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return "", errors.New("key.pem is not PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return "", errors.New("key.pem is not an ed25519 key")
	}
	return enroll.Fingerprint(priv.Public().(ed25519.PublicKey)), nil
}
