// Package state is the agent's state directory (default /var/lib/warden-agent, mode 0700):
// key.pem, cert.pem, ca.pem, config.json (trust + identity), bundle.json and executed.log.
package state

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/janickssa/warden/agent/internal/bundle"
)

type Dir struct{ Path string }

func (d Dir) File(name string) string { return filepath.Join(d.Path, name) }

// Config is what enrollment establishes.
type Config struct {
	Server string       `json:"server"`
	Name   string       `json:"name"`
	Trust  bundle.Trust `json:"trust"`
}

// CheckPrivate refuses a state dir others can read or write.
func (d Dir) CheckPrivate() error {
	fi, err := os.Stat(d.Path)
	if err != nil {
		return err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s must not be accessible by group or others (chmod 700)", d.Path)
	}
	return nil
}

func (d Dir) LoadConfig() (*Config, error) {
	data, err := os.ReadFile(d.File("config.json"))
	if err != nil {
		return nil, err
	}
	var c Config
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config.json: %w", err)
	}
	return &c, nil
}

func (d Dir) SaveConfig(c *Config) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return bundle.WriteFileAtomic(d.File("config.json"), data, 0o600)
}

// ExecutedLog records every plan ID the agent has started, so one approval can never run twice.
type ExecutedLog struct {
	mu   sync.Mutex
	path string
}

func (d Dir) Executed() *ExecutedLog { return &ExecutedLog{path: d.File("executed.log")} }

func (l *ExecutedLog) has(planID string) (bool, error) {
	f, err := os.Open(l.path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if id, _, _ := strings.Cut(sc.Text(), " "); id == planID {
			return true, nil
		}
	}
	return false, sc.Err()
}

// Claim records planID durably. It fails if the plan was already claimed or the log can't be written.
func (l *ExecutedLog) Claim(planID, hash string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	seen, err := l.has(planID)
	if err != nil {
		return err
	}
	if seen {
		return fmt.Errorf("plan %s has already been run on this agent", planID)
	}
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s %s\n", planID, hash); err != nil {
		return err
	}
	return f.Sync()
}
