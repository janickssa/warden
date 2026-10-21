package bundle

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/janickssa/warden/agent/internal/policy"
)

type side struct {
	Rules        json.RawMessage `json:"rules"`
	ApprovalKeys []KeyRef        `json:"approval_keys"`
}

// TestSharedClassifyVectors: the agent must classify exactly like Warden (policy-fixtures/classify_vectors.json).
func TestSharedClassifyVectors(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures", "classify_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Name     string `json:"name"`
		Old      side   `json:"old"`
		New      side   `json:"new"`
		Expected string `json:"expected"`
	}
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) < 30 {
		t.Fatalf("only %d vectors", len(cases))
	}
	for _, c := range cases {
		oldR, err := policy.ParseRules(c.Old.Rules)
		if err != nil {
			t.Fatalf("%s old: %v", c.Name, err)
		}
		newR, err := policy.ParseRules(c.New.Rules)
		if err != nil {
			t.Fatalf("%s new: %v", c.Name, err)
		}
		got, changes := Classify(oldR, newR, c.Old.ApprovalKeys, c.New.ApprovalKeys)
		if got != c.Expected {
			t.Errorf("%s: got %s, want %s (%v)", c.Name, got, c.Expected, changes)
		}
	}
}
