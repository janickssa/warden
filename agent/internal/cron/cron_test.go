package cron

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

type vectors struct {
	TZ    string `json:"tz"`
	Valid []struct {
		Expr     string   `json:"expr"`
		Slots    []string `json:"slots"`
		NotSlots []string `json:"not_slots"`
	} `json:"valid"`
	Invalid []string `json:"invalid"`
}

func load(t *testing.T) vectors {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures", "cron_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestSharedVectors(t *testing.T) {
	v := load(t)
	if v.TZ != TZName {
		t.Fatalf("vectors are for %s", v.TZ)
	}
	for _, c := range v.Valid {
		cr, err := Parse(c.Expr)
		if err != nil {
			t.Fatalf("%q: %v", c.Expr, err)
		}
		for _, s := range c.Slots {
			ts, _ := time.Parse(time.RFC3339, s)
			if !cr.IsSlot(ts) {
				t.Errorf("%q: %s should be a slot", c.Expr, s)
			}
		}
		for _, s := range c.NotSlots {
			ts, _ := time.Parse(time.RFC3339, s)
			if cr.IsSlot(ts) {
				t.Errorf("%q: %s should not be a slot", c.Expr, s)
			}
		}
	}
	for _, e := range v.Invalid {
		if _, err := Parse(e); err == nil {
			t.Errorf("%q should be refused", e)
		}
	}
}

func TestDST(t *testing.T) {
	c, _ := Parse("30 2 * * *")
	first := time.Date(2026, 10, 25, 0, 30, 0, 0, time.UTC) // 02:30 CEST
	second := time.Date(2026, 10, 25, 1, 30, 0, 0, time.UTC) // 02:30 CET, the repeat
	if !c.IsSlot(first) || c.IsSlot(second) {
		t.Fatal("the repeated autumn hour must fire once")
	}
	// 29 March 2026 has no 02:30 at all; 00:30 UTC that day is 01:30 CET, 01:30 UTC is 03:30 CEST.
	for _, ts := range []time.Time{time.Date(2026, 3, 29, 0, 30, 0, 0, time.UTC), time.Date(2026, 3, 29, 1, 30, 0, 0, time.UTC)} {
		if c.IsSlot(ts) {
			t.Fatalf("%s is not 02:30 in Copenhagen", ts)
		}
	}
}

func TestRefusals(t *testing.T) {
	for _, e := range []string{"", "*  * * * *", "0 3 * * ５", "0\t3 * * *", "1,,2 * * * *", "-1 * * * *"} {
		if _, err := Parse(e); err == nil {
			t.Errorf("%q should be refused", e)
		}
	}
}
