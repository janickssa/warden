package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/janickssa/warden/agent/internal/policy"
)

type scheduleVectors struct {
	ApprovalKey struct {
		KeyID  string `json:"key_id"`
		Public string `json:"public"`
	} `json:"approval_key"`
	Trust policy.Approvals `json:"trust"`
	Now   string           `json:"now"`
	Claim string           `json:"claim"`
	Run   json.RawMessage  `json:"run"`
}

func loadSchedule(t *testing.T) (Run, map[string]ed25519.PublicKey, policy.Approvals, time.Time, string) {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures", "schedule_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v scheduleVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.RawURLEncoding.DecodeString(v.ApprovalKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	var run Run
	if err := json.Unmarshal(v.Run, &run); err != nil {
		t.Fatal(err)
	}
	now, _ := time.Parse(time.RFC3339Nano, v.Now)
	return run, map[string]ed25519.PublicKey{v.ApprovalKey.KeyID: pub}, v.Trust, now, v.Claim
}

func TestScheduleGrantFromPythonVerifies(t *testing.T) {
	run, keys, trust, now, claim := loadSchedule(t)
	tpl, got, err := VerifySchedule(run, keys, trust, "dev", now)
	if err != nil {
		t.Fatal(err)
	}
	if got != claim || tpl.PlanID != run.Schedule.RunID || len(tpl.Steps) != 2 || tpl.Steps[1].Command != "npm test" {
		t.Fatalf("unexpected %+v %s", tpl, got)
	}
}

func TestScheduleRefusals(t *testing.T) {
	cases := map[string]struct {
		code   string
		mutate func(r *Run, now *time.Time, trust *policy.Approvals)
	}{
		"tampered step": {"hash_mismatch", func(r *Run, _ *time.Time, _ *policy.Approvals) {
			r.Template = json.RawMessage(strings.Replace(string(r.Template), "npm test", "npm publish", 1))
		}},
		"hash rewritten to match": {"hash_mismatch", func(r *Run, _ *time.Time, _ *policy.Approvals) {
			r.Template = json.RawMessage(strings.Replace(string(r.Template), "npm test", "npm publish", 1))
			r.PlanHash = "sha256:" + strings.Repeat("0", 64)
			r.Schedule.Grant.TemplateHash = r.PlanHash
		}},
		"other target": {"wrong_target", func(r *Run, _ *time.Time, _ *policy.Approvals) {}},
		"cron widened": {"bad_signature", func(r *Run, _ *time.Time, _ *policy.Approvals) { r.Schedule.Grant.Cron = "* * * * *" }},
		"window extended": {"bad_signature", func(r *Run, _ *time.Time, _ *policy.Approvals) {
			r.Schedule.Grant.ExpiresAt = "2027-12-31T00:00:00+00:00"
		}},
		"no passkey":              {"passkey_required", func(r *Run, _ *time.Time, _ *policy.Approvals) { r.Schedule.Grant.Passkey = nil }},
		"passkey not an approver": {"bad_passkey", func(_ *Run, _ *time.Time, tr *policy.Approvals) { tr.Approvers = nil }},
		"slot off the cron": {"bad_slot", func(r *Run, now *time.Time, _ *policy.Approvals) {
			s, _ := time.Parse(time.RFC3339, r.Schedule.Slot)
			r.Schedule.Slot = s.Add(time.Minute).Format(time.RFC3339)
			*now = now.Add(time.Minute)
		}},
		"too late":  {"bad_slot", func(_ *Run, now *time.Time, _ *policy.Approvals) { *now = now.Add(20 * time.Minute) }},
		"too early": {"bad_slot", func(r *Run, now *time.Time, _ *policy.Approvals) { *now = now.Add(-5 * time.Minute) }},
		"next day's slot early": {"bad_slot", func(r *Run, _ *time.Time, _ *policy.Approvals) {
			s, _ := time.Parse(time.RFC3339, r.Schedule.Slot)
			r.Schedule.Slot = s.Add(24 * time.Hour).Format(time.RFC3339)
		}},
		"after expiry": {"expired", func(r *Run, now *time.Time, _ *policy.Approvals) {
			s, _ := time.Parse(time.RFC3339, r.Schedule.Slot)
			later := s.Add(91 * 24 * time.Hour)
			r.Schedule.Slot = later.Format(time.RFC3339)
			*now = later
		}},
		"forged run id":        {"bad_schedule", func(r *Run, _ *time.Time, _ *policy.Approvals) { r.Schedule.RunID = "pln_../../x" }},
		"unknown key":          {"unknown_key", func(r *Run, _ *time.Time, _ *policy.Approvals) { r.Schedule.Grant.Signature.KeyID = "ed25519:other" }},
		"extra template field": {"bad_template", func(r *Run, _ *time.Time, _ *policy.Approvals) {}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			run, keys, trust, now, _ := loadSchedule(t)
			c.mutate(&run, &now, &trust)
			target := "dev"
			if name == "other target" {
				target = "dev2"
			}
			if name == "extra template field" {
				var m map[string]any
				_ = json.Unmarshal(run.Template, &m)
				m["shell"] = true
				run.Template = reencode(t, m)
			}
			_, _, err := VerifySchedule(run, keys, trust, target, now)
			if code(err) != c.code && !(c.code == "bad_template" && code(err) == "hash_mismatch") {
				t.Fatalf("want %s, got %v", c.code, err)
			}
		})
	}
}

// A plan approval can't be replayed as a schedule grant or the other way round: different domains.
func TestPlanApprovalIsNotAScheduleGrant(t *testing.T) {
	run, keys, trust, now, _ := loadSchedule(t)
	plain := Run{Template: run.Template, PlanHash: run.PlanHash}
	if _, err := Verify(plain, keys, trust, "dev", now); err == nil {
		t.Fatal("a schedule template ran as a plan")
	}
}
