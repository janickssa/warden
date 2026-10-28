package approval

// Scheduled runs (README 11, DECISIONS M7-02). The human approved a schedule once: a grant over the
// template hash, the target, the cron and a window of at most 180 days, signed by Warden's approval key
// and by the human's passkey (always). Warden can only ask for a run; this file decides whether one may
// happen: the right steps, the right target, a slot the cron allows, now, inside the window, and never the
// same slot twice (the caller claims ClaimKey in executed.log).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"regexp"
	"time"

	"github.com/janickssa/warden/agent/internal/bundle"
	"github.com/janickssa/warden/agent/internal/canonical"
	"github.com/janickssa/warden/agent/internal/cron"
	"github.com/janickssa/warden/agent/internal/policy"
	"github.com/janickssa/warden/agent/internal/webauthn"
)

const (
	scheduleDomain = "warden-schedule-v1\n"
	MaxGrant       = 180 * 24 * time.Hour
	Late           = 15 * time.Minute
	Early          = time.Minute
)

var (
	scheduleID = regexp.MustCompile(`^sch_[0-9A-HJKMNP-TV-Z]{26}$`)
	runID      = regexp.MustCompile(`^pln_[0-9A-HJKMNP-TV-Z]{26}$`)
)

type Grant struct {
	ScheduleID   string              `json:"schedule_id"`
	TemplateHash string              `json:"template_hash"`
	Target       string              `json:"target"`
	Cron         string              `json:"cron"`
	TZ           string              `json:"tz"`
	ApprovedAt   string              `json:"approved_at"`
	ExpiresAt    string              `json:"expires_at"`
	By           string              `json:"by"`
	Signature    Signature           `json:"signature"`
	Passkey      *webauthn.Assertion `json:"passkey"`
}

// ScheduleRun is unsigned except for the grant: RunID only names the run in events, and Slot is checked.
type ScheduleRun struct {
	RunID string `json:"run_id"`
	Slot  string `json:"slot"`
	Grant Grant  `json:"grant"`
}

type ScheduleTemplate struct {
	V          int           `json:"v"`
	ScheduleID string        `json:"schedule_id"`
	Target     string        `json:"target"`
	Goal       string        `json:"goal"`
	Steps      []policy.Step `json:"steps"`
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// VerifySchedule returns the steps to run as a Template whose PlanID is the run ID, and the claim key.
func VerifySchedule(run Run, keys map[string]ed25519.PublicKey, trust policy.Approvals, ownTarget string, now time.Time) (*Template, string, error) {
	sr := run.Schedule
	if sr == nil {
		return nil, "", refuse("bad_schedule", "not a scheduled run")
	}
	g := sr.Grant
	if !runID.MatchString(sr.RunID) || !scheduleID.MatchString(g.ScheduleID) {
		return nil, "", refuse("bad_schedule", "malformed run or schedule ID")
	}
	generic, err := canonical.Decode(run.Template)
	if err != nil {
		return nil, "", refuse("bad_template", "%v", err)
	}
	hash, err := canonical.Hash(generic)
	if err != nil {
		return nil, "", refuse("bad_template", "%v", err)
	}
	if hash != run.PlanHash || hash != g.TemplateHash {
		return nil, "", refuse("hash_mismatch", "steps don't match the approved schedule")
	}
	dec := json.NewDecoder(bytes.NewReader(run.Template))
	dec.DisallowUnknownFields()
	var t ScheduleTemplate
	if err := dec.Decode(&t); err != nil {
		return nil, "", refuse("bad_template", "%v", err)
	}
	if t.V != 1 || len(t.Steps) == 0 || t.ScheduleID != g.ScheduleID {
		return nil, "", refuse("bad_template", "unsupported template")
	}
	for i, s := range t.Steps {
		if s.N != i+1 {
			return nil, "", refuse("bad_template", "steps must be numbered 1, 2, 3, …")
		}
	}
	if t.Target != ownTarget || g.Target != ownTarget {
		return nil, "", refuse("wrong_target", "schedule is for %q, this agent is %q", g.Target, ownTarget)
	}
	if g.TZ != cron.TZName {
		return nil, "", refuse("bad_schedule", "unsupported time zone %q", g.TZ)
	}

	// The grant: approval key signature, then the human's passkey over the same message.
	if g.Signature.By != signer {
		return nil, "", refuse("bad_signature", "grant signed by %q, expected the approval key", g.Signature.By)
	}
	pub, ok := keys[g.Signature.KeyID]
	if !ok {
		return nil, "", refuse("unknown_key", "approval key %s isn't in this agent's bundle", g.Signature.KeyID)
	}
	payload := map[string]any{
		"v": json.Number("1"), "kind": "schedule", "schedule_id": g.ScheduleID, "template_hash": g.TemplateHash,
		"target": g.Target, "cron": g.Cron, "tz": g.TZ, "approved_at": g.ApprovedAt, "expires_at": g.ExpiresAt,
		"by": g.By,
	}
	body, err := canonical.Marshal(payload)
	if err != nil {
		return nil, "", refuse("bad_signature", "%v", err)
	}
	message := append([]byte(scheduleDomain), body...)
	raw, err := bundle.DecodeSig(g.Signature.Sig)
	if err != nil || !ed25519.Verify(pub, message, raw) {
		return nil, "", refuse("bad_signature", "schedule grant signature is invalid")
	}
	if g.Passkey == nil {
		return nil, "", refuse("passkey_required", "a schedule needs the approver's passkey signature")
	}
	challenge := sha256.Sum256(message)
	if _, err := webauthn.Verify(*g.Passkey, challenge[:], trust); err != nil {
		return nil, "", refuse("bad_passkey", "%v", err)
	}

	// When: inside the window, on the cron, and now.
	approved, ok1 := parseTime(g.ApprovedAt)
	expires, ok2 := parseTime(g.ExpiresAt)
	slot, ok3 := parseTime(sr.Slot)
	if !ok1 || !ok2 || !ok3 {
		return nil, "", refuse("bad_schedule", "invalid time in the grant or slot")
	}
	if !expires.After(approved) || expires.Sub(approved) > MaxGrant {
		return nil, "", refuse("bad_schedule", "a schedule grant lasts at most 180 days")
	}
	if !now.Before(expires) || !slot.Before(expires) {
		return nil, "", refuse("expired", "schedule expired at %s", g.ExpiresAt)
	}
	if slot.Before(approved) {
		return nil, "", refuse("bad_slot", "slot is before the schedule was approved")
	}
	c, err := cron.Parse(g.Cron)
	if err != nil {
		return nil, "", refuse("bad_schedule", "%v", err)
	}
	if !c.IsSlot(slot) {
		return nil, "", refuse("bad_slot", "%s isn't a slot of %q in %s", sr.Slot, g.Cron, cron.TZName)
	}
	if now.Before(slot.Add(-Early)) || now.After(slot.Add(Late)) {
		return nil, "", refuse("bad_slot", "slot %s isn't now", sr.Slot)
	}
	claim := g.ScheduleID + "@" + slot.UTC().Format("2006-01-02T15:04:05Z")
	return &Template{V: 1, PlanID: sr.RunID, Target: t.Target, Goal: t.Goal, Steps: t.Steps}, claim, nil
}
