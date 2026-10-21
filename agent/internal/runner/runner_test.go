package runner

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/janickssa/warden/agent/internal/approval"
	"github.com/janickssa/warden/agent/internal/canonical"
	"github.com/janickssa/warden/agent/internal/policy"
	"github.com/janickssa/warden/agent/internal/state"
)

type sink struct {
	mu   sync.Mutex
	msgs []any
}

func (s *sink) Send(m any) { s.mu.Lock(); s.msgs = append(s.msgs, m); s.mu.Unlock() }

func (s *sink) finished() []StepFinished {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []StepFinished
	for _, m := range s.msgs {
		if f, ok := m.(StepFinished); ok {
			out = append(out, f)
		}
	}
	return out
}

func (s *sink) output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var b strings.Builder
	for _, m := range s.msgs {
		if o, ok := m.(Output); ok {
			b.WriteString(o.Data)
		}
	}
	return b.String()
}

func (s *sink) refusal() *PlanRefused {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, m := range s.msgs {
		if r, ok := m.(PlanRefused); ok {
			return &r
		}
	}
	return nil
}

type env struct {
	ws     string
	priv   ed25519.PrivateKey
	keyID  string
	runner *Runner
	now    time.Time
}

func setup(t *testing.T, capMB int) *env {
	t.Helper()
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	rules := fmt.Sprintf(`{"schema":1,"target":"dev","workspace_roots":[%q],"docker_socket":null,"deny_paths":["/etc"],
"allow":{"echo":{"subcommands":null,"flags_deny":[]},"sleep":{"subcommands":null,"flags_deny":[]},
"false":{"subcommands":null,"flags_deny":[]},"true":{"subcommands":null,"flags_deny":[]},
"seq":{"subcommands":null,"flags_deny":[]},"printenv":{"subcommands":null,"flags_deny":[]},
"cat":{"subcommands":null,"flags_deny":[]},"no-such-program":{"subcommands":null,"flags_deny":[]}},
"deny_patterns":[],"allowed_projects":[],"denied_containers":[],"git_hosts":[],"http_check_hosts":[],
"limits":{"step_timeout_s":{"value":60,"group":null},"plan_max_steps":{"value":10,"group":null},"output_cap_mb":{"value":%d,"group":null}},
"read_only":{"mode":"allowed","group":null,"deny_paths":[]},"approvals":{"passkey":false},"gatekeepers":{"unanimous":false},
"groups":[],"lockdown":false}`, ws, capMB)
	r, err := policy.ParseRules([]byte(rules))
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	keyID := "ed25519:test"
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	st := state.Dir{Path: t.TempDir()}
	return &env{ws: ws, priv: priv, keyID: keyID, now: now, runner: &Runner{
		Rules: r, ApprovalKeys: map[string]ed25519.PublicKey{keyID: pub}, Target: "dev", Executed: st.Executed(),
		Resolver: policy.RealResolver{}, Now: func() time.Time { return now }, Home: ws, KillGrace: 500 * time.Millisecond,
	}}
}

type stepSpec struct {
	command  string
	timeout  int
	captures map[string]string
}

var planSeq int

func (e *env) plan(t *testing.T, steps ...stepSpec) approval.Run {
	t.Helper()
	planSeq++
	var list []any
	for i, s := range steps {
		timeout := s.timeout
		if timeout == 0 {
			timeout = 10
		}
		caps := map[string]any{}
		for k, val := range s.captures {
			caps[k] = val
		}
		list = append(list, map[string]any{"n": json.Number(fmt.Sprint(i + 1)), "kind": "shell", "command": s.command,
			"purpose": "test", "cwd": e.ws, "timeout_s": json.Number(fmt.Sprint(timeout)), "expect_exit": json.Number("0"),
			"captures": caps})
	}
	planID := fmt.Sprintf("pln_TEST%022d", planSeq)
	tpl := map[string]any{"v": json.Number("1"), "plan_id": planID, "target": "dev", "goal": "test", "revises": nil, "steps": list}
	raw, err := canonical.Marshal(tpl)
	if err != nil {
		t.Fatal(err)
	}
	h := canonical.SHA256Tagged(raw)
	at, exp := e.now.Format(time.RFC3339), e.now.Add(30*time.Minute).Format(time.RFC3339)
	payload, _ := canonical.Marshal(map[string]any{"v": json.Number("1"), "plan_hash": h, "plan_id": planID,
		"target": "dev", "approved_at": at, "expires_at": exp, "by": "cli:test"})
	sig := ed25519.Sign(e.priv, append([]byte("warden-approval-v1\n"), payload...))
	return approval.Run{Template: raw, PlanHash: h, Approval: approval.Approval{By: "cli:test", At: at, ExpiresAt: exp,
		Hash: h, Signature: approval.Signature{By: "warden-approval-key", KeyID: e.keyID,
			Sig: "ed25519:" + base64.RawURLEncoding.EncodeToString(sig)}}}
}

func (e *env) run(t *testing.T, run approval.Run, ctl *Control) *sink {
	t.Helper()
	s := &sink{}
	if ctl == nil {
		ctl = NewControl()
	}
	e.runner.Run(context.Background(), run, s, ctl)
	return s
}

func exit(f StepFinished) int {
	if f.ExitCode == nil {
		return -1
	}
	return *f.ExitCode
}

func TestSuccess(t *testing.T) {
	e := setup(t, 1)
	s := e.run(t, e.plan(t, stepSpec{command: "echo hello"}, stepSpec{command: "true"}), nil)
	f := s.finished()
	if len(f) != 2 || exit(f[0]) != 0 || exit(f[1]) != 0 {
		t.Fatalf("got %+v", f)
	}
	if !strings.Contains(s.output(), "hello") {
		t.Fatalf("output %q", s.output())
	}
	if _, ok := s.msgs[len(s.msgs)-1].(RunFinished); !ok {
		t.Fatal("last message should be run_finished")
	}
}

func TestStopOnFirstFailure(t *testing.T) {
	e := setup(t, 1)
	s := e.run(t, e.plan(t, stepSpec{command: "true"}, stepSpec{command: "false"}, stepSpec{command: "echo never"}), nil)
	f := s.finished()
	if len(f) != 2 || exit(f[1]) != 1 {
		t.Fatalf("got %+v", f)
	}
	if strings.Contains(s.output(), "never") {
		t.Fatal("step 3 ran")
	}
}

func TestTimeout(t *testing.T) {
	e := setup(t, 1)
	start := time.Now()
	s := e.run(t, e.plan(t, stepSpec{command: "sleep 30", timeout: 1}), nil)
	f := s.finished()
	if len(f) != 1 || !f[0].TimedOut || exit(f[0]) != 128+15 {
		t.Fatalf("got %+v", f)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestKill(t *testing.T) {
	e := setup(t, 1)
	ctl := NewControl()
	go func() { time.Sleep(300 * time.Millisecond); ctl.DoKill() }()
	s := e.run(t, e.plan(t, stepSpec{command: "sleep 30"}, stepSpec{command: "echo after"}), ctl)
	f := s.finished()
	if len(f) != 1 || !f[0].Killed {
		t.Fatalf("got %+v", f)
	}
}

func TestDisconnectFinishesCurrentStepOnly(t *testing.T) {
	e := setup(t, 1)
	ctl := NewControl()
	go func() { time.Sleep(200 * time.Millisecond); ctl.DoDisconnect() }()
	s := e.run(t, e.plan(t, stepSpec{command: "sleep 1"}, stepSpec{command: "echo after"}), ctl)
	f := s.finished()
	if len(f) != 1 || exit(f[0]) != 0 || f[0].Killed {
		t.Fatalf("current step should finish normally, got %+v", f)
	}
	if strings.Contains(s.output(), "after") {
		t.Fatal("next step started after disconnect")
	}
}

func TestOutputCapKeepsRunning(t *testing.T) {
	e := setup(t, 1)
	s := e.run(t, e.plan(t, stepSpec{command: "seq 1 400000"}), nil) // about 2.6 MB
	f := s.finished()
	if len(f) != 1 || exit(f[0]) != 0 || !f[0].Truncated {
		t.Fatalf("got %+v", f)
	}
	if n := len(s.output()); n != 1024*1024 {
		t.Fatalf("sent %d bytes, want exactly 1 MiB", n)
	}
}

func TestReplayRefused(t *testing.T) {
	e := setup(t, 1)
	run := e.plan(t, stepSpec{command: "true"})
	e.run(t, run, nil)
	s := e.run(t, run, nil)
	if r := s.refusal(); r == nil || r.Code != "replayed_plan" {
		t.Fatalf("got %+v", r)
	}
}

func TestTamperedPlanRefused(t *testing.T) {
	e := setup(t, 1)
	run := e.plan(t, stepSpec{command: "echo safe"})
	run.Template = []byte(strings.Replace(string(run.Template), "echo safe", "echo evil", 1))
	s := e.run(t, run, nil)
	if r := s.refusal(); r == nil || r.Code != "hash_mismatch" {
		t.Fatalf("got %+v", r)
	}
	if len(s.finished()) != 0 {
		t.Fatal("a step ran")
	}
}

func TestExpiredApprovalRefused(t *testing.T) {
	e := setup(t, 1)
	run := e.plan(t, stepSpec{command: "true"})
	e.runner.Now = func() time.Time { return e.now.Add(31 * time.Minute) }
	if r := e.run(t, run, nil).refusal(); r == nil || r.Code != "expired" {
		t.Fatalf("got %+v", r)
	}
}

func TestSymlinkEscapeRefusedOnAgent(t *testing.T) {
	e := setup(t, 1)
	if err := os.Symlink("/etc/hostname", filepath.Join(e.ws, "link")); err != nil {
		t.Fatal(err)
	}
	s := e.run(t, e.plan(t, stepSpec{command: "cat link"}), nil)
	f := s.finished()
	if len(f) != 1 || f[0].Refused == nil || f[0].Refused.Code != "policy_violation" || exit(f[0]) != 126 {
		t.Fatalf("got %+v", f)
	}
	if strings.Contains(s.output(), "\n") {
		t.Fatal("cat ran")
	}
}

func TestCapturesSubstitutedAsArgv(t *testing.T) {
	e := setup(t, 1)
	s := e.run(t, e.plan(t,
		stepSpec{command: "echo 0123456789abcdef", captures: map[string]string{"container_id": "stdout_trimmed"}},
		stepSpec{command: "echo got {{step1.container_id}}"}), nil)
	f := s.finished()
	if len(f) != 2 || exit(f[1]) != 0 || !strings.Contains(s.output(), "got 0123456789abcdef") {
		t.Fatalf("got %+v / %q", f, s.output())
	}
}

func TestInvalidCaptureRefused(t *testing.T) {
	e := setup(t, 1)
	s := e.run(t, e.plan(t,
		stepSpec{command: "echo not-hex!", captures: map[string]string{"container_id": "stdout_trimmed"}},
		stepSpec{command: "echo {{step1.container_id}}"}), nil)
	f := s.finished()
	if len(f) != 1 || f[0].Refused == nil {
		t.Fatalf("got %+v", f)
	}
}

func TestSecretsRefusedForNow(t *testing.T) {
	e := setup(t, 1)
	s := e.run(t, e.plan(t, stepSpec{command: "echo {{secret:TOKEN}}"}), nil)
	if f := s.finished(); len(f) != 1 || f[0].Refused == nil || !strings.Contains(f[0].Refused.Message, "secret") {
		t.Fatalf("got %+v", f)
	}
}

func TestMinimalEnvironment(t *testing.T) {
	t.Setenv("WARDEN_TEST_LEAK", "leaked")
	e := setup(t, 1)
	s := e.run(t, e.plan(t, stepSpec{command: "printenv"}), nil)
	out := s.output()
	if strings.Contains(out, "leaked") || !strings.Contains(out, "PATH=/usr/local/bin:/usr/bin:/bin") {
		t.Fatalf("environment: %q", out)
	}
}

func TestProgramMustBeOnFixedPath(t *testing.T) {
	e := setup(t, 1)
	s := e.run(t, e.plan(t, stepSpec{command: "no-such-program"}), nil)
	if f := s.finished(); len(f) != 1 || f[0].Refused == nil {
		t.Fatalf("got %+v", f)
	}
}

func TestWrongTargetRefused(t *testing.T) {
	e := setup(t, 1)
	e.runner.Target = "dev2"
	if r := e.run(t, e.plan(t, stepSpec{command: "true"}), nil).refusal(); r == nil || r.Code != "wrong_target" {
		t.Fatalf("got %+v", r)
	}
}
