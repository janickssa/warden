// Package runner executes an approved plan on the target (README 7A).
//
// Before anything runs: approval verified, plan ID claimed in the executed log. Before every step: policy
// checked on the template and again on the argv after placeholders are substituted, with real realpath.
// Steps run as argv (no shell) with a minimal environment, in their own process group, with a timeout
// (SIGTERM, then SIGKILL after the grace period) and an output cap. The first failure stops the plan.
package runner

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/janickssa/warden/agent/internal/approval"
	"github.com/janickssa/warden/agent/internal/policy"
	"github.com/janickssa/warden/agent/internal/state"
)

// Messages sent to Warden (the conn package adds the "type" field).
type StepStarted struct {
	PlanID string `json:"plan_id"`
	N      int    `json:"n"`
}

type Output struct {
	PlanID    string `json:"plan_id"`
	N         int    `json:"n"`
	Stream    string `json:"stream"`
	Data      string `json:"data"`
	Truncated bool   `json:"truncated"`
}

type Refusal struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type StepFinished struct {
	PlanID     string   `json:"plan_id"`
	N          int      `json:"n"`
	ExitCode   *int     `json:"exit_code"`
	TimedOut   bool     `json:"timed_out"`
	Killed     bool     `json:"killed"`
	Refused    *Refusal `json:"refused"`
	DurationMS int64    `json:"duration_ms"`
	Truncated  bool     `json:"truncated"`
}

type PlanRefused struct {
	PlanID  string `json:"plan_id"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type RunFinished struct {
	PlanID string `json:"plan_id"`
}

// Sink receives messages for Warden. It must not block for long.
type Sink interface{ Send(msg any) }

// DefaultPath is the only place programs are looked up.
var DefaultPath = []string{"/usr/local/bin", "/usr/bin", "/bin"}

type Runner struct {
	Rules        *policy.Rules
	ApprovalKeys map[string]ed25519.PublicKey
	Target       string
	Executed     *state.ExecutedLog
	Resolver     policy.Resolver
	Now          func() time.Time
	Path         []string
	Home         string
	KillGrace    time.Duration
}

const captureLimit = 4096
const chunkSize = 32 * 1024

var (
	containerID = regexp.MustCompile(`^[a-f0-9]{12,64}$`)
	port        = regexp.MustCompile(`^[0-9]{1,5}$`)
	generic     = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
)

func validCapture(name, value string) bool {
	switch {
	case strings.HasSuffix(name, "container_id"):
		return containerID.MatchString(value)
	case strings.HasSuffix(name, "port"):
		if !port.MatchString(value) {
			return false
		}
		var n int
		fmt.Sscanf(value, "%d", &n)
		return n >= 1 && n <= 65535
	}
	return generic.MatchString(value)
}

func (r *Runner) lookPath(program string) (string, error) {
	dirs := r.Path
	if len(dirs) == 0 {
		dirs = DefaultPath
	}
	for _, d := range dirs {
		p := filepath.Join(d, program)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in %s", program, strings.Join(dirs, ":"))
}

// Control lets the connection stop a run: Kill is the kill switch, Disconnected means Warden is gone
// (finish the current step within its timeout, then abort the rest).
type Control struct {
	Kill         chan struct{}
	Disconnected chan struct{}
	killOnce     sync.Once
	discOnce     sync.Once
}

func NewControl() *Control {
	return &Control{Kill: make(chan struct{}), Disconnected: make(chan struct{})}
}

func (c *Control) DoKill()       { c.killOnce.Do(func() { close(c.Kill) }) }
func (c *Control) DoDisconnect() { c.discOnce.Do(func() { close(c.Disconnected) }) }

func closed(ch chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func intp(n int) *int { return &n }

// Run verifies and executes one plan, reporting everything to sink.
func (r *Runner) Run(ctx context.Context, run approval.Run, sink Sink, ctl *Control) {
	tpl, err := approval.Verify(run, r.ApprovalKeys, r.Rules.Approvals, r.Target, r.Now())
	if err != nil {
		var ae *approval.Error
		code := "bad_plan"
		if errors.As(err, &ae) {
			code = ae.Code
		}
		sink.Send(PlanRefused{PlanID: planIDOf(run), Code: code, Message: err.Error()})
		return
	}
	if r.Rules.Lockdown {
		sink.Send(PlanRefused{PlanID: tpl.PlanID, Code: "lockdown", Message: "lockdown: only read-only commands are allowed"})
		return
	}
	if len(tpl.Steps) > r.Rules.Limits.PlanMaxSteps.Value {
		sink.Send(PlanRefused{PlanID: tpl.PlanID, Code: "too_many_steps", Message: "plan has more steps than limits.plan_max_steps"})
		return
	}
	if err := r.Executed.Claim(tpl.PlanID, run.PlanHash); err != nil {
		sink.Send(PlanRefused{PlanID: tpl.PlanID, Code: "replayed_plan", Message: err.Error()})
		return
	}
	captures := map[string]string{}
	for _, step := range tpl.Steps {
		if closed(ctl.Kill) || closed(ctl.Disconnected) || ctx.Err() != nil {
			break
		}
		res := r.runStep(ctx, tpl.PlanID, step, captures, sink, ctl)
		sink.Send(res)
		if res.Refused != nil || res.TimedOut || res.Killed || res.ExitCode == nil || *res.ExitCode != step.ExpectExit {
			break
		}
	}
	sink.Send(RunFinished{PlanID: tpl.PlanID})
}

func planIDOf(run approval.Run) string {
	var t struct {
		PlanID string `json:"plan_id"`
	}
	_ = json.Unmarshal(run.Template, &t)
	return t.PlanID
}

func refused(planID string, n int, code, msg string) StepFinished {
	return StepFinished{PlanID: planID, N: n, ExitCode: intp(126), Refused: &Refusal{Code: code, Message: msg}}
}

// substitute replaces whole-element placeholders with captured values (single argv elements, never
// interpolated into strings). Secrets aren't supported yet, so they refuse.
func substitute(argv []string, captures map[string]string) ([]string, error) {
	out := make([]string, len(argv))
	for i, tok := range argv {
		m := policy.Placeholder.FindStringSubmatch(tok)
		if m == nil {
			out[i] = tok
			continue
		}
		if m[3] != "" {
			return nil, fmt.Errorf("{{secret:%s}}: secrets aren't supported by this agent yet", m[3])
		}
		val, ok := captures[m[1]+"."+m[2]]
		if !ok {
			return nil, fmt.Errorf("%s: no captured value", tok)
		}
		out[i] = val
	}
	return out, nil
}

func (r *Runner) runStep(ctx context.Context, planID string, step policy.Step, captures map[string]string, sink Sink, ctl *Control) StepFinished {
	// 1. Policy on the template.
	if vs := policy.CheckStep(step, r.Rules, r.Resolver); len(vs) > 0 {
		return refused(planID, step.N, "policy_violation", vs[0].Code+": "+vs[0].Message)
	}
	argv, err := policy.Lex(step.Command)
	if err != nil {
		return refused(planID, step.N, "policy_violation", err.Error())
	}
	// 2. Placeholders, then policy again on what will actually run.
	argv, err = substitute(argv, captures)
	if err != nil {
		return refused(planID, step.N, "policy_violation", err.Error())
	}
	if vs := policy.CheckArgv(step, step.Command, argv, r.Rules, r.Resolver); len(vs) > 0 {
		return refused(planID, step.N, "policy_violation", vs[0].Code+": "+vs[0].Message)
	}
	program, err := r.lookPath(argv[0])
	if err != nil {
		return refused(planID, step.N, "policy_violation", err.Error())
	}

	sink.Send(StepStarted{PlanID: planID, N: step.N})
	env := []string{"PATH=" + strings.Join(DefaultPath, ":"), "LANG=C.UTF-8", "HOME=" + r.Home}
	if step.Kind == "docker" && r.Rules.DockerSocket != nil {
		env = append(env, "DOCKER_HOST=unix://"+*r.Rules.DockerSocket)
	}
	cmd := &exec.Cmd{Path: program, Args: argv, Dir: step.Cwd, Env: env,
		SysProcAttr: &syscall.SysProcAttr{Setpgid: true}}
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	start := time.Now()
	if err := cmd.Start(); err != nil {
		return refused(planID, step.N, "policy_violation", "can't start: "+err.Error())
	}

	capLimit := int64(r.Rules.Limits.OutputCapMB.Value) * 1024 * 1024
	out := &capped{limit: capLimit, sink: sink, planID: planID, n: step.N}
	var captured strings.Builder
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); out.pump(stdout, "stdout", &captured) }()
	go func() { defer wg.Done(); out.pump(stderr, "stderr", nil) }()

	done := make(chan error, 1)
	go func() { wg.Wait(); done <- cmd.Wait() }()

	timeout := time.NewTimer(time.Duration(step.TimeoutS) * time.Second)
	defer timeout.Stop()
	grace := r.KillGrace
	if grace == 0 {
		grace = 10 * time.Second
	}
	timedOut, killed := false, false
	var waitErr error
	stop := func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		select {
		case waitErr = <-done:
		case <-time.After(grace):
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			waitErr = <-done
		}
	}
	// A dropped connection doesn't stop the current step: it may finish within its own timeout.
	select {
	case waitErr = <-done:
	case <-timeout.C:
		timedOut = true
		stop()
	case <-ctl.Kill:
		killed = true
		stop()
	case <-ctx.Done():
		killed = true
		stop()
	}
	res := StepFinished{PlanID: planID, N: step.N, TimedOut: timedOut, Killed: killed,
		DurationMS: time.Since(start).Milliseconds(), Truncated: out.truncated()}
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		res.ExitCode = intp(0)
	case errors.As(waitErr, &exitErr):
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			res.ExitCode = intp(128 + int(ws.Signal()))
		} else {
			res.ExitCode = intp(exitErr.ExitCode())
		}
	}
	if res.ExitCode != nil && *res.ExitCode == step.ExpectExit && !timedOut && !killed {
		for name := range step.Captures {
			val := strings.TrimSpace(captured.String())
			if !validCapture(name, val) {
				return refused(planID, step.N, "policy_violation", fmt.Sprintf("captured %s isn't a valid value", name))
			}
			captures[fmt.Sprintf("%d.%s", step.N, name)] = val
		}
	}
	return res
}

// capped streams output to Warden until the per-step cap, then keeps draining without sending, so the
// step keeps running and its exit code still counts.
type capped struct {
	mu     sync.Mutex
	limit  int64
	sent   int64
	cut    bool
	sink   Sink
	planID string
	n      int
}

func (c *capped) truncated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cut
}

func (c *capped) pump(rd io.Reader, stream string, capture *strings.Builder) {
	buf := make([]byte, chunkSize)
	for {
		n, err := rd.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			if capture != nil && capture.Len() < captureLimit {
				room := captureLimit - capture.Len()
				if room > n {
					room = n
				}
				capture.Write(chunk[:room])
			}
			c.mu.Lock()
			send := chunk
			if c.sent+int64(len(send)) > c.limit {
				send = send[:max(0, c.limit-c.sent)]
				c.cut = true
			}
			c.sent += int64(len(send))
			truncNow := c.cut
			c.mu.Unlock()
			if len(send) > 0 || truncNow {
				if len(send) > 0 {
					c.sink.Send(Output{PlanID: c.planID, N: c.n, Stream: stream, Data: strings.ToValidUTF8(string(send), "\uFFFD"), Truncated: truncNow})
				}
			}
		}
		if err != nil {
			return
		}
	}
}
