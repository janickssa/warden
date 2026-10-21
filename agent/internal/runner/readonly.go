package runner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/janickssa/warden/agent/internal/policy"
)

// ReadOnlyResult answers a `read_only` request (README 8).
type ReadOnlyResult struct {
	ID         string   `json:"id"`
	ExitCode   *int     `json:"exit_code"`
	Output     string   `json:"output"`
	Truncated  bool     `json:"truncated"`
	Refused    *Refusal `json:"refused"`
	DurationMS int64    `json:"duration_ms"`
}

const readOnlyTimeout = 30 * time.Second
const readOnlyCap = 1024 * 1024

type limitedBuffer struct {
	buf   bytes.Buffer
	limit int
	cut   bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := l.limit - l.buf.Len()
	if room <= 0 {
		l.cut = true
		return len(p), nil
	}
	if len(p) > room {
		l.buf.Write(p[:room])
		l.cut = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

// RunReadOnly checks a read-only command against the agent's own rules (real realpath) and runs it with a
// 30 s timeout and a 1 MB output cap.
func (r *Runner) RunReadOnly(ctx context.Context, id, command string) ReadOnlyResult {
	argv, vs := policy.CheckReadOnly(command, r.Rules, r.Resolver)
	if len(vs) > 0 {
		return ReadOnlyResult{ID: id, Refused: &Refusal{Code: vs[0].Code, Message: vs[0].Message}}
	}
	program, err := r.lookPath(argv[0])
	if err != nil {
		return ReadOnlyResult{ID: id, Refused: &Refusal{Code: "policy_violation", Message: err.Error()}}
	}
	env := []string{"PATH=" + strings.Join(DefaultPath, ":"), "LANG=C.UTF-8", "HOME=" + r.Home}
	if argv[0] == "docker" && r.Rules.DockerSocket != nil {
		env = append(env, "DOCKER_HOST=unix://"+*r.Rules.DockerSocket)
	}
	ctx, cancel := context.WithTimeout(ctx, readOnlyTimeout)
	defer cancel()
	limit := readOnlyCap
	if c := r.Rules.Limits.OutputCapMB.Value * 1024 * 1024; c < limit {
		limit = c
	}
	out := &limitedBuffer{limit: limit}
	cmd := exec.CommandContext(ctx, program)
	cmd.Args = argv
	cmd.Dir = r.Rules.WorkspaceRoots[0]
	cmd.Env = env
	cmd.Stdout, cmd.Stderr = out, out
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	start := time.Now()
	err = cmd.Run()
	res := ReadOnlyResult{ID: id, Output: strings.ToValidUTF8(out.buf.String(), "\uFFFD"), Truncated: out.cut,
		DurationMS: time.Since(start).Milliseconds()}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		res.ExitCode = intp(0)
	case errors.As(err, &exitErr):
		res.ExitCode = intp(exitErr.ExitCode())
	default:
		res.Refused = &Refusal{Code: "error", Message: err.Error()}
	}
	return res
}
