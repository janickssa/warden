// Package conn keeps the agent's outbound mTLS WebSocket to Warden (README 7A): hello, heartbeats every
// 15 s, bundles, runs, kill and read-only requests. It reconnects with backoff. If the connection drops
// mid-plan, the running step may finish within its own timeout and the rest is aborted.
package conn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coder/websocket"

	"github.com/janickssa/warden/agent/internal/approval"
	"github.com/janickssa/warden/agent/internal/bundle"
	"github.com/janickssa/warden/agent/internal/runner"
	"github.com/janickssa/warden/agent/internal/state"
)

const (
	HeartbeatEvery = 15 * time.Second
	maxFrame       = 4 * 1024 * 1024
)

// Encode adds the "type" field to a message.
func Encode(typ string, v any) ([]byte, error) {
	body, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if string(body) == "{}" {
		return []byte(fmt.Sprintf(`{"type":%q}`, typ)), nil
	}
	return []byte(fmt.Sprintf(`{"type":%q,%s`, typ, body[1:])), nil
}

func typeOf(m any) string {
	switch m.(type) {
	case runner.StepStarted:
		return "step_started"
	case runner.Output:
		return "output"
	case runner.StepFinished:
		return "step_finished"
	case runner.PlanRefused:
		return "refused"
	case runner.RunFinished:
		return "run_finished"
	case runner.ReadOnlyResult:
		return "read_only_result"
	}
	return ""
}

// Agent is the long-running agent process.
type Agent struct {
	Dir     state.Dir
	Cfg     *state.Config
	Version string
	Home    string

	mu      sync.Mutex
	current *bundle.Verified
	active  map[string]*runner.Control
}

// TLSConfig trusts only Warden's CA (pinned at enrollment) and presents the agent's certificate.
func TLSConfig(dir state.Dir) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(dir.File("cert.pem"), dir.File("key.pem"))
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(dir.File("ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("ca.pem has no certificate")
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: pool, MinVersion: tls.VersionTLS13}, nil
}

// LoadBundle re-verifies the installed bundle at start-up.
func (a *Agent) LoadBundle() error {
	raw, err := os.ReadFile(a.Dir.File("bundle.json"))
	if err != nil {
		return err
	}
	v, err := bundle.Verify(raw, a.Cfg.Trust, bundle.Options{OwnTarget: a.Cfg.Name, AgentVersion: a.Version, Installed: true})
	if err != nil {
		return fmt.Errorf("installed bundle: %w", err)
	}
	a.mu.Lock()
	a.current = v
	a.mu.Unlock()
	return nil
}

func (a *Agent) policyVersion() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.current == nil {
		return 0
	}
	return a.current.Bundle.Version
}

func (a *Agent) newRunner() *runner.Runner {
	a.mu.Lock()
	defer a.mu.Unlock()
	return &runner.Runner{Rules: a.current.Rules, ApprovalKeys: a.current.ApprovalKeys, Target: a.Cfg.Name,
		Executed: a.Dir.Executed(), Resolver: runnerResolver, Now: time.Now, Home: a.Home}
}

// Run connects and reconnects until ctx ends.
func (a *Agent) Run(ctx context.Context) error {
	tlsConf, err := TLSConfig(a.Dir)
	if err != nil {
		return err
	}
	if a.active == nil {
		a.active = map[string]*runner.Control{}
	}
	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.session(ctx, tlsConf)
		if ctx.Err() != nil {
			return nil
		}
		log.Printf("connection to %s lost: %v", a.Cfg.Server, err)
		if time.Since(start) > time.Minute {
			backoff = time.Second
		}
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
	return nil
}

type writer struct {
	ch     chan []byte
	closed chan struct{}
	once   sync.Once
}

func (w *writer) Send(m any) {
	data, err := Encode(typeOf(m), m)
	if err != nil {
		log.Printf("encode: %v", err)
		return
	}
	select {
	case w.ch <- data:
	case <-w.closed:
	}
}

func (w *writer) sendTyped(typ string, v any) {
	data, err := Encode(typ, v)
	if err != nil {
		return
	}
	select {
	case w.ch <- data:
	case <-w.closed:
	}
}

func (w *writer) close() { w.once.Do(func() { close(w.closed) }) }

func (a *Agent) session(ctx context.Context, tlsConf *tls.Config) error {
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConf}}
	dialCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	c, _, err := websocket.Dial(dialCtx, strings.TrimRight(a.Cfg.Server, "/")+"/agent", &websocket.DialOptions{HTTPClient: client})
	cancel()
	if err != nil {
		return err
	}
	defer c.CloseNow()
	c.SetReadLimit(maxFrame)
	sctx, stop := context.WithCancel(ctx)
	defer stop()

	w := &writer{ch: make(chan []byte, 256), closed: make(chan struct{})}
	defer w.close()
	go func() {
		for {
			select {
			case data := <-w.ch:
				if err := c.Write(sctx, websocket.MessageText, data); err != nil {
					stop()
					return
				}
			case <-sctx.Done():
				return
			}
		}
	}()
	w.sendTyped("hello", map[string]any{"agent_version": a.Version, "policy_version": a.policyVersion()})
	log.Printf("connected to %s as %s (policy v%d)", a.Cfg.Server, a.Cfg.Name, a.policyVersion())

	go func() {
		t := time.NewTicker(HeartbeatEvery)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				w.sendTyped("heartbeat", heartbeat(a))
			case <-sctx.Done():
				return
			}
		}
	}()

	defer func() {
		// Warden is gone: let running steps finish within their own timeout, start nothing new.
		a.mu.Lock()
		for _, ctl := range a.active {
			ctl.DoDisconnect()
		}
		a.mu.Unlock()
	}()

	for {
		_, data, err := c.Read(sctx)
		if err != nil {
			return err
		}
		a.handle(ctx, data, w)
	}
}

func heartbeat(a *Agent) map[string]any {
	var st syscall.Statfs_t
	free := int64(0)
	if err := syscall.Statfs(a.Home, &st); err == nil {
		free = int64(st.Bavail) * int64(st.Bsize) / (1024 * 1024)
	}
	load := 0.0
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		fmt.Sscanf(string(b), "%f", &load)
	}
	return map[string]any{"agent_version": a.Version, "policy_version": a.policyVersion(), "disk_free_mb": free, "load1": load}
}

func (a *Agent) handle(ctx context.Context, data []byte, w *writer) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &head); err != nil {
		log.Printf("bad frame: %v", err)
		return
	}
	switch head.Type {
	case "bundle":
		var m struct {
			Type   string          `json:"type"`
			Bundle json.RawMessage `json:"bundle"`
		}
		if err := strictUnmarshal(data, &m); err != nil {
			return
		}
		a.installBundle(m.Bundle, w)
	case "run":
		var m struct {
			Type string `json:"type"`
			approval.Run
		}
		if err := strictUnmarshal(data, &m); err != nil {
			log.Printf("bad run message: %v", err)
			return
		}
		a.startRun(ctx, m.Run, w)
	case "kill":
		var m struct {
			Type   string `json:"type"`
			PlanID string `json:"plan_id"`
		}
		if err := strictUnmarshal(data, &m); err != nil {
			return
		}
		a.mu.Lock()
		ctl := a.active[m.PlanID]
		a.mu.Unlock()
		if ctl != nil {
			log.Printf("kill switch for %s", m.PlanID)
			ctl.DoKill()
		}
	case "read_only":
		var m struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			Command string `json:"command"`
		}
		if err := strictUnmarshal(data, &m); err != nil {
			return
		}
		r := a.newRunner()
		go func() { w.Send(r.RunReadOnly(ctx, m.ID, m.Command)) }()
	default:
		log.Printf("unknown message type %q", head.Type)
	}
}

func (a *Agent) installBundle(raw json.RawMessage, w *writer) {
	a.mu.Lock()
	current := a.current
	a.mu.Unlock()
	v, err := bundle.Verify(raw, a.Cfg.Trust, bundle.Options{Current: current, OwnTarget: a.Cfg.Name, AgentVersion: a.Version})
	if err != nil {
		var be *bundle.Error
		code := "bad_bundle"
		if errors.As(err, &be) {
			code = be.Code
		}
		log.Printf("refused bundle: %v", err)
		w.sendTyped("bundle_rejected", map[string]any{"version": versionOf(raw), "code": code, "message": err.Error()})
		return
	}
	if err := bundle.WriteFileAtomic(a.Dir.File("bundle.json"), v.Canonical, 0o600); err != nil {
		w.sendTyped("bundle_rejected", map[string]any{"version": v.Bundle.Version, "code": "store_failed", "message": err.Error()})
		return
	}
	a.mu.Lock()
	a.current = v
	a.mu.Unlock()
	log.Printf("installed policy v%d (%s, classified %s)", v.Bundle.Version, v.Bundle.Change, v.Class)
	w.sendTyped("bundle_ack", map[string]any{"version": v.Bundle.Version, "sha256": v.SHA256})
}

func versionOf(raw json.RawMessage) int {
	var m struct {
		Version int `json:"version"`
	}
	_ = json.Unmarshal(raw, &m)
	return m.Version
}

func (a *Agent) startRun(ctx context.Context, run approval.Run, w *writer) {
	var id struct {
		PlanID string `json:"plan_id"`
	}
	_ = json.Unmarshal(run.Template, &id)
	a.mu.Lock()
	if len(a.active) > 0 {
		a.mu.Unlock()
		w.Send(runner.PlanRefused{PlanID: id.PlanID, Code: "busy", Message: "another plan is running on this agent"})
		return
	}
	ctl := runner.NewControl()
	a.active[id.PlanID] = ctl
	a.mu.Unlock()
	r := a.newRunner()
	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.active, id.PlanID)
			a.mu.Unlock()
		}()
		log.Printf("running %s", id.PlanID)
		r.Run(ctx, run, w, ctl)
		log.Printf("finished %s", id.PlanID)
	}()
}
