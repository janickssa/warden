// Package policy is the agent's own policy engine (README 7A): the same checks Warden runs centrally,
// repeated before every step with real realpath. It mirrors backend/src/warden/policy and must agree with
// it on every case in policy-fixtures/cases.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
)

// Violation is one reason a command is refused.
type Violation struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Step    int    `json:"step,omitempty"`
	Group   string `json:"group,omitempty"`
}

// BinaryRule is commands.allow.<program>.
type BinaryRule struct {
	Subcommands *[]string `json:"subcommands"`
	FlagsDeny   []string  `json:"flags_deny"`
}

// DenyPattern is a compiled regex with the group it came from ("" = global).
type DenyPattern struct {
	Source string  `json:"source"`
	Group  *string `json:"group"`
	re     *regexp.Regexp
}

// Limit is a limit value and the group that lowered it.
type Limit struct {
	Value int     `json:"value"`
	Group *string `json:"group"`
}

// ReadOnlyDeny is a group's read_only.deny_paths entry.
type ReadOnlyDeny struct {
	Path  string `json:"path"`
	Group string `json:"group"`
}

// Rules is the compiled rule set for one target (backend/src/warden/policy_dist/compile.py).
type Rules struct {
	Schema           int                   `json:"schema"`
	Target           string                `json:"target"`
	WorkspaceRoots   []string              `json:"workspace_roots"`
	DockerSocket     *string               `json:"docker_socket"`
	DenyPaths        []string              `json:"deny_paths"`
	Allow            map[string]BinaryRule `json:"allow"`
	DenyPatterns     []DenyPattern         `json:"deny_patterns"`
	AllowedProjects  []string              `json:"allowed_projects"`
	DeniedContainers []string              `json:"denied_containers"`
	GitHosts         []string              `json:"git_hosts"`
	HTTPCheckHosts   []string              `json:"http_check_hosts"`
	Limits           struct {
		StepTimeoutS Limit `json:"step_timeout_s"`
		PlanMaxSteps Limit `json:"plan_max_steps"`
		OutputCapMB  Limit `json:"output_cap_mb"`
	} `json:"limits"`
	ReadOnly struct {
		Mode      string         `json:"mode"`
		Group     *string        `json:"group"`
		DenyPaths []ReadOnlyDeny `json:"deny_paths"`
	} `json:"read_only"`
	Approvals struct {
		Passkey bool `json:"passkey"`
	} `json:"approvals"`
	Gatekeepers struct {
		Unanimous bool `json:"unanimous"`
	} `json:"gatekeepers"`
	Groups   []string `json:"groups"`
	Lockdown bool     `json:"lockdown"`
}

const RulesSchema = 1

// ParseRules decodes compiled rules strictly: unknown fields, a wrong schema, a bad regex or a missing
// workspace root all refuse the whole rule set (fail closed).
func ParseRules(data []byte) (*Rules, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var r Rules
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if dec.More() {
		return nil, fmt.Errorf("rules: trailing data")
	}
	if r.Schema != RulesSchema {
		return nil, fmt.Errorf("rules: unsupported schema %d", r.Schema)
	}
	if r.Target == "" || len(r.WorkspaceRoots) == 0 {
		return nil, fmt.Errorf("rules: target and workspace_roots are required")
	}
	switch r.ReadOnly.Mode {
	case "allowed", "restricted", "off":
	default:
		return nil, fmt.Errorf("rules: invalid read_only.mode %q", r.ReadOnly.Mode)
	}
	if r.Limits.StepTimeoutS.Value < 1 || r.Limits.PlanMaxSteps.Value < 1 || r.Limits.OutputCapMB.Value < 1 {
		return nil, fmt.Errorf("rules: limits must be positive")
	}
	for i := range r.DenyPatterns {
		re, err := regexp.Compile(r.DenyPatterns[i].Source)
		if err != nil {
			return nil, fmt.Errorf("rules: deny pattern %q: %w", r.DenyPatterns[i].Source, err)
		}
		r.DenyPatterns[i].re = re
	}
	return &r, nil
}

func groupName(g *string) string {
	if g == nil {
		return ""
	}
	return *g
}

func (r *Rules) readOnlyLevel() int {
	return map[string]int{"allowed": 0, "restricted": 1, "off": 2}[r.ReadOnly.Mode]
}
