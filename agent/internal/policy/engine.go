package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Step is one plan step as the agent receives it (README section 5).
type Step struct {
	N          int               `json:"n"`
	Kind       string            `json:"kind"`
	Command    string            `json:"command"`
	Purpose    string            `json:"purpose"`
	Cwd        string            `json:"cwd"`
	TimeoutS   int               `json:"timeout_s"`
	ExpectExit int               `json:"expect_exit"`
	Captures   map[string]string `json:"captures"`
}

var captureName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

func dedupe(in []Violation) []Violation {
	var out []Violation
	for _, x := range in {
		seen := false
		for _, y := range out {
			if x == y {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, x)
		}
	}
	return out
}

// CheckArgv runs every check on an already-lexed argv (used after placeholders are substituted).
func CheckArgv(step Step, raw string, argv []string, r *Rules, res Resolver) []Violation {
	n := step.N
	out := checkCwd(step.Cwd, r, res, n)
	cwdOK := len(out) == 0
	baseCwd := "/"
	if strings.HasPrefix(step.Cwd, "/") {
		baseCwd = step.Cwd
	}
	out = append(out, Baseline(argv, baseCwd, res, n)...)
	out = append(out, checkProgram(step.Kind, argv, r, n)...)
	if cwdOK {
		out = append(out, checkPaths(argv, step.Cwd, r, res, n)...)
	}
	out = append(out, checkDenyPatterns(raw, argv, r, n)...)
	if step.TimeoutS > r.Limits.StepTimeoutS.Value || step.TimeoutS < 1 {
		g := groupName(r.Limits.StepTimeoutS.Group)
		who := ""
		if g != "" {
			who = "group " + g + ": "
		}
		out = append(out, Violation{Code: "timeout_too_long", Step: n, Group: g,
			Message: fmt.Sprintf("%stimeout %d s is above limits.step_timeout_s %d s", who, step.TimeoutS, r.Limits.StepTimeoutS.Value)})
	}
	for name := range step.Captures {
		if !captureName.MatchString(name) {
			out = append(out, Violation{Code: "bad_capture", Message: fmt.Sprintf("capture name %q isn't valid", name), Step: n})
		}
	}
	return dedupe(out)
}

// CheckStep mirrors engine.check_step: lex, then every structural check. A panic becomes policy_error.
func CheckStep(step Step, r *Rules, res Resolver) (violations []Violation) {
	defer func() {
		if rec := recover(); rec != nil {
			violations = []Violation{{Code: "policy_error", Message: "policy check failed", Step: step.N}}
		}
	}()
	if r.Lockdown {
		return []Violation{{Code: "lockdown", Message: "lockdown: only read-only commands are allowed", Step: step.N}}
	}
	argv, err := Lex(step.Command)
	if err != nil {
		le := err.(*LexError)
		return []Violation{{Code: le.Code, Message: le.Message, Step: step.N}}
	}
	return CheckArgv(step, step.Command, argv, r, res)
}
