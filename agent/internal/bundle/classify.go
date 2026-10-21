package bundle

import (
	"fmt"
	"sort"

	"github.com/janickssa/warden/agent/internal/policy"
)

// Classify compares the agent's installed rules with a new bundle's (README 7A, section 16 rule 12).
// It mirrors backend/src/warden/policy_dist/classify.py and runs the same vectors. The result decides
// which signatures the agent requires: "none" or "tighten" → the online key is enough; "loosen" → the
// offline key must have signed. Anything it can't prove is tighter counts as "loosen".
func Classify(oldR, newR *policy.Rules, oldKeys, newKeys []KeyRef) (string, []string) {
	var changes []string
	loosen := false
	add := func(effect, format string, args ...any) {
		changes = append(changes, effect+" "+fmt.Sprintf(format, args...))
		if effect == "loosen" {
			loosen = true
		}
	}
	setDiff := func(path string, old, cur []string, denyList bool) {
		o, n := toSet(old), toSet(cur)
		for _, v := range sortedKeys(n) {
			if !o[v] {
				if denyList {
					add("tighten", "%s add %s", path, v)
				} else {
					add("loosen", "%s add %s", path, v)
				}
			}
		}
		for _, v := range sortedKeys(o) {
			if !n[v] {
				if denyList {
					add("loosen", "%s remove %s", path, v)
				} else {
					add("tighten", "%s remove %s", path, v)
				}
			}
		}
	}

	if oldR.Schema != newR.Schema || oldR.Target != newR.Target || strp(oldR.DockerSocket) != strp(newR.DockerSocket) {
		add("loosen", "schema, target or docker_socket changed")
	}
	setDiff("deny_paths", oldR.DenyPaths, newR.DenyPaths, true)
	setDiff("denied_containers", oldR.DeniedContainers, newR.DeniedContainers, true)
	setDiff("allowed_projects", oldR.AllowedProjects, newR.AllowedProjects, false)
	setDiff("git_hosts", oldR.GitHosts, newR.GitHosts, false)
	setDiff("http_check_hosts", oldR.HTTPCheckHosts, newR.HTTPCheckHosts, false)
	setDiff("workspace_roots", oldR.WorkspaceRoots, newR.WorkspaceRoots, false)

	for _, prog := range sortedRuleKeys(newR.Allow) {
		if _, ok := oldR.Allow[prog]; !ok {
			add("loosen", "commands.allow add %s", prog)
		}
	}
	for _, prog := range sortedRuleKeys(oldR.Allow) {
		n, ok := newR.Allow[prog]
		if !ok {
			add("tighten", "commands.allow remove %s", prog)
			continue
		}
		o := oldR.Allow[prog]
		path := "commands.allow." + prog
		switch {
		case o.Subcommands == nil && n.Subcommands != nil:
			add("tighten", "%s.subcommands any → list", path)
		case o.Subcommands != nil && n.Subcommands == nil:
			add("loosen", "%s.subcommands list → any", path)
		case o.Subcommands != nil && n.Subcommands != nil:
			setDiff(path+".subcommands", *o.Subcommands, *n.Subcommands, false)
		}
		setDiff(path+".flags_deny", o.FlagsDeny, n.FlagsDeny, true)
	}

	setDiff("commands.deny_patterns", patternSources(oldR), patternSources(newR), true)

	limit := func(name string, a, b int) {
		switch {
		case b < a:
			add("tighten", "limits.%s %d → %d", name, a, b)
		case b > a:
			add("loosen", "limits.%s %d → %d", name, a, b)
		}
	}
	limit("step_timeout_s", oldR.Limits.StepTimeoutS.Value, newR.Limits.StepTimeoutS.Value)
	limit("plan_max_steps", oldR.Limits.PlanMaxSteps.Value, newR.Limits.PlanMaxSteps.Value)
	limit("output_cap_mb", oldR.Limits.OutputCapMB.Value, newR.Limits.OutputCapMB.Value)

	ro := map[string]int{"allowed": 0, "restricted": 1, "off": 2}
	if a, b := oldR.ReadOnly.Mode, newR.ReadOnly.Mode; a != b {
		if ro[b] > ro[a] {
			add("tighten", "read_only.mode %s → %s", a, b)
		} else {
			add("loosen", "read_only.mode %s → %s", a, b)
		}
	}
	setDiff("read_only.deny_paths", roPaths(oldR), roPaths(newR), true)

	flag := func(name string, a, b bool) {
		if a != b {
			if b {
				add("tighten", "%s on", name)
			} else {
				add("loosen", "%s off", name)
			}
		}
	}
	flag("approvals.passkey", oldR.Approvals.Passkey, newR.Approvals.Passkey)
	flag("gatekeepers.unanimous", oldR.Gatekeepers.Unanimous, newR.Gatekeepers.Unanimous)
	flag("lockdown", oldR.Lockdown, newR.Lockdown)

	setDiff("approval_keys", keyStrings(oldKeys), keyStrings(newKeys), false)

	switch {
	case len(changes) == 0:
		return "none", nil
	case loosen:
		return "loosen", changes
	default:
		return "tighten", changes
	}
}

func strp(s *string) string {
	if s == nil {
		return "\x00none"
	}
	return *s
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedRuleKeys(m map[string]policy.BinaryRule) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func patternSources(r *policy.Rules) []string {
	out := make([]string, len(r.DenyPatterns))
	for i, p := range r.DenyPatterns {
		out[i] = p.Source
	}
	return out
}

func roPaths(r *policy.Rules) []string {
	out := make([]string, len(r.ReadOnly.DenyPaths))
	for i, d := range r.ReadOnly.DenyPaths {
		out[i] = d.Path
	}
	return out
}

func keyStrings(keys []KeyRef) []string {
	out := make([]string, len(keys))
	for i, k := range keys {
		out[i] = k.KeyID + "=" + k.Public
	}
	return out
}
