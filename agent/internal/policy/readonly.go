package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Mirrors backend/src/warden/policy/readonly.py.

var intRE = regexp.MustCompile(`^[0-9]{1,6}$`)

var (
	lsFlags        = "lahdRrtS1AF"
	lsLong         = set("--all", "--almost-all", "--human-readable", "--directory", "--recursive", "--reverse")
	gitStatusFlags = set("-s", "--short", "-b", "--branch", "--porcelain")
	gitLogFlags    = set("--oneline", "--stat", "--decorate", "--graph", "--no-color", "--all", "-p")
	dockerPsFlags  = set("-a", "--all", "-q", "--quiet", "--no-trunc", "-s", "--size")
)

func refuse(msg string) []Violation {
	return []Violation{{Code: "not_read_only", Message: "not on the read-only allowlist: " + msg}}
}

func fileArgs(argv []string, allowed string, long map[string]bool, valueFlags map[string]bool) ([]string, []Violation) {
	var paths []string
	var errs []Violation
	for i := 1; i < len(argv); i++ {
		tok := argv[i]
		if valueFlags[tok] {
			if i+1 >= len(argv) || !intRE.MatchString(argv[i+1]) {
				errs = append(errs, refuse(fmt.Sprintf("%s %s needs a number", argv[0], tok))...)
			}
			i++
			continue
		}
		if strings.HasPrefix(tok, "--") {
			name, value, _ := strings.Cut(tok, "=")
			if long[name] || (name == "--lines" && intRE.MatchString(value)) {
				continue
			}
			errs = append(errs, refuse(argv[0]+" "+tok)...)
		} else if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			for _, c := range tok[1:] {
				if !strings.ContainsRune(allowed, c) {
					errs = append(errs, refuse(argv[0]+" "+tok)...)
					break
				}
			}
		} else {
			paths = append(paths, tok)
		}
	}
	if len(paths) == 0 {
		errs = append(errs, refuse(argv[0]+" needs at least one absolute path")...)
	}
	return paths, errs
}

func roShape(argv []string, r *Rules) ([]string, []Violation) {
	program := argv[0]
	switch program {
	case "ls":
		return fileArgs(argv, lsFlags, lsLong, nil)
	case "cat":
		return fileArgs(argv, "n", nil, nil)
	case "head", "tail":
		return fileArgs(argv, "", nil, set("-n", "-c"))
	case "stat":
		return fileArgs(argv, "", nil, nil)
	case "df":
		if len(argv) == 2 && argv[1] == "-h" {
			return nil, nil
		}
		return nil, refuse("only `df -h`")
	case "free":
		if len(argv) == 2 && argv[1] == "-m" {
			return nil, nil
		}
		return nil, refuse("only `free -m`")
	case "git":
		if len(argv) < 4 || argv[1] != "-C" || (argv[3] != "status" && argv[3] != "log") {
			return nil, refuse("git must be `git -C <path> status` or `git -C <path> log`")
		}
		allowed := gitStatusFlags
		if argv[3] == "log" {
			allowed = gitLogFlags
		}
		var errs []Violation
		for i := 4; i < len(argv); i++ {
			tok := argv[i]
			if argv[3] == "log" && (tok == "-n" || tok == "--max-count") && i+1 < len(argv) && intRE.MatchString(argv[i+1]) {
				i++
				continue
			}
			if argv[3] == "log" && strings.HasPrefix(tok, "--max-count=") && intRE.MatchString(afterEq(tok)) {
				continue
			}
			if !allowed[tok] {
				errs = append(errs, refuse("git "+argv[3]+" "+tok)...)
			}
		}
		return []string{argv[2]}, errs
	case "docker":
		return nil, roDocker(argv, r)
	case "curl":
		return nil, CheckCurl(argv, r, 0, true)
	}
	return nil, refuse(program + " isn't a read-only command")
}

func roDocker(argv []string, r *Rules) []Violation {
	sub := ""
	if len(argv) > 1 {
		sub = argv[1]
	}
	var out []Violation
	var names []string
	switch sub {
	case "ps":
		for i := 2; i < len(argv); i++ {
			tok := argv[i]
			if (tok == "--filter" || tok == "-f") && i+1 < len(argv) {
				names = append(names, afterEq(argv[i+1]))
				i++
				continue
			}
			if !dockerPsFlags[tok] {
				out = append(out, refuse("docker ps "+tok)...)
			}
		}
	case "logs":
		rest := argv[2:]
		hasTail := false
		for _, t := range rest {
			if t == "--tail" {
				hasTail = true
			}
		}
		if !hasTail {
			return refuse("docker logs needs --tail N")
		}
		for i := 0; i < len(rest); i++ {
			tok := rest[i]
			if (tok == "--tail" || tok == "--since") && i+1 < len(rest) {
				if tok == "--tail" && !intRE.MatchString(rest[i+1]) {
					out = append(out, refuse("docker logs --tail needs a number")...)
				}
				i++
				continue
			}
			if tok == "-t" || tok == "--timestamps" {
				continue
			}
			if strings.HasPrefix(tok, "-") {
				out = append(out, refuse("docker logs "+tok)...)
			} else {
				names = append(names, tok)
			}
		}
		if len(names) != 1 {
			out = append(out, refuse("docker logs needs exactly one container")...)
		}
	case "inspect":
		for _, tok := range argv[2:] {
			if strings.HasPrefix(tok, "-") {
				out = append(out, refuse("docker inspect "+tok)...)
			} else {
				names = append(names, tok)
			}
		}
		if len(names) == 0 {
			out = append(out, refuse("docker inspect needs a container")...)
		}
	case "compose":
		rest := argv[2:]
		if len(rest) > 0 && (rest[0] == "-p" || rest[0] == "--project-name") {
			if len(rest) < 2 || nameMatches(rest[1], r.AllowedProjects) == "" {
				out = append(out, Violation{Code: "compose_project_denied", Message: "compose project isn't in docker.allowed_projects"})
			}
			if len(rest) >= 2 {
				rest = rest[2:]
			} else {
				rest = nil
			}
		}
		if len(rest) != 1 || rest[0] != "ps" {
			out = append(out, refuse("only `docker compose [-p <project>] ps`")...)
		}
	default:
		return refuse("docker " + sub)
	}
	for _, n := range names {
		if hit := nameMatches(n, r.DeniedContainers); hit != "" {
			out = append(out, Violation{Code: "container_denied", Message: fmt.Sprintf("container %s matches docker.denied_containers %s", n, hit)})
		}
	}
	return out
}

// CheckReadOnly mirrors readonly.check_read_only. Returns argv when allowed.
func CheckReadOnly(command string, r *Rules, res Resolver) (argv []string, violations []Violation) {
	defer func() {
		if rec := recover(); rec != nil {
			argv, violations = nil, []Violation{{Code: "policy_error", Message: "read-only check failed"}}
		}
	}()
	if r.ReadOnly.Mode == "off" {
		g := groupName(r.ReadOnly.Group)
		return nil, []Violation{{Code: "read_only_off", Message: "group " + g + ": read-only commands are off; this needs a plan", Group: g}}
	}
	argv, err := Lex(command)
	if err != nil {
		le := err.(*LexError)
		return nil, []Violation{{Code: le.Code, Message: le.Message}}
	}
	cwd := r.WorkspaceRoots[0]
	paths, out := roShape(argv, r)
	for _, p := range paths {
		if !strings.HasPrefix(p, "/") {
			out = append(out, Violation{Code: "relative_path", Message: p + ": read-only commands need absolute paths"})
			continue
		}
		if r.ReadOnly.Mode == "restricted" {
			if got, rerr := res.Resolve(p, cwd); rerr == nil {
				for _, d := range r.ReadOnly.DenyPaths {
					if IsWithin(got.Lexical, d.Path) || IsWithin(got.Real, d.Path) {
						out = append(out, Violation{Code: "read_only_denied_path", Message: fmt.Sprintf("group %s: read_only.deny_paths includes %s", d.Group, d.Path), Group: d.Group})
						break
					}
				}
			}
		}
		out = append(out, CheckPath(p, cwd, r, res, 0, "path")...)
	}
	out = append(out, Baseline(argv, cwd, res, 0)...)
	out = append(out, checkDenyPatterns(command, argv, r, 0)...)
	out = dedupe(out)
	if len(out) > 0 {
		return nil, out
	}
	return argv, nil
}
