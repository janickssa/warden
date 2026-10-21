package policy

import (
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var programKind = map[string]string{"git": "git", "docker": "docker", "curl": "http_check"}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, it := range items {
		m[it] = true
	}
	return m
}

var (
	gitGlobalWithValue = set("-C")
	gitGlobalNoValue   = set("--no-pager", "-P", "--no-replace-objects", "--literal-pathspecs", "--no-optional-locks")
	gitDenyAnywhere    = []string{"-c", "--config", "--config-env", "--upload-pack", "--receive-pack", "--exec",
		"--template", "--separate-git-dir", "--recurse-submodules", "--recursive", "--git-dir", "--work-tree",
		"--ext-diff", "--open-files-in-pager", "--textconv"}
	scpLike = regexp.MustCompile(`^[^/\s:]+@[^/\s:]+:|^[A-Za-z0-9.-]+:[^/]`)

	curlShortNoArg = "IsSfiv46"
	curlLongNoArg  = set("--head", "--silent", "--show-error", "--fail", "--fail-with-body", "--include",
		"--verbose", "--compressed", "--ipv4", "--ipv6", "--no-progress-meter")
	curlShortArg = set("-m", "-H", "-A", "-X")
	curlLongArg  = set("--max-time", "--connect-timeout", "--header", "--user-agent", "--retry", "--request")
	curlMethods  = set("GET", "HEAD")

	npmGlobalWithValue = set("--prefix")
	npmGlobalNoValue   = set("--silent", "-s", "--no-audit", "--no-fund", "--quiet", "-q")
	npmDenyAnywhere    = []string{"-g", "--global", "--location", "--userconfig", "--globalconfig", "--script-shell"}
)

func v(code, msg string, step int, group string) Violation {
	return Violation{Code: code, Message: msg, Step: step, Group: group}
}

func hostMatches(host string, patterns []string) bool {
	host = strings.TrimRight(strings.ToLower(host), ".")
	for _, p := range patterns {
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(host, p[1:]) && host != p[2:] {
				return true
			}
		} else if host == p {
			return true
		}
	}
	return false
}

// globMatch is fnmatchcase for the restricted patterns policy allows ([A-Za-z0-9*?._-]).
func globMatch(name, glob string) bool {
	var b strings.Builder
	b.WriteString("^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString("$")
	return regexp.MustCompile(b.String()).MatchString(name)
}

func nameMatches(name string, globs []string) string {
	for _, g := range globs {
		if globMatch(name, g) {
			return g
		}
	}
	return ""
}

func flagDenied(tok string, denied []string) string {
	if strings.HasPrefix(tok, "--") {
		name, _, _ := strings.Cut(tok, "=")
		for _, d := range denied {
			if strings.HasPrefix(d, "--") && (name == d || (len(name) > 2 && strings.HasPrefix(d, name))) {
				return d
			}
		}
		return ""
	}
	if strings.HasPrefix(tok, "-") && len(tok) > 1 {
		for _, c := range tok[1:] {
			for _, d := range denied {
				if d == "-"+string(c) {
					return d
				}
			}
		}
	}
	return ""
}

func checkFlagsDeny(argv []string, rule BinaryRule, step int) []Violation {
	var out []Violation
	for _, tok := range argv[1:] {
		if tok == "--" {
			break
		}
		if hit := flagDenied(tok, rule.FlagsDeny); hit != "" {
			out = append(out, v("flag_denied", fmt.Sprintf("%s flag %s matches %s in flags_deny", argv[0], tok, hit), step, ""))
		}
	}
	return out
}

func checkSubcommand(program string, sub string, has bool, rule BinaryRule, step int) []Violation {
	if rule.Subcommands == nil {
		return nil
	}
	if !has {
		return []Violation{v("missing_subcommand", program+" needs a subcommand", step, "")}
	}
	for _, s := range *rule.Subcommands {
		if s == sub {
			return nil
		}
	}
	return []Violation{v("subcommand_not_allowed", fmt.Sprintf("%s %s isn't in commands.allow.%s.subcommands (%s)",
		program, sub, program, strings.Join(*rule.Subcommands, ", ")), step, "")}
}

type splitURL struct {
	scheme, hostname string
	hasUser          bool
	port             int // -1 none
	err              error
}

func parseURL(raw string) splitURL {
	u, err := url.Parse(raw)
	if err != nil {
		return splitURL{err: err}
	}
	out := splitURL{scheme: strings.ToLower(u.Scheme), hostname: strings.ToLower(u.Hostname()), hasUser: u.User != nil, port: -1}
	if p := u.Port(); p != "" {
		n, perr := strconv.Atoi(p)
		if perr != nil || n > 65535 {
			out.err = fmt.Errorf("invalid port")
			return out
		}
		out.port = n
	}
	return out
}

func gitURLOK(raw string, r *Rules) string {
	if !IsURL(raw) {
		return "only https:// URLs are allowed for git"
	}
	u := parseURL(raw)
	if u.err != nil {
		return "invalid URL"
	}
	if u.scheme != "https" {
		return fmt.Sprintf("scheme %s:// isn't allowed (https only)", u.scheme)
	}
	if u.hasUser {
		return "credentials in the URL aren't allowed"
	}
	if u.port != -1 && u.port != 443 {
		return fmt.Sprintf("port %d isn't allowed", u.port)
	}
	if u.hostname == "" || !hostMatches(u.hostname, r.GitHosts) {
		return fmt.Sprintf("host %s isn't in network.git_hosts", u.hostname)
	}
	return ""
}

func checkGit(argv []string, r *Rules, step int) []Violation {
	var out []Violation
	i := 1
	for i < len(argv) && strings.HasPrefix(argv[i], "-") {
		tok := argv[i]
		switch {
		case gitGlobalWithValue[tok]:
			i += 2
			continue
		case gitGlobalNoValue[tok]:
			i++
			continue
		}
		out = append(out, v("git_option_denied", fmt.Sprintf("git option %s isn't allowed before the subcommand", tok), step, ""))
		i++
	}
	sub, has := "", i < len(argv)
	if has {
		sub = argv[i]
	}
	out = append(out, checkSubcommand("git", sub, has, r.Allow["git"], step)...)
	rest := []string{}
	if has {
		rest = argv[i+1:]
	}
	for _, tok := range rest {
		if tok == "--" {
			break
		}
		if hit := flagDenied(tok, gitDenyAnywhere); hit != "" {
			out = append(out, v("git_option_denied", fmt.Sprintf("git option %s isn't allowed (%s)", tok, hit), step, ""))
		}
		if (sub == "clone" || sub == "fetch" || sub == "pull" || sub == "ls-remote") && tok == "-u" {
			out = append(out, v("git_option_denied", "git -u (upload-pack) isn't allowed", step, ""))
		}
	}
	var urls []string
	for _, t := range rest {
		if IsURL(t) || scpLike.MatchString(t) || strings.Contains(t, "::") || strings.HasPrefix(t, "file:") {
			urls = append(urls, t)
		}
	}
	for _, u := range urls {
		if why := gitURLOK(u, r); why != "" {
			out = append(out, v("git_url_denied", fmt.Sprintf("git URL %s: %s", u, why), step, ""))
		}
	}
	if sub == "clone" && len(urls) == 0 {
		out = append(out, v("git_url_denied", "git clone needs an https:// URL", step, ""))
	}
	return out
}

func afterEq(s string) string {
	if _, val, ok := strings.Cut(s, "="); ok {
		return val
	}
	return s
}

func dockerContainers(argv []string, start int) []string {
	var names []string
	for _, tok := range argv[start:] {
		if strings.HasPrefix(tok, "-") {
			if strings.HasPrefix(tok, "--") && strings.Contains(tok, "=") {
				names = append(names, afterEq(afterEq(tok)))
			}
			continue
		}
		names = append(names, afterEq(tok))
	}
	return names
}

func checkDocker(argv []string, r *Rules, step int) []Violation {
	if len(argv) < 2 || strings.HasPrefix(argv[1], "-") {
		return []Violation{v("docker_option_denied", "docker global options (-H, --context, --config, ...) aren't "+
			"allowed; start with the subcommand", step, "")}
	}
	sub := argv[1]
	out := checkSubcommand("docker", sub, true, r.Allow["docker"], step)
	if sub == "compose" {
		project, hasProject := "", false
		i := 2
		for i < len(argv) && strings.HasPrefix(argv[i], "-") {
			tok := argv[i]
			name, _, _ := strings.Cut(tok, "=")
			switch {
			case tok == "-p" || tok == "--project-name":
				if i+1 < len(argv) {
					project, hasProject = argv[i+1], true
				}
				i += 2
			case strings.HasPrefix(tok, "--project-name="):
				project, hasProject = afterEq(tok), true
				i++
			case tok == "-f" || tok == "--file" || tok == "--env-file" || tok == "--project-directory" || tok == "--profile":
				i += 2
			case name == "--file" || name == "--env-file" || name == "--project-directory" || name == "--profile":
				i++
			default:
				out = append(out, v("docker_option_denied", fmt.Sprintf("docker compose option %s isn't allowed", tok), step, ""))
				i++
			}
		}
		if !hasProject {
			out = append(out, v("compose_project_required", "docker compose needs -p <project> so Warden can check "+
				"it against docker.allowed_projects", step, ""))
		} else if !IsPlaceholder(project) && nameMatches(project, r.AllowedProjects) == "" {
			out = append(out, v("compose_project_denied", fmt.Sprintf("compose project %s isn't in docker.allowed_projects", project), step, ""))
		}
		if i >= len(argv) {
			out = append(out, v("missing_subcommand", "docker compose needs a subcommand", step, ""))
		}
		return out
	}
	for _, name := range dockerContainers(argv, 2) {
		if hit := nameMatches(name, r.DeniedContainers); hit != "" {
			out = append(out, v("container_denied", fmt.Sprintf("container %s matches docker.denied_containers %s", name, hit), step, ""))
		}
	}
	return out
}

func checkHTTPURL(raw string, r *Rules, step int) []Violation {
	u := parseURL(raw)
	if u.err != nil || (u.scheme != "http" && u.scheme != "https") {
		if u.err == nil {
			return []Violation{v("http_url_denied", raw+": only http:// and https:// are allowed", step, "")}
		}
		return []Violation{v("http_url_denied", raw+": invalid URL", step, "")}
	}
	if u.hasUser {
		return []Violation{v("http_url_denied", raw+": credentials in the URL aren't allowed", step, "")}
	}
	if u.hostname == "" || !hostMatches(u.hostname, r.HTTPCheckHosts) {
		return []Violation{v("http_host_denied", fmt.Sprintf("host %s isn't in network.http_check_hosts", u.hostname), step, "")}
	}
	return nil
}

// CheckCurl mirrors matcher.check_curl.
func CheckCurl(argv []string, r *Rules, step int, readOnly bool) []Violation {
	var out []Violation
	var urls []string
	i := 1
	for i < len(argv) {
		tok := argv[i]
		if strings.HasPrefix(tok, "--") {
			name, value, eq := strings.Cut(tok, "=")
			if curlLongNoArg[name] && !eq {
				i++
				continue
			}
			if curlLongArg[name] && !readOnly {
				val := value
				if !eq {
					val = ""
					if i+1 < len(argv) {
						val = argv[i+1]
					}
				}
				if name == "--request" && !curlMethods[val] {
					out = append(out, v("curl_method_denied", fmt.Sprintf("curl --request %s: only GET and HEAD", val), step, ""))
				}
				if eq {
					i++
				} else {
					i += 2
				}
				continue
			}
			if (name == "--max-time" || name == "--connect-timeout") && readOnly {
				if eq {
					i++
				} else {
					i += 2
				}
				continue
			}
			out = append(out, v("curl_flag_not_allowed", fmt.Sprintf("curl %s isn't allowed in an HTTP check", name), step, ""))
			i++
			continue
		}
		if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			if curlShortArg[tok] && (!readOnly || tok == "-m") {
				val := ""
				if i+1 < len(argv) {
					val = argv[i+1]
				}
				if tok == "-X" && !curlMethods[val] {
					out = append(out, v("curl_method_denied", fmt.Sprintf("curl -X %s: only GET and HEAD", val), step, ""))
				}
				i += 2
				continue
			}
			for _, c := range tok[1:] {
				if !strings.ContainsRune(curlShortNoArg, c) {
					out = append(out, v("curl_flag_not_allowed", fmt.Sprintf("curl %s isn't allowed in an HTTP check", tok), step, ""))
					break
				}
			}
			i++
			continue
		}
		urls = append(urls, tok)
		i++
	}
	if len(urls) != 1 {
		out = append(out, v("http_url_denied", "an HTTP check needs exactly one URL", step, ""))
	}
	for _, u := range urls {
		out = append(out, checkHTTPURL(u, r, step)...)
	}
	return out
}

func checkNpm(argv []string, r *Rules, step int) []Violation {
	var out []Violation
	i := 1
	for i < len(argv) && strings.HasPrefix(argv[i], "-") {
		tok := argv[i]
		name, _, _ := strings.Cut(tok, "=")
		switch {
		case npmGlobalWithValue[tok]:
			i += 2
		case npmGlobalWithValue[name] || npmGlobalNoValue[tok]:
			i++
		default:
			out = append(out, v("npm_option_denied", fmt.Sprintf("npm option %s isn't allowed before the subcommand", tok), step, ""))
			i++
		}
	}
	sub, has := "", i < len(argv)
	if has {
		sub = argv[i]
	}
	out = append(out, checkSubcommand("npm", sub, has, r.Allow["npm"], step)...)
	for _, tok := range argv[1:] {
		if hit := flagDenied(tok, npmDenyAnywhere); hit != "" {
			out = append(out, v("npm_option_denied", fmt.Sprintf("npm %s isn't allowed (%s)", tok, hit), step, ""))
		}
	}
	return out
}

// pathCandidates mirrors matcher.path_candidates.
func pathCandidates(argv []string) (paths, attached []string) {
	endOfOptions := false
	var all []string
	for _, tok := range argv[1:] {
		if !endOfOptions && tok == "--" {
			endOfOptions = true
			continue
		}
		if !endOfOptions && strings.HasPrefix(tok, "-") && tok != "-" {
			if strings.HasPrefix(tok, "--") {
				if strings.Contains(tok, "=") {
					all = append(all, afterEq(tok))
				}
			} else if strings.Contains(tok, "/") {
				attached = append(attached, tok)
			}
			continue
		}
		all = append(all, tok)
	}
	for _, p := range all {
		if p != "" && p != "-" && !IsURL(p) && !IsPlaceholder(p) {
			paths = append(paths, p)
		}
	}
	return paths, attached
}

// CheckPath mirrors matcher.check_path.
func CheckPath(tok, cwd string, r *Rules, res Resolver, step int, what string) []Violation {
	if strings.HasPrefix(tok, "~") {
		return []Violation{v("tilde_path", fmt.Sprintf("%s %s: ~ isn't expanded (no shell); use an absolute path", what, tok), step, "")}
	}
	got, err := res.Resolve(tok, cwd)
	if err != nil {
		return []Violation{v("path_unresolvable", fmt.Sprintf("%s %s: %v", what, tok, err), step, "")}
	}
	for _, p := range []string{got.Lexical, got.Real} {
		if hit := withinAny(p, r.DenyPaths); hit != "" {
			return []Violation{v("denied_path", fmt.Sprintf("%s %s resolves to %s, inside deny_paths %s", what, tok, p, hit), step, "")}
		}
	}
	roots := strings.Join(r.WorkspaceRoots, " ")
	if withinAny(got.Lexical, r.WorkspaceRoots) == "" {
		return []Violation{v("outside_workspace", fmt.Sprintf("%s %s resolves to %s, outside workspace_roots %s", what, tok, got.Lexical, roots), step, "")}
	}
	if withinAny(got.Real, r.WorkspaceRoots) == "" {
		return []Violation{v("symlink_escape", fmt.Sprintf("%s %s: realpath %s → %s leaves workspace_roots %s", what, tok, got.Lexical, got.Real, roots), step, "")}
	}
	return nil
}

func checkCwd(cwd string, r *Rules, res Resolver, step int) []Violation {
	ok := strings.HasPrefix(cwd, "/")
	for _, c := range cwd {
		if !isASCIIPrintable(c) {
			ok = false
		}
	}
	if !ok {
		return []Violation{v("bad_cwd", fmt.Sprintf("cwd %q must be an absolute ASCII path", cwd), step, "")}
	}
	return CheckPath(cwd, "/", r, res, step, "cwd")
}

func checkPaths(argv []string, cwd string, r *Rules, res Resolver, step int) []Violation {
	toks, attached := pathCandidates(argv)
	var out []Violation
	for _, t := range attached {
		out = append(out, v("attached_path_value", t+": put the value in its own argument (e.g. -C /path)", step, ""))
	}
	for _, t := range toks {
		out = append(out, CheckPath(t, cwd, r, res, step, "path")...)
	}
	return out
}

func checkDenyPatterns(raw string, argv []string, r *Rules, step int) []Violation {
	joined := shlexJoin(argv)
	var out []Violation
	for _, dp := range r.DenyPatterns {
		if dp.re.MatchString(raw) || dp.re.MatchString(joined) {
			g := groupName(dp.Group)
			where := "matches commands.deny_patterns"
			if g != "" {
				where = "group " + g + ": matches deny pattern"
			}
			out = append(out, v("deny_pattern", fmt.Sprintf("%s “%s”", where, dp.Source), step, g))
		}
	}
	return out
}

// checkProgram mirrors matcher.check_program.
func checkProgram(kind string, argv []string, r *Rules, step int) []Violation {
	program := argv[0]
	if strings.Contains(program, "/") {
		return []Violation{v("program_path", program+": use the bare program name, not a path", step, "")}
	}
	expected, ok := programKind[program]
	if !ok {
		expected = "shell"
	}
	var out []Violation
	if kind != expected {
		out = append(out, v("kind_mismatch", fmt.Sprintf("%s must be a %s step, not %s", program, expected, kind), step, ""))
	}
	rule, allowed := r.Allow[program]
	if !allowed {
		return append(out, v("program_not_allowed", program+" isn't in commands.allow", step, ""))
	}
	switch program {
	case "git":
		out = append(out, checkGit(argv, r, step)...)
	case "docker":
		out = append(out, checkDocker(argv, r, step)...)
	case "curl":
		out = append(out, CheckCurl(argv, r, step, false)...)
	case "npm":
		out = append(out, checkNpm(argv, r, step)...)
	default:
		if rule.Subcommands != nil {
			i := 1
			for i < len(argv) && strings.HasPrefix(argv[i], "-") {
				i++
			}
			sub, has := "", i < len(argv)
			if has {
				sub = argv[i]
			}
			out = append(out, checkSubcommand(program, sub, has, rule, step)...)
		}
	}
	return append(out, checkFlagsDeny(argv, rule, step)...)
}
