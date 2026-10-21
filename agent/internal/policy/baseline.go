package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// Baseline rules are compiled into the agent and can't be disabled by any policy, group or setting
// (README 7A, section 16 rule 13). Mirrors backend/src/warden/policy/baseline.py.

var protectedTrees = []string{"/etc", "/usr", "/boot", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
	"/proc", "/sys", "/dev", "/root", "/run", "/var/run", "/var/lib/docker", "/var/lib/warden-agent",
	"/usr/local/bin/warden-agent"}

var forbiddenPrograms = set(
	"sudo", "su", "doas", "pkexec", "runuser",
	"sh", "bash", "dash", "zsh", "ksh", "mksh", "fish", "csh", "tcsh", "busybox",
	"env", "xargs", "nohup", "setsid", "chroot", "nsenter", "unshare", "eval", "exec",
	"timeout", "watch", "script", "expect", "find",
	"ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet",
	"dd", "mount", "umount", "losetup", "mkfs", "fdisk", "parted", "wipefs",
	"systemctl", "service", "crontab", "at", "batch",
	"kill", "pkill", "killall",
	"iptables", "ip6tables", "nft", "ufw",
	"reboot", "shutdown", "poweroff", "halt", "init",
	"chown", "chgrp", "setcap", "useradd", "usermod", "passwd", "visudo",
	"warden-agent",
)

var interpreters = set("python", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun", "lua", "Rscript")
var inlineCodeFlags = set("-c", "-e", "-E", "-r", "-p", "--eval", "--print")

var dockerDangerous = set("--privileged", "--cap-add", "--device", "--security-opt", "--pid", "--ipc", "--uts",
	"--userns", "--cgroupns", "--device-cgroup-rule", "--sysctl")
var dockerNetwork = set("--network", "--net")
var dockerMount = set("-v", "--volume", "--mount")

var setuidMode = regexp.MustCompile(`^(0?[2-7][0-7]{3}|.*[ugoa]*[+=][rwxXt]*s.*)$`)
var dockerSock = regexp.MustCompile(`docker\.sock|docker-proxy\.sock`)

func bv(code, msg string, step int) Violation {
	return Violation{Code: code, Message: "baseline: " + msg, Step: step}
}

type flagItem struct {
	name  string
	value string
	has   bool
}

func flagItems(argv []string) []flagItem {
	var items []flagItem
	for i := 1; i < len(argv); i++ {
		tok := argv[i]
		if tok == "--" {
			break
		}
		next, hasNext := "", i+1 < len(argv)
		if hasNext {
			next = argv[i+1]
		}
		if strings.HasPrefix(tok, "--") {
			if name, value, ok := strings.Cut(tok, "="); ok {
				items = append(items, flagItem{name, value, true})
			} else {
				items = append(items, flagItem{tok, next, hasNext})
			}
		} else if strings.HasPrefix(tok, "-") && len(tok) > 1 {
			if len(tok) > 2 {
				items = append(items, flagItem{tok[:2], tok[2:], true})
			} else {
				items = append(items, flagItem{tok[:2], next, hasNext})
			}
		}
	}
	return items
}

func mountSource(flag, value string) (string, bool) {
	if flag == "--mount" {
		for _, part := range strings.Split(value, ",") {
			key, val, _ := strings.Cut(part, "=")
			if key == "source" || key == "src" {
				return val, true
			}
		}
		return "", false
	}
	src, _, _ := strings.Cut(value, ":")
	return src, true
}

// Baseline returns baseline violations for argv run in cwd.
func Baseline(argv []string, cwd string, res Resolver, step int) []Violation {
	var out []Violation
	program := argv[0]

	if forbiddenPrograms[program] || strings.HasPrefix(program, "mkfs.") {
		out = append(out, bv("baseline_program", program+" is never allowed", step))
	}
	if interpreters[program] {
		for _, tok := range argv[1:] {
			name, _, _ := strings.Cut(tok, "=")
			hit := inlineCodeFlags[name]
			if !hit && strings.HasPrefix(tok, "-") && !strings.HasPrefix(tok, "--") {
				for _, c := range tok[1:] {
					if inlineCodeFlags["-"+string(c)] {
						hit = true
					}
				}
			}
			if hit {
				out = append(out, bv("baseline_inline_code", fmt.Sprintf("%s %s runs inline code", program, tok), step))
				break
			}
		}
	}

	if program == "rm" {
		for _, t := range argv {
			if t == "--no-preserve-root" {
				out = append(out, bv("baseline_rm_root", "rm --no-preserve-root is never allowed", step))
				break
			}
		}
		for _, tok := range argv[1:] {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			got, err := res.Resolve(tok, cwd)
			if err != nil {
				continue
			}
			for _, p := range []string{got.Lexical, got.Real} {
				if strings.Count(p, "/") <= 1 || tok == "/*" || tok == "/." {
					out = append(out, bv("baseline_rm_root", fmt.Sprintf("rm on %s (filesystem root or a top-level directory)", p), step))
					break
				}
			}
		}
	}

	if program == "chmod" {
		for _, tok := range argv[1:] {
			if !strings.HasPrefix(tok, "-") && setuidMode.MatchString(tok) && !strings.HasPrefix(tok, "/") {
				out = append(out, bv("baseline_setuid", fmt.Sprintf("chmod %s sets setuid/setgid bits", tok), step))
			}
		}
	}

	if program == "docker" || program == "podman" {
		for _, it := range flagItems(argv) {
			if dockerDangerous[it.name] {
				out = append(out, bv("baseline_docker_flag", fmt.Sprintf("docker %s is never allowed", it.name), step))
			}
			if dockerNetwork[it.name] && it.has && strings.HasPrefix(it.value, "host") {
				out = append(out, bv("baseline_docker_flag", fmt.Sprintf("docker %s=%s is never allowed", it.name, it.value), step))
			}
			if dockerMount[it.name] && it.has {
				if src, ok := mountSource(it.name, it.value); ok && strings.HasPrefix(src, "/") {
					n := "/" + strings.Trim(src, "/")
					if n == "/" {
						out = append(out, bv("baseline_docker_mount", "mounting / is never allowed", step))
					} else {
						for _, t := range protectedTrees {
							if IsWithin(n, t) {
								out = append(out, bv("baseline_docker_mount", fmt.Sprintf("mounting %s is never allowed", n), step))
								break
							}
						}
					}
				}
				if dockerSock.MatchString(it.value) {
					out = append(out, bv("baseline_docker_mount", "mounting the Docker socket is never allowed", step))
				}
			}
		}
	}

	candidates := []string{cwd}
	endOfOptions := false
	for _, tok := range argv[1:] {
		if !endOfOptions && tok == "--" {
			endOfOptions = true
			continue
		}
		if !endOfOptions && strings.HasPrefix(tok, "-") {
			if strings.HasPrefix(tok, "--") && strings.Contains(tok, "=") {
				candidates = append(candidates, afterEq(tok))
			}
			continue
		}
		candidates = append(candidates, tok)
	}
	for _, c := range candidates {
		if c == "" || IsURL(c) || IsPlaceholder(c) {
			continue
		}
		got, err := res.Resolve(c, cwd)
		if err != nil {
			continue
		}
		for _, t := range protectedTrees {
			if IsWithin(got.Lexical, t) || IsWithin(got.Real, t) {
				where := got.Lexical
				if IsWithin(got.Real, t) {
					where = got.Real
				}
				out = append(out, bv("baseline_protected_path", fmt.Sprintf("%s resolves to %s, inside %s", c, where, t), step))
				break
			}
		}
	}
	return out
}
