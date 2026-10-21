package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// A fake target filesystem under a temp dir, mapped to "/" (mirrors tests/policy/test_paths_adversarial.py).
func fakeFS(t *testing.T) RealResolver {
	t.Helper()
	root := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ln := func(target, at string) {
		if err := os.Symlink(target, filepath.Join(root, at)); err != nil {
			t.Fatal(err)
		}
	}
	mk("srv/dev/myapp/src")
	mk("srv/dev/other")
	mk("srv/prod/app")
	mk("var/cache/npm/_cacache")
	mk("etc")
	mk("home/admin/.ssh")
	if err := os.WriteFile(filepath.Join(root, "etc/shadow"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "srv/dev/myapp/package.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln("../../../var/cache/npm", "srv/dev/myapp/.cache")
	ln("../../prod/app", "srv/dev/myapp/prod-link")
	ln("../../../etc/shadow", "srv/dev/myapp/rel-shadow")
	ln("src", "srv/dev/myapp/inside-link")
	ln("loop-b", "srv/dev/myapp/loop-a")
	ln("loop-a", "srv/dev/myapp/loop-b")
	ln("../../../etc/does-not-exist", "srv/dev/myapp/dangling")
	ln("../../../var/cache/npm", "srv/dev/myapp/sub-escape")
	return RealResolver{Root: root}
}

func codes(t *testing.T, res Resolver, command, kind, cwd string) map[string]bool {
	t.Helper()
	r := loadRules(t, "dev")
	out := map[string]bool{}
	for _, v := range CheckStep(Step{N: 1, Kind: kind, Command: command, Purpose: "t", Cwd: cwd, TimeoutS: 60}, r, res) {
		out[v.Code] = true
	}
	return out
}

func TestSymlinkAttacks(t *testing.T) {
	fs := fakeFS(t)
	const app = "/srv/dev/myapp"
	cases := []struct {
		command, kind, cwd, code string
	}{
		{"npm run /srv/dev/myapp/.cache/_cacache", "shell", app, "symlink_escape"},
		{"npm --prefix prod-link ci", "shell", app, "denied_path"},
		{"npm run rel-shadow", "shell", app, "denied_path"},
		{"npm run rel-shadow", "shell", app, "baseline_protected_path"},
		{"npm run sub-escape", "shell", app, "symlink_escape"},
		{"npm run sub-escape/..", "shell", app, "symlink_escape"},
		{"npm run loop-a", "shell", app, "path_unresolvable"},
		{"npm run dangling", "shell", app, "denied_path"},
		{"npm --prefix nope/../../x ci", "shell", app, "path_unresolvable"},
		{"npm ci", "shell", "/srv/dev/myapp/.cache", "symlink_escape"},
	}
	for _, c := range cases {
		if got := codes(t, fs, c.command, c.kind, c.cwd); !got[c.code] {
			t.Errorf("%q in %s: expected %s, got %v", c.command, c.cwd, c.code, got)
		}
	}
	// The central (lexical) check can't see the cache symlink; the agent can.
	if got := codes(t, LexicalResolver{}, "npm run /srv/dev/myapp/.cache/_cacache", "shell", app); len(got) != 0 {
		t.Fatalf("lexical check should pass, got %v", got)
	}
}

func TestSymlinkInsideAllowed(t *testing.T) {
	fs := fakeFS(t)
	if got := codes(t, fs, "npm --prefix inside-link ci", "shell", "/srv/dev/myapp"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
	if got := codes(t, fs, "git clone https://github.com/you/x /srv/dev/new-repo", "git", "/srv/dev"); len(got) != 0 {
		t.Fatalf("got %v", got)
	}
}

func TestResolverDangling(t *testing.T) {
	fs := fakeFS(t)
	got, err := fs.Resolve("dangling", "/srv/dev/myapp")
	if err != nil {
		t.Fatal(err)
	}
	if got.Real != "/etc/does-not-exist" {
		t.Fatalf("got %s", got.Real)
	}
}
