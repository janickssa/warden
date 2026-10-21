package policy

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

func fixtureDir(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "policy-fixtures")
}

func loadRules(t *testing.T, target string) *Rules {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(fixtureDir(t), "compiled", target+".json"))
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseRules(data)
	if err != nil {
		t.Fatalf("%s: %v", target, err)
	}
	return r
}

type fixtureCase struct {
	ID      string `yaml:"id"`
	Mode    string `yaml:"mode"`
	Target  string `yaml:"target"`
	Kind    string `yaml:"kind"`
	Cwd     string `yaml:"cwd"`
	Command string `yaml:"command"`
	Expect  string `yaml:"expect"`
	Code    string `yaml:"code"`
}

// TestSharedCorpus runs policy-fixtures/cases/*.yaml: the Go agent must agree with the Python engine.
func TestSharedCorpus(t *testing.T) {
	files, _ := filepath.Glob(filepath.Join(fixtureDir(t), "cases", "*.yaml"))
	sort.Strings(files)
	rules := map[string]*Rules{}
	total := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var cases []fixtureCase
		if err := yaml.Unmarshal(data, &cases); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, c := range cases {
			total++
			c := c
			name := filepath.Base(f) + ":" + c.ID
			t.Run(name, func(t *testing.T) {
				target := c.Target
				if target == "" {
					target = "dev"
				}
				if rules[target] == nil {
					rules[target] = loadRules(t, target)
				}
				r := rules[target]
				var got []Violation
				if c.Mode == "read_only" {
					_, got = CheckReadOnly(c.Command, r, LexicalResolver{})
				} else {
					kind, cwd := c.Kind, c.Cwd
					if kind == "" {
						kind = "shell"
					}
					if cwd == "" {
						cwd = "/srv/dev/myapp"
						if target == "sec-auth" {
							cwd = "/srv/app"
						}
					}
					got = CheckStep(Step{N: 1, Kind: kind, Command: c.Command, Purpose: "test", Cwd: cwd, TimeoutS: 60}, r, LexicalResolver{})
				}
				if c.Expect == "allow" {
					if len(got) != 0 {
						t.Fatalf("expected allow, got %+v", got)
					}
					return
				}
				if len(got) == 0 {
					t.Fatal("expected deny, got allow")
				}
				if c.Code != "" {
					for _, v := range got {
						if v.Code == c.Code {
							return
						}
					}
					t.Fatalf("expected %s, got %+v", c.Code, got)
				}
			})
		}
	}
	if total < 150 {
		t.Fatalf("corpus too small: %d", total)
	}
}

func TestParseRulesRefusesUnknownFields(t *testing.T) {
	data, _ := os.ReadFile(filepath.Join(fixtureDir(t), "compiled", "dev.json"))
	bad := append([]byte(`{"surprise": 1,`), data[1:]...)
	if _, err := ParseRules(bad); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := ParseRules([]byte(`{"schema": 2}`)); err == nil {
		t.Fatal("wrong schema accepted")
	}
}

func TestShlexMatchesPython(t *testing.T) {
	cases := map[string][]string{
		`git commit -m "Tilføj login"`: {"git", "commit", "-m", "Tilføj login"},
		`a'b c'd`:                      {"ab cd"},
		`x ''`:                         {"x", ""},
		`a\ b`:                         {"a b"},
		`"a\"b"`:                       {`a"b`},
		`"a\xb"`:                       {`a\xb`},
		`'a\b'`:                        {`a\b`},
		`npm   run    build`:           {"npm", "run", "build"},
	}
	for in, want := range cases {
		got, err := shlexSplit(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
		for i := range got {
			if got[i] != want[i] {
				t.Fatalf("%q: got %q want %q", in, got, want)
			}
		}
	}
	for _, bad := range []string{`'open`, `"open`, `trailing\`} {
		if _, err := shlexSplit(bad); err == nil {
			t.Fatalf("%q: expected error", bad)
		}
	}
}

func TestShlexJoinMatchesPython(t *testing.T) {
	got := shlexJoin([]string{"git", "log", "--grep", "a b", "", "it's"})
	want := `git log --grep 'a b' '' 'it'"'"'s'`
	if got != want {
		t.Fatalf("got %s", got)
	}
}
