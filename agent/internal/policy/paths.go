package policy

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var urlRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

func IsURL(tok string) bool { return urlRE.MatchString(tok) }

func IsPathLike(tok string) bool {
	if IsURL(tok) {
		return false
	}
	return tok == "." || tok == ".." || strings.HasPrefix(tok, "/") || strings.HasPrefix(tok, "./") ||
		strings.HasPrefix(tok, "../") || strings.HasPrefix(tok, "~") || strings.Contains(tok, "/")
}

// LexicalJoin mirrors warden.policy.paths.lexical_join (posixpath.normpath semantics).
func LexicalJoin(cwd, p string) string {
	joined := p
	if !strings.HasPrefix(p, "/") {
		joined = cwd + "/" + p
	}
	return path.Clean(joined) // Clean also collapses a leading "//" to "/"
}

func IsWithin(p, root string) bool {
	if root == "/" {
		return true
	}
	return p == root || strings.HasPrefix(p, strings.TrimRight(root, "/")+"/")
}

func withinAny(p string, roots []string) string {
	for _, r := range roots {
		if IsWithin(p, r) {
			return r
		}
	}
	return ""
}

// Resolved is a path as written (normalised) and where it really points.
type Resolved struct{ Lexical, Real string }

// ResolveError means the path can't be resolved safely (deny).
type ResolveError struct{ Msg string }

func (e *ResolveError) Error() string { return e.Msg }

// Resolver turns a path argument into a Resolved.
type Resolver interface {
	Resolve(p, cwd string) (Resolved, error)
}

// LexicalResolver normalises without touching the filesystem.
type LexicalResolver struct{}

func (LexicalResolver) Resolve(p, cwd string) (Resolved, error) {
	l := LexicalJoin(cwd, p)
	return Resolved{Lexical: l, Real: l}, nil
}

// RealResolver follows symlinks on the local filesystem, like the kernel: `lnk/../x` goes through the
// link before `..`. Paths that don't exist yet resolve their deepest existing ancestor and append the
// rest; dangling symlinks are followed; loops and a `..` into a missing path are refused.
// Root maps a fake filesystem for tests ("" or "/" = the real root).
type RealResolver struct{ Root string }

const maxLinkDepth = 40

func (r RealResolver) root() string {
	if r.Root == "" {
		return "/"
	}
	return filepath.Clean(r.Root)
}

func (r RealResolver) toHost(p string) string {
	if r.root() == "/" {
		return p
	}
	return r.root() + p
}

func (r RealResolver) fromHost(p string) string {
	root := r.root()
	if root == "/" {
		return p
	}
	if p == root {
		return "/"
	}
	if strings.HasPrefix(p, root+"/") {
		return p[len(root):]
	}
	return "/__outside_root__" + p
}

func lexists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

func (r RealResolver) Resolve(p, cwd string) (Resolved, error) {
	lex := LexicalJoin(cwd, p)
	raw := p
	if !strings.HasPrefix(p, "/") {
		raw = strings.TrimRight(cwd, "/") + "/" + p
	}
	host := r.toHost(raw)
	hasDotDot := false
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			hasDotDot = true
		}
	}
	if hasDotDot && !lexists(host) {
		return Resolved{}, &ResolveError{"can't resolve " + raw + ": it contains '..' and doesn't exist"}
	}
	real, err := r.resolveHost(host, 0)
	if err != nil {
		return Resolved{}, err
	}
	return Resolved{Lexical: lex, Real: r.fromHost(real)}, nil
}

func (r RealResolver) resolveHost(host string, depth int) (string, error) {
	if depth > maxLinkDepth {
		return "", &ResolveError{"can't resolve " + host + ": too many symlinks"}
	}
	var missing []string
	probe := host
	for {
		real, err := filepath.EvalSymlinks(probe)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return real, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return "", &ResolveError{"can't resolve " + host + ": " + err.Error()}
		}
		if fi, lerr := os.Lstat(probe); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
			// A dangling symlink: follow its text so it can't hide where it points.
			target, rerr := os.Readlink(probe)
			if rerr != nil {
				return "", &ResolveError{"can't resolve " + host + ": " + rerr.Error()}
			}
			if !filepath.IsAbs(target) {
				parent, perr := r.resolveHost(filepath.Dir(probe), depth+1)
				if perr != nil {
					return "", perr
				}
				target = filepath.Join(parent, target)
			}
			real, terr := r.resolveHost(filepath.Clean(target), depth+1)
			if terr != nil {
				return "", terr
			}
			for i := len(missing) - 1; i >= 0; i-- {
				real = filepath.Join(real, missing[i])
			}
			return real, nil
		} else if lerr == nil {
			// Exists but EvalSymlinks said not-exist: a component inside is a dangling link or a loop.
			return "", &ResolveError{"can't resolve " + host}
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			return "", &ResolveError{"can't resolve " + host}
		}
		missing = append(missing, filepath.Base(probe))
		probe = parent
	}
}
