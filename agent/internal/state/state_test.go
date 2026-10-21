package state

import (
	"os"
	"testing"
)

func TestExecutedLogRefusesReplay(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	log := d.Executed()
	if err := log.Claim("pln_A", "sha256:1"); err != nil {
		t.Fatal(err)
	}
	if err := log.Claim("pln_B", "sha256:2"); err != nil {
		t.Fatal(err)
	}
	if err := d.Executed().Claim("pln_A", "sha256:1"); err == nil {
		t.Fatal("replay accepted after reopening the log")
	}
	fi, _ := os.Stat(d.File("executed.log"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode())
	}
}

func TestCheckPrivate(t *testing.T) {
	d := Dir{Path: t.TempDir()}
	if err := os.Chmod(d.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckPrivate(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(d.Path, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := d.CheckPrivate(); err == nil {
		t.Fatal("group-readable state dir accepted")
	}
}
