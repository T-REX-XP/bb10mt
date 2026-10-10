package buildversion

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReservationsIncreaseAndCannotBeReused(t *testing.T) {
	dir := t.TempDir()
	seed, state := filepath.Join(dir, "VERSION"), filepath.Join(dir, "state.json")
	os.WriteFile(seed, []byte("v0.7.0-go.3\n"), 0644)
	for _, version := range []string{"v0.7.0-go.4", "v0.7.0-go.5"} {
		r, err := Reserve(seed, state, "", "")
		if err != nil || r.Version != version {
			t.Fatalf("%+v %v", r, err)
		}
	}
	if _, err := Reserve(seed, state, "v0.7.0-go.5", ""); err == nil {
		t.Fatal("reused version")
	}
	r, err := Reserve(seed, state, "v0.8.0-go.1", "123.2.release")
	if err != nil || r.Version != "v0.8.0-go.1+build.123.2.release" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := Reserve(seed, state, "v0.7.0-go.9", ""); err == nil {
		t.Fatal("downgrade")
	}
}
func TestLockAndCorruptStateFailClosed(t *testing.T) {
	dir := t.TempDir()
	seed, state := filepath.Join(dir, "VERSION"), filepath.Join(dir, "state.json")
	os.WriteFile(seed, []byte("v0.7.0-go.3"), 0644)
	os.Mkdir(state+".lock", 0700)
	if _, err := Reserve(seed, state, "", ""); err == nil {
		t.Fatal("concurrent allocation")
	}
	os.Remove(state + ".lock")
	os.WriteFile(state, []byte("invalid JSON"), 0644)
	if _, err := Reserve(seed, state, "", ""); err == nil {
		t.Fatal("reset corrupt state")
	}
}
