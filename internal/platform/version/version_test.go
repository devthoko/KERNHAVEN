package version

import (
	"runtime"
	"testing"
)

func TestGetFillsAllFields(t *testing.T) {
	info := Get()
	if info.Version == "" || info.Commit == "" || info.BuildDate == "" {
		t.Fatalf("empty field in %+v", info)
	}
	if info.GoVersion != runtime.Version() {
		t.Fatalf("GoVersion = %q, want %q", info.GoVersion, runtime.Version())
	}
}

func TestGetPrefersLinkTimeValues(t *testing.T) {
	oldV, oldC, oldB := Version, Commit, BuildDate
	t.Cleanup(func() { Version, Commit, BuildDate = oldV, oldC, oldB })
	Version, Commit, BuildDate = "1.2.3", "abc123", "2026-10-27T00:00:00Z"

	info := Get()
	if info.Version != "1.2.3" || info.Commit != "abc123" || info.BuildDate != "2026-10-27T00:00:00Z" {
		t.Fatalf("link-time values not used: %+v", info)
	}
}
