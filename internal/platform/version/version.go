// Package version exposes build metadata injected at link time.
package version

import (
	"runtime"
	"runtime/debug"
)

// Set via -ldflags "-X github.com/devthoko/KERNHAVEN/internal/platform/version.Version=..."
var (
	Version   = "dev"
	Commit    = ""
	BuildDate = ""
)

// Info describes the running build.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
}

// Get returns the build information, falling back to VCS data embedded by the
// Go toolchain when link-time values are absent.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.BuildDate == "" {
					info.BuildDate = s.Value
				}
			}
		}
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.BuildDate == "" {
		info.BuildDate = "unknown"
	}
	return info
}
