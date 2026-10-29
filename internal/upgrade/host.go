package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Host is the real System: dpkg, apt-get and systemctl with fixed
// arguments; package paths are verified files in the release or cache.
type Host struct {
	ConfigPath string // /etc/kernhaven/core.toml, for the Core's address
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "DEBIAN_FRONTEND=noninteractive", "LC_ALL=C"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(lastLines(string(out), 5)))
	}
	return string(out), nil
}

func lastLines(s string, n int) string {
	l := strings.Split(strings.TrimSpace(s), "\n")
	if len(l) > n {
		l = l[len(l)-n:]
	}
	return strings.Join(l, "\n")
}

// InstalledVersion asks dpkg.
func (Host) InstalledVersion(ctx context.Context) (string, error) {
	out, err := run(ctx, "dpkg-query", "-W", "-f=${Version}", "kernhaven")
	if err != nil {
		return "", fmt.Errorf("kernhaven is not installed: %w", err)
	}
	return strings.TrimSpace(out), nil
}

// Compare uses dpkg's version ordering.
func (Host) Compare(ctx context.Context, a, b string) (int, error) {
	if !validVersion(a) || !validVersion(b) {
		return 0, errors.New("invalid version")
	}
	for _, c := range []struct {
		op string
		r  int
	}{{"lt", -1}, {"eq", 0}, {"gt", 1}} {
		if _, err := run(ctx, "dpkg", "--compare-versions", a, c.op, b); err == nil {
			return c.r, nil
		}
	}
	return 0, fmt.Errorf("cannot compare %s and %s", a, b)
}

// Install installs a package file with its dependencies.
func (Host) Install(ctx context.Context, deb string, downgrade bool) error {
	abs, err := filepath.Abs(deb)
	if err != nil || !strings.HasSuffix(abs, ".deb") {
		return fmt.Errorf("invalid package path %q", deb)
	}
	args := []string{"install", "-y", "--no-install-recommends"}
	if downgrade {
		args = append(args, "--allow-downgrades")
	}
	_, err = run(ctx, "apt-get", append(args, abs)...)
	return err
}

// Stop stops a unit.
func (Host) Stop(ctx context.Context, unit string) error {
	_, err := run(ctx, "systemctl", "stop", unit)
	return err
}

// Start starts a unit.
func (Host) Start(ctx context.Context, unit string) error {
	_, err := run(ctx, "systemctl", "start", unit)
	return err
}

// Healthy polls the Core's readiness endpoint and checks the version the
// binary reports.
func (h Host) Healthy(ctx context.Context, version string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	listen := "127.0.0.1:8470"
	var cfg struct {
		Server struct {
			Listen string `toml:"listen"`
		} `toml:"server"`
	}
	if _, err := toml.DecodeFile(h.ConfigPath, &cfg); err == nil && cfg.Server.Listen != "" {
		listen = cfg.Server.Listen
	}
	out, err := run(ctx, "/usr/bin/kernhaven-core", "version")
	if err != nil {
		return err
	}
	var v struct {
		Version string `json:"version"`
	}
	if json.Unmarshal([]byte(out), &v) != nil || v.Version != version {
		return fmt.Errorf("the Core reports version %q, want %s", v.Version, version)
	}
	cl := &http.Client{Timeout: 5 * time.Second}
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		resp, err := cl.Get("http://" + listen + "/api/v1/health/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				// Still running a moment later (not a crash loop).
				time.Sleep(3 * time.Second)
				if _, err := run(ctx, "systemctl", "is-active", "--quiet", CoreUnit); err == nil {
					return nil
				}
				last = "the Core stopped after becoming ready"
				continue
			}
			last = resp.Status
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return fmt.Errorf("the Core did not become ready within %s (%s)", timeout, last)
}

// ensure Host implements System.
var _ System = Host{}

// Euid is replaced in tests.
var Euid = os.Geteuid
