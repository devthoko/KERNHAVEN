// Command kernhaven-upgrade installs signed Kernhaven releases with a
// database snapshot and automatic rollback (M18, ADR-0032). It runs as root
// from the command line; the web interface cannot start it.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/release"
	"github.com/devthoko/KERNHAVEN/internal/upgrade"
)

const usage = `usage: kernhaven-upgrade COMMAND [flags]

  verify DIR             check a release directory's signature and packages
  apply DIR              install the release in DIR (snapshot, health check, automatic rollback)
  rollback               return to the version before the last upgrade and its database
  status                 show installed versions and the upgrade history
  cache-package DEB      remember the package just installed (used by install.sh)
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, upgrade.Host{ConfigPath: "/etc/kernhaven/core.toml"}, os.Geteuid())
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, sys upgrade.System, euid int) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd := args[0]
	fs := flag.NewFlagSet("kernhaven-upgrade "+cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	dataDir := fs.String("data-dir", "/var/lib/kernhaven", "the Core's data directory")
	stateDir := fs.String("state-dir", "/var/lib/kernhaven-upgrade", "packages and snapshots kept by the upgrader")
	keysDir := fs.String("keys", "/etc/kernhaven/release-keys", "directory of trusted minisign public keys")
	allowDowngrade := fs.Bool("allow-downgrade", false, "apply: allow installing an older version")
	timeout := fs.Duration("health-timeout", 2*time.Minute, "apply: how long the new version may take to become ready")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	u := &upgrade.Upgrader{Sys: sys, DataDir: *dataDir, StateDir: *stateDir, KeysDir: *keysDir, Arch: runtime.GOARCH, HealthTimeout: *timeout, Out: stdout}
	needRoot := func() bool {
		if euid != 0 {
			fmt.Fprintln(stderr, "kernhaven-upgrade must run as root")
			return false
		}
		return os.MkdirAll(*stateDir, 0o700) == nil
	}
	var err error
	switch {
	case cmd == "verify" && fs.NArg() == 1:
		var keys []release.PublicKey
		if keys, err = release.LoadKeys(*keysDir); err == nil {
			var r release.Release
			if r, err = release.Open(fs.Arg(0), keys); err == nil {
				var p, v string
				if p, v, err = r.Package(runtime.GOARCH); err == nil {
					fmt.Fprintf(stdout, "verified %s (%s): %s\n", v, r.Comment, p)
				}
			}
		}
	case cmd == "apply" && fs.NArg() == 1:
		if !needRoot() {
			return 1
		}
		err = u.Apply(ctx, fs.Arg(0), *allowDowngrade)
	case cmd == "rollback" && fs.NArg() == 0:
		if !needRoot() {
			return 1
		}
		err = u.Rollback(ctx)
	case cmd == "cache-package" && fs.NArg() == 1:
		if !needRoot() {
			return 1
		}
		err = u.CachePackage(fs.Arg(0))
	case cmd == "status" && fs.NArg() == 0:
		var st upgrade.State
		if st, err = u.LoadState(); err == nil {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			err = enc.Encode(st)
		}
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "kernhaven-upgrade %s: %v\n", cmd, err)
		if errors.Is(err, upgrade.ErrRolledBack) {
			return 3
		}
		return 1
	}
	return 0
}
