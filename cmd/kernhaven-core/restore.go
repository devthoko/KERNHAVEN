package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/core/backup"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

// runRestore implements `kernhaven-core restore` (M16, AT-F14-05): it
// restores a platform snapshot into the data directory while the Core is
// stopped. Run it as the Core's user.
func runRestore(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kernhaven-core restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path to core.toml")
	targetPath := fs.String("target", "", "JSON file describing the backup target (kind, config, secret)")
	snapshot := fs.String("snapshot", "latest", "snapshot ID or latest")
	passFile := fs.String("passphrase-file", "", "file holding the repository passphrase (default: read a line from standard input)")
	list := fs.Bool("list", false, "list the snapshots and exit")
	replace := fs.Bool("replace", false, "replace an installation that already has users")
	skipVerify := fs.Bool("skip-verify", false, "do not verify every object of the snapshot first")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 || *targetPath == "" {
		fmt.Fprintln(stderr, "usage: kernhaven-core restore -target target.json [-snapshot ID] [-passphrase-file F] [-list] [-replace]")
		return exitConfig
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitConfig
	}
	target, err := backup.ReadTargetFile(*targetPath)
	if err != nil {
		fmt.Fprintf(stderr, "target: %v\n", err)
		return exitConfig
	}
	var pass string
	if *passFile != "" {
		b, err := os.ReadFile(*passFile)
		if err != nil {
			fmt.Fprintf(stderr, "passphrase: %v\n", err)
			return exitConfig
		}
		pass = strings.TrimRight(string(b), "\r\n")
	} else {
		fmt.Fprint(stderr, "repository passphrase: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintln(stderr, "no passphrase given")
			return exitConfig
		}
		pass = strings.TrimRight(line, "\r\n")
	}
	unlock, err := store.LockDir(cfg.Storage.DataDir)
	if err != nil {
		fmt.Fprintf(stderr, "%v; stop kernhaven-core first\n", err)
		return exitRuntime
	}
	defer unlock()
	err = backup.RestorePlatform(ctx, backup.RestoreOptions{
		DataDir: cfg.Storage.DataDir, LocalRoots: cfg.Backup.LocalRoots, Guard: netguard.Guard{AllowLoopback: cfg.Backup.AllowLoopbackForTests},
		Target: target, Passphrase: pass, Snapshot: *snapshot, List: *list, Replace: *replace, SkipVerify: *skipVerify, Out: stdout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "restore failed: %v\n", err)
		return exitRuntime
	}
	return exitOK
}
