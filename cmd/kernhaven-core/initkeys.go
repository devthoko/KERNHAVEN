package main

import (
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
)

// runInitKeys implements `kernhaven-core init-keys` (M18): the package's
// installation script runs it as the Core's user to create the grant key
// before the agents start; the script then copies the public key to a
// root-owned path the agents read.
func runInitKeys(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("kernhaven-core init-keys", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path to core.toml")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitConfig
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitConfig
	}
	if _, err := agentclient.LoadOrCreateKey(cfg.Storage.DataDir); err != nil {
		fmt.Fprintf(stderr, "grant key: %v\n", err)
		return exitRuntime
	}
	fmt.Fprintln(stdout, filepath.Join(cfg.Storage.DataDir, agentclient.PublicKeyFile))
	return exitOK
}
