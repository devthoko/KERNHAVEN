// Command kernhaven-agent runs the privileged host agent (M4).
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agent/storage"
	"github.com/devthoko/KERNHAVEN/internal/platform/logging"
	"github.com/devthoko/KERNHAVEN/internal/platform/version"
)

const (
	exitOK      = 0
	exitRuntime = 1
	exitConfig  = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "version" {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(version.Get())
		return exitOK
	}
	fs := flag.NewFlagSet("kernhaven-agent", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", agent.DefaultConfigPath, "path to agent.toml")
	if err := fs.Parse(args); err != nil || fs.NArg() > 0 {
		return exitConfig
	}
	cfg, err := agent.LoadConfig(*configPath)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitConfig
	}
	log, err := logging.New(stderr, cfg.Log.Level)
	if err != nil {
		fmt.Fprintf(stderr, "configuration error: %v\n", err)
		return exitConfig
	}
	info := version.Get()
	log.Info("starting kernhaven-agent", "version", info.Version, "commit", info.Commit, "role", cfg.Role, "socket", cfg.Socket, "docker_socket", cfg.DockerSocket)

	// The storage role (M9) runs as root and offers only disk operations;
	// the docker role never gets them.
	var srv *agent.Server
	if cfg.Role == "storage" {
		srv = agent.NewServer(log, cfg.PublicKey(), cfg.AllowedUIDs, nil, agent.Options{
			Storage: storage.New(storage.NewExecRunner(), storage.Config{MountRoot: cfg.MountRoot, IncludeLoop: cfg.StorageIncludeLoop})})
	} else {
		srv = agent.NewServer(log, cfg.PublicKey(), cfg.AllowedUIDs, docker.New(cfg.DockerSocket, 30*time.Second),
			agent.Options{AllowedBindRoots: cfg.AllowedBindRoots, HelperImage: cfg.HelperImage})
	}
	ln, err := agent.Listen(cfg.Socket)
	if err != nil {
		log.Error("listen failed", "error", err.Error())
		return exitRuntime
	}
	defer os.Remove(cfg.Socket)
	if err := srv.Serve(ctx, ln); err != nil {
		log.Error("agent stopped with error", "error", err.Error())
		return exitRuntime
	}
	log.Info("stopped")
	return exitOK
}
