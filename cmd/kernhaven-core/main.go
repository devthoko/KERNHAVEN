// Command kernhaven-core runs the Kernhaven Core service.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/health"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/platform/logging"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
	"github.com/devthoko/KERNHAVEN/internal/platform/version"
)

// Exit codes (documented in docs/milestones/M1-core-foundation.md).
const (
	exitOK       = 0
	exitRuntime  = 1
	exitConfig   = 2
	exitDatabase = 3
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

	fs := flag.NewFlagSet("kernhaven-core", flag.ContinueOnError)
	fs.SetOutput(stderr)
	configPath := fs.String("config", config.DefaultPath, "path to core.toml")
	if err := fs.Parse(args); err != nil {
		return exitConfig
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %v\n", fs.Args())
		return exitConfig
	}

	cfg, err := config.Load(*configPath)
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
	log.Info("starting kernhaven-core", "version", info.Version, "commit", info.Commit)

	db, err := store.Open(ctx, filepath.Join(cfg.Storage.DataDir, store.FileName))
	if err != nil {
		log.Error("database error", "error", err.Error())
		return exitDatabase
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Error("closing database", "error", err.Error())
		}
	}()
	instanceID, err := store.EnsureInstance(ctx, db)
	if err != nil {
		log.Error("database error", "error", err.Error())
		return exitDatabase
	}

	rt := httpserver.NewRouter()
	health.Register(rt, db, log)
	handler := httpserver.Middleware(log, cfg.Server.MaxBodyBytes, rt)

	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		log.Error("listen failed", "address", cfg.Server.Listen, "error", err.Error())
		return exitRuntime
	}
	log.Info("listening", "address", ln.Addr().String(), "instance_id", instanceID)

	if err := httpserver.Run(ctx, ln, handler, httpserver.Options{
		ShutdownTimeout: cfg.Server.ShutdownTimeout.Duration,
		Logger:          log,
	}); err != nil {
		log.Error("server stopped with error", "error", err.Error())
		return exitRuntime
	}
	log.Info("stopped")
	return exitOK
}
