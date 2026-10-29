// Command kernhaven-core runs the Kernhaven Core service.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/app"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
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

	core, err := app.New(db, cfg, log, app.Options{})
	if err != nil {
		log.Error("initialization failed", "error", err.Error())
		return exitRuntime
	}
	setupToken, err := core.Identity.PrepareSetup(ctx)
	if err != nil {
		log.Error("database error", "error", err.Error())
		return exitDatabase
	}
	if setupToken != "" {
		// TH-10: the one-time token is only available to whoever can read the
		// service journal on the host.
		log.Warn("first-run setup required: open the web UI and enter the setup token",
			"setup_token", setupToken, "valid_for", cfg.Auth.SetupTokenTTL.Duration.String())
	}
	if err := core.Runner.Recover(ctx); err != nil {
		log.Error("job recovery failed", "error", err.Error())
		return exitDatabase
	}
	core.Runner.Start()
	defer func() {
		// Runs after the HTTP server has drained and before the DB closes.
		sctx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout.Duration)
		defer cancel()
		core.Runner.Stop(sctx)
	}()
	// Maintenance stops (and is waited for) before the runner and the
	// database, also when startup fails below.
	mctx, stopMaintenance := context.WithCancel(ctx)
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); core.Metrics.Run(mctx) }() // sampling stops with maintenance (M14)
		scheduleMaintenance(mctx, core, log)
		wg.Wait()
	}()
	defer func() {
		stopMaintenance()
		<-maintenanceDone
	}()

	ln, err := net.Listen("tcp", cfg.Server.Listen)
	if err != nil {
		log.Error("listen failed", "address", cfg.Server.Listen, "error", err.Error())
		return exitRuntime
	}
	log.Info("listening", "address", ln.Addr().String(), "instance_id", instanceID)

	if err := httpserver.Run(ctx, ln, core.Handler, httpserver.Options{
		ShutdownTimeout: cfg.Server.ShutdownTimeout.Duration,
		Logger:          log,
	}); err != nil {
		log.Error("server stopped with error", "error", err.Error())
		return exitRuntime
	}
	log.Info("stopped")
	return exitOK
}

// scheduleMaintenance enqueues the maintenance jobs at startup and hourly
// until ctx is cancelled.
func scheduleMaintenance(ctx context.Context, core *app.App, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := core.EnqueueMaintenance(ctx); err != nil && ctx.Err() == nil {
			log.Warn("scheduling maintenance jobs failed", "error", err.Error())
		}
		core.Runner.Wake()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
