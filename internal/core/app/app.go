// Package app wires the Core modules into one HTTP handler.
package app

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"path/filepath"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/apps"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/containers"
	khfiles "github.com/devthoko/KERNHAVEN/internal/core/files"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
	khstorage "github.com/devthoko/KERNHAVEN/internal/core/storage"
	"github.com/devthoko/KERNHAVEN/internal/core/webui"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/health"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
)

// App is the assembled Core.
type App struct {
	Handler  http.Handler
	Router   *httpserver.Router
	Identity *identity.Service
	Audit    *audit.Log
	Jobs     *jobs.Service
	Agent    *agentclient.Client // nil when no agent is configured
	Stacks   *stacks.Service
	Apps     *apps.Service
	Network  *network.Service
	Runner   *jobs.Runner

	now func() time.Time
}

// Options allow tests to control time and hashing cost.
type Options struct {
	Now    func() time.Time
	Hash   identity.HashParams
	Runner jobs.RunnerOptions
	// UI overrides the embedded web interface (tests).
	UI fs.FS
	// Fetcher overrides the Compose URL fetcher (tests).
	Fetcher *stacks.Fetcher
}

// New builds the Core from an open database and validated config.
func New(db *sql.DB, cfg config.Config, log *slog.Logger, opts Options) (*App, error) {
	auditLog := audit.New(db, opts.Now)
	box, err := secretbox.Open(filepath.Join(cfg.Storage.DataDir, secretbox.KeyFile))
	if err != nil {
		return nil, fmt.Errorf("secrets key: %w", err)
	}
	ids, err := identity.New(db, auditLog, identity.Config{
		IdleTimeout:     cfg.Auth.SessionIdleTimeout.Duration,
		AbsoluteTimeout: cfg.Auth.SessionAbsoluteTimeout.Duration,
		SetupTokenTTL:   cfg.Auth.SetupTokenTTL.Duration,
		Origin:          cfg.Server.Origin(),
		Hash:            opts.Hash,
		Box:             box,
	}, log, opts.Now)
	if err != nil {
		return nil, err
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	jobSvc := jobs.New(db, now)
	runner := jobs.NewRunner(jobSvc, log, opts.Runner)

	rt := httpserver.NewRouter(ids.Guard)
	health.Register(rt, db, log)
	ids.Register(rt)
	audit.Register(rt, auditLog)
	jobs.RegisterRoutes(rt, jobSvc, auditLog, runner.Wake)
	var agent *agentclient.Client
	if cfg.Agent.Socket != "" {
		key, err := agentclient.LoadOrCreateKey(cfg.Storage.DataDir)
		if err != nil {
			return nil, fmt.Errorf("agent grant key: %w", err)
		}
		agent = agentclient.New(cfg.Agent.Socket, key)
	}
	agentclient.RegisterRoutes(rt, agent)
	// Disk management goes to the separate root storage service (M9).
	var storageClient *agentclient.Client
	if cfg.Agent.StorageSocket != "" {
		key, err := agentclient.LoadOrCreateKey(cfg.Storage.DataDir)
		if err != nil {
			return nil, fmt.Errorf("agent grant key: %w", err)
		}
		storageClient = agentclient.New(cfg.Agent.StorageSocket, key)
	}
	khstorage.New(storageClient, auditLog, ids, jobSvc, runner.Wake).Register(rt)
	// The file manager talks to the separate file service (M10).
	var filesClient *agentclient.Client
	if cfg.Agent.FilesSocket != "" {
		key, err := agentclient.LoadOrCreateKey(cfg.Storage.DataDir)
		if err != nil {
			return nil, fmt.Errorf("agent grant key: %w", err)
		}
		filesClient = agentclient.New(cfg.Agent.FilesSocket, key)
	}
	khfiles.New(filesClient, db, auditLog, jobSvc, runner.Wake, cfg.Files, now).Register(rt)
	containers.New(agent, auditLog, jobSvc, runner.Wake, cfg.Containers.AllowedBindRoots).Register(rt)
	stackSvc := stacks.New(db, box, agent, auditLog, jobSvc, runner.Wake, stacks.Options{BindRoots: cfg.Containers.AllowedBindRoots, Fetcher: opts.Fetcher, Now: now})
	stackSvc.Register(rt)
	// Routes go to the separate proxy service, which alone configures Caddy (M12).
	var proxyClient *agentclient.Client
	if cfg.Agent.ProxySocket != "" {
		key, err := agentclient.LoadOrCreateKey(cfg.Storage.DataDir)
		if err != nil {
			return nil, fmt.Errorf("agent grant key: %w", err)
		}
		proxyClient = agentclient.New(cfg.Agent.ProxySocket, key)
	}
	netSvc := network.New(db, proxyClient, auditLog, ids, cfg.Server.Origin(), cfg.Server.Listen, log, now)
	netSvc.Register(rt)
	appSvc := apps.New(db, auditLog, stackSvc, opts.Fetcher, now)
	appSvc.SetRoutes(netSvc)
	appSvc.Register(rt, ids)
	ui := opts.UI
	if ui == nil {
		ui = webui.Dist()
	}
	rt.SetFallback(webui.Handler(ui))

	a := &App{
		Handler:  httpserver.Middleware(log, cfg.Server.MaxBodyBytes, rt),
		Router:   rt,
		Identity: ids,
		Audit:    auditLog,
		Jobs:     jobSvc,
		Agent:    agent,
		Stacks:   stackSvc,
		Apps:     appSvc,
		Network:  netSvc,
		Runner:   runner,
		now:      now,
	}
	a.registerMaintenance()
	return a, nil
}
