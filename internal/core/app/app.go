// Package app wires the Core modules into one HTTP handler.
package app

import (
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/containers"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/webui"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/health"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// App is the assembled Core.
type App struct {
	Handler  http.Handler
	Router   *httpserver.Router
	Identity *identity.Service
	Audit    *audit.Log
	Jobs     *jobs.Service
	Agent    *agentclient.Client // nil when no agent is configured
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
}

// New builds the Core from an open database and validated config.
func New(db *sql.DB, cfg config.Config, log *slog.Logger, opts Options) (*App, error) {
	auditLog := audit.New(db, opts.Now)
	ids, err := identity.New(db, auditLog, identity.Config{
		IdleTimeout:     cfg.Auth.SessionIdleTimeout.Duration,
		AbsoluteTimeout: cfg.Auth.SessionAbsoluteTimeout.Duration,
		SetupTokenTTL:   cfg.Auth.SetupTokenTTL.Duration,
		Origin:          cfg.Server.Origin(),
		Hash:            opts.Hash,
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
	containers.New(agent, auditLog, jobSvc, runner.Wake, cfg.Containers.AllowedBindRoots).Register(rt)
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
		Runner:   runner,
		now:      now,
	}
	a.registerMaintenance()
	return a, nil
}
