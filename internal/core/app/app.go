// Package app wires the Core modules into one HTTP handler.
package app

import (
	"database/sql"
	"log/slog"
	"net/http"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
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
}

// Options allow tests to control time and hashing cost.
type Options struct {
	Now  func() time.Time
	Hash identity.HashParams
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

	rt := httpserver.NewRouter(ids.Guard)
	health.Register(rt, db, log)
	ids.Register(rt)
	audit.Register(rt, auditLog)

	return &App{
		Handler:  httpserver.Middleware(log, cfg.Server.MaxBodyBytes, rt),
		Router:   rt,
		Identity: ids,
		Audit:    auditLog,
	}, nil
}
