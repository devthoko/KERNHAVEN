// Package app wires the Core modules into one HTTP handler.
package app

import (
	"context"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/alerts"
	"github.com/devthoko/KERNHAVEN/internal/core/apps"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/backup"
	"github.com/devthoko/KERNHAVEN/internal/core/certs"
	"github.com/devthoko/KERNHAVEN/internal/core/containers"
	khfiles "github.com/devthoko/KERNHAVEN/internal/core/files"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/metrics"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
	khstorage "github.com/devthoko/KERNHAVEN/internal/core/storage"
	"github.com/devthoko/KERNHAVEN/internal/core/webui"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/health"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
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
	Certs    *certs.Service
	Metrics  *metrics.Service
	Alerts   *alerts.Service
	Backup   *backup.Service
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
	// TLS overrides the DNS-01 issuer, DNS providers and trusted roots (tests).
	TLS certs.Config
	// AlertRoots replaces the system roots for notification channels (tests).
	AlertRoots *x509.CertPool
	// BackupRoots replaces the system roots for S3 targets (tests).
	BackupRoots *x509.CertPool
	// ConfigPath is core.toml, copied into platform backups for reference.
	ConfigPath string
	// BackupHealthTimeout bounds waiting for restored stacks (tests).
	BackupHealthTimeout time.Duration
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
	storageSvc := khstorage.New(storageClient, auditLog, ids, jobSvc, runner.Wake)
	storageSvc.Register(rt)
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
	tlsCfg := opts.TLS
	tlsCfg.Propagation = cfg.TLS.DNSPropagation.Duration
	if cfg.TLS.ACMEDirectoryForTests != "" {
		tlsCfg.ACMEDirectory = cfg.TLS.ACMEDirectoryForTests
	}
	if p := cfg.TLS.ACMERootForTests; p != "" {
		pem, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("tls.acme_ca_root_for_tests: %w", err)
		}
		tlsCfg.ACMERoots = x509.NewCertPool()
		if !tlsCfg.ACMERoots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls.acme_ca_root_for_tests: no PEM certificate in %s", p)
		}
	}
	certSvc := certs.New(db, box, netSvc, auditLog, jobSvc, runner.Wake, tlsCfg, log, now)
	certSvc.Register(rt)
	// Host readings come from the separate monitor service (M14, ADR-0027).
	var monitorClient *agentclient.Client
	if cfg.Agent.MonitorSocket != "" {
		key, err := agentclient.LoadOrCreateKey(cfg.Storage.DataDir)
		if err != nil {
			return nil, fmt.Errorf("agent grant key: %w", err)
		}
		monitorClient = agentclient.New(cfg.Agent.MonitorSocket, key)
	}
	metricSvc := metrics.New(db, monitorClient, agent, cfg.Metrics.Interval.Duration, log, now)
	deps := metrics.HealthDeps{DB: db, Started: now(), Docker: agent, Storage: storageClient, Files: filesClient, Proxy: proxyClient, Monitor: monitorClient,
		Caddy: func(ctx context.Context) (bool, bool, bool, string) {
			st := netSvc.State(ctx)
			return st.Configured, st.Reachable, st.InSync, st.Error
		}}
	metricSvc.Register(rt, func(r *http.Request) []metrics.Check { return metrics.Health(r.Context(), deps, now()) })
	// Alerts read the other modules through their APIs (M15).
	src := alerts.Sources{
		Health:       func(ctx context.Context) []metrics.Check { return metrics.Health(ctx, deps, now()) },
		Host:         metricSvc.HostNow,
		CPUAverage:   func(d time.Duration) (float64, int) { return metricSvc.Average("host.cpu", d) },
		Certificates: certSvc.Certificates,
		FailedJobs:   jobSvc.FailedSince,
		Audit:        auditLog.Since,
		VerifyAudit:  auditLog.Verify,
	}
	if storageClient != nil {
		src.Storage = storageSvc.Inventory
	}
	alertSvc := alerts.New(db, box, auditLog, alerts.Sender{Guard: alerts.Guard{AllowLoopback: cfg.Alerts.AllowLoopbackForTests}, Roots: opts.AlertRoots},
		src, cfg.Server.Origin(), log, now)
	alertSvc.Register(rt)
	// Backups stream volumes through the Docker agent (M16, ADR-0030).
	backupSvc := backup.New(db, box, auditLog, jobSvc, runner.Wake, agent, stackSvc, backup.Config{
		LocalRoots: cfg.Backup.LocalRoots, Guard: netguard.Guard{AllowLoopback: cfg.Backup.AllowLoopbackForTests}, Roots: opts.BackupRoots,
		DataDir: cfg.Storage.DataDir, ConfigPath: opts.ConfigPath, HealthTimeout: opts.BackupHealthTimeout,
	}, log, now)
	backupSvc.Register(rt)
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
		Certs:    certSvc,
		Metrics:  metricSvc,
		Alerts:   alertSvc,
		Backup:   backupSvc,
		Runner:   runner,
		now:      now,
	}
	a.registerMaintenance()
	return a, nil
}
