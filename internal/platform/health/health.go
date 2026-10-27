// Package health provides liveness, readiness and version endpoints.
package health

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/platform/version"
)

// Pinger is satisfied by *sql.DB.
type Pinger interface {
	PingContext(ctx context.Context) error
}

// readyTimeout bounds the readiness dependency check.
const readyTimeout = 2 * time.Second

// VersionPermission guards build information to limit fingerprinting.
const VersionPermission = "system.read"

type status struct {
	Status string `json:"status"`
}

// Register adds the health and version routes to rt.
func Register(rt *httpserver.Router, db Pinger, log *slog.Logger) {
	rt.HandleFunc("GET /api/v1/health/live", httpserver.Public(), func(w http.ResponseWriter, r *http.Request) {
		httpserver.WriteJSON(w, http.StatusOK, status{"ok"})
	})
	rt.HandleFunc("GET /api/v1/health/ready", httpserver.Public(), func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()
		if err := db.PingContext(ctx); err != nil {
			log.WarnContext(r.Context(), "readiness check failed",
				"request_id", httpserver.RequestID(r.Context()), "error", err.Error())
			httpserver.WriteJSON(w, http.StatusServiceUnavailable, status{"unavailable"})
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, status{"ok"})
	})
	rt.HandleFunc("GET /api/v1/version", httpserver.RequirePermission(VersionPermission), func(w http.ResponseWriter, r *http.Request) {
		httpserver.WriteJSON(w, http.StatusOK, version.Get())
	})
}
