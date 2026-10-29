package metrics

import (
	"errors"
	"net/http"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrUnavailable):
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "metrics_unavailable", "this source of metrics is not configured")
	case errors.Is(err, ErrNoData):
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "metrics_pending", "no reading yet; try again in a few seconds")
	case errors.Is(err, ErrRange):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
	default:
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "metrics_unavailable", unavailable(err))
	}
}

// Register adds the metrics and health routes; health is set by the app.
func (s *Service) Register(rt *httpserver.Router, health func(r *http.Request) []Check) {
	sys := httpserver.RequirePermission(string(authz.SystemRead))
	rt.HandleFunc("GET /api/v1/metrics/host", sys, func(w http.ResponseWriter, r *http.Request) {
		h, err := s.HostNow()
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, h)
	})
	rt.HandleFunc("GET /api/v1/metrics/containers", httpserver.RequirePermission(string(authz.ContainersRead)), func(w http.ResponseWriter, r *http.Request) {
		cs, err := s.ContainersNow()
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"containers": cs})
	})
	rt.HandleFunc("GET /api/v1/metrics/series", sys, func(w http.ResponseWriter, r *http.Request) {
		all, err := s.Series(r.Context())
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		p, _ := identity.FromContext(r.Context())
		out := []SeriesInfo{}
		for _, x := range all {
			if !IsContainerSeries(x.Key) || p.Has(authz.ContainersRead) {
				out = append(out, x)
			}
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"series": out})
	})
	rt.HandleFunc("GET /api/v1/metrics/history", sys, func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("series")
		// Container series need the container permission (AT-F13-02).
		if p, _ := identity.FromContext(r.Context()); IsContainerSeries(key) && !p.Has(authz.ContainersRead) {
			httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", "you do not have permission for this action")
			return
		}
		h, err := s.History(r.Context(), key, r.URL.Query().Get("range"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, h)
	})
	rt.HandleFunc("GET /api/v1/health/services", sys, func(w http.ResponseWriter, r *http.Request) {
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"services": health(r)})
	})
}
