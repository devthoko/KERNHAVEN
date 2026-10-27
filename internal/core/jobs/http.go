package jobs

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// RegisterRoutes adds the job API. wake is called after a cancel so an idle
// worker processes it promptly (may be nil).
func RegisterRoutes(rt *httpserver.Router, s *Service, auditLog *audit.Log, wake func()) {
	read := httpserver.RequirePermission(string(authz.JobsRead))
	manage := httpserver.RequirePermission(string(authz.JobsManage))

	rt.HandleFunc("GET /api/v1/jobs", read, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f := Filter{State: State(q.Get("state")), Kind: q.Get("kind")}
		switch f.State {
		case "", Queued, Running, Compensating, Succeeded, Failed, Cancelled:
		default:
			httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", "unknown state")
			return
		}
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 200 {
				httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", "limit must be 1..200")
				return
			}
			f.Limit = n
		}
		list, err := s.List(r.Context(), f)
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"jobs": list})
	})

	rt.HandleFunc("GET /api/v1/jobs/{id}", read, func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
			return
		}
		j, err := s.Get(r.Context(), id)
		if errors.Is(err, ErrNotFound) {
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
			return
		}
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, j)
	})

	rt.HandleFunc("POST /api/v1/jobs/{id}/cancel", manage, func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
			return
		}
		p, _ := identity.FromContext(r.Context())
		m := identity.MetaFrom(r)
		ev := audit.Event{Action: "job.cancel", Target: "job:" + strconv.FormatInt(id, 10), RequestID: m.RequestID, IP: m.IP}
		if p != nil {
			ev.ActorID, ev.Actor = p.User.ID, p.User.Username
		}
		err = s.RequestCancel(r.Context(), id)
		switch {
		case errors.Is(err, ErrNotFound):
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
			return
		case errors.Is(err, ErrFinished):
			httpserver.WriteError(w, r, http.StatusConflict, "job_finished", err.Error())
			return
		case err != nil:
			httpserver.InternalError(w, r, err)
			return
		}
		ev.Result = audit.Success
		if err := auditLog.Record(r.Context(), ev); err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		if wake != nil {
			wake()
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
