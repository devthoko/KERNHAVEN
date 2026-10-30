package apps

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

func actorFrom(r *http.Request) stacks.Actor {
	m := identity.MetaFrom(r)
	a := stacks.Actor{Name: "system", RequestID: m.RequestID, IP: m.IP}
	if p, ok := identity.FromContext(r.Context()); ok {
		a.ID, a.Name, a.CanApprove = p.User.ID, p.User.Username, p.Has(authz.PolicyExceptions)
	}
	return a
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	var se *stacks.ValidationError
	var re *RejectedError
	var pe *stacks.PolicyError
	var rl *identity.RateLimitError
	switch {
	case errors.As(err, &re):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "catalog_rejected", re.Error())
	case errors.As(err, &pe):
		httpserver.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":      map[string]string{"code": "policy_violation", "message": err.Error(), "request_id": httpserver.RequestID(r.Context())},
			"evaluation": pe.Evaluation,
		})
	case errors.As(err, &ve):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.Message)
	case errors.As(err, &se):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", se.Message)
	case errors.Is(err, ErrExpired), errors.Is(err, ErrNoURL):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
	case errors.Is(err, ErrNotFound), errors.Is(err, stacks.ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrExists), errors.Is(err, stacks.ErrExists), errors.Is(err, ErrUpToDate), errors.Is(err, ErrBuiltin):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, jobs.ErrDuplicate):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", "another operation on this app is queued or running")
	case errors.Is(err, ErrApproval), errors.Is(err, stacks.ErrForbiddenException):
		httpserver.WriteError(w, r, http.StatusForbidden, "approval_required", err.Error())
	case errors.Is(err, stacks.ErrBlocked):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "url_blocked", err.Error())
	case errors.Is(err, identity.ErrStepUpRequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "step_up_required", err.Error())
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", strconv.Itoa(int(rl.RetryAfter.Seconds())+1))
		httpserver.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", rl.Error())
	default:
		httpserver.InternalError(w, r, err)
	}
}

func sourceID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
		return 0, false
	}
	return id, true
}

// Register adds the app store routes. ids confirms destructive actions.
func (s *Service) Register(rt *httpserver.Router, ids *identity.Service) {
	read := httpserver.RequirePermission(string(authz.AppsRead))
	manage := httpserver.RequirePermission(string(authz.AppsManage))
	sources := httpserver.RequirePermission(string(authz.CatalogManage))

	rt.HandleFunc("GET /api/v1/catalog/sources", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Sources(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"sources": list})
	})

	rt.HandleFunc("POST /api/v1/catalog/sources", sources, func(w http.ResponseWriter, r *http.Request) {
		var in SourceInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		// A trust key decides which apps may be installed (AT-F09-04).
		if err := identity.CheckStepUp(r.Context()); err != nil {
			writeErr(w, r, err)
			return
		}
		src, err := s.AddSource(r.Context(), actorFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, src)
	})

	rt.HandleFunc("DELETE /api/v1/catalog/sources/{id}", sources, func(w http.ResponseWriter, r *http.Request) {
		if err := identity.CheckStepUp(r.Context()); err != nil {
			writeErr(w, r, err)
			return
		}
		id, ok := sourceID(w, r)
		if !ok {
			return
		}
		if err := s.DeleteSource(r.Context(), actorFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("PUT /api/v1/catalog/sources/{id}/enabled", sources, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled *bool `json:"enabled"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if in.Enabled == nil {
			writeErr(w, r, &ValidationError{"enabled is required"})
			return
		}
		// Which sources are on decides which apps may be installed (AT-F09-04).
		if err := identity.CheckStepUp(r.Context()); err != nil {
			writeErr(w, r, err)
			return
		}
		id, ok := sourceID(w, r)
		if !ok {
			return
		}
		src, err := s.SetEnabled(r.Context(), actorFrom(r), id, *in.Enabled)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, src)
	})

	rt.HandleFunc("POST /api/v1/catalog/sources/{id}/sync", sources, func(w http.ResponseWriter, r *http.Request) {
		id, ok := sourceID(w, r)
		if !ok {
			return
		}
		src, err := s.Sync(r.Context(), actorFrom(r), id)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, src)
	})

	rt.HandleFunc("POST /api/v1/catalog/sources/{id}/upload", sources, func(w http.ResponseWriter, r *http.Request) {
		id, ok := sourceID(w, r)
		if !ok {
			return
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusRequestEntityTooLarge, "too_large", "the catalog is larger than the server accepts")
			return
		}
		src, err := s.Upload(r.Context(), actorFrom(r), id, data)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, src)
	})

	rt.HandleFunc("GET /api/v1/catalog/apps", read, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var src int64
		if v := q.Get("source"); v != "" {
			src, _ = strconv.ParseInt(v, 10, 64)
		}
		list, cats, err := s.Browse(r.Context(), q.Get("q"), q.Get("category"), src)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"apps": list, "categories": cats})
	})

	rt.HandleFunc("GET /api/v1/catalog/apps/{id}/{app}", read, func(w http.ResponseWriter, r *http.Request) {
		id, ok := sourceID(w, r)
		if !ok {
			return
		}
		d, err := s.AppDetail(r.Context(), id, r.PathValue("app"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, d)
	})

	rt.HandleFunc("GET /api/v1/apps", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.List(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"apps": list})
	})

	rt.HandleFunc("POST /api/v1/apps", manage, func(w http.ResponseWriter, r *http.Request) {
		var in InstallInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		// Publishing a web address is security relevant like approving exceptions (M12).
		if in.ApproveExceptions || in.Route != nil {
			if err := identity.CheckStepUp(r.Context()); err != nil {
				writeErr(w, r, err)
				return
			}
		}
		if in.Route != nil {
			// Publishing needs the network permission, not only apps.manage.
			if p, ok := identity.FromContext(r.Context()); !ok || !p.Has(authz.NetworkManage) {
				httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", "publishing a web address needs the network.manage permission")
				return
			}
			if err := s.routes.CheckAppRoute(*in.Route); err != nil {
				network.WriteErr(w, r, err)
				return
			}
		}
		app, job, err := s.Install(r.Context(), actorFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		res := map[string]any{"app": app, "job_id": job}
		if in.Route != nil {
			// The app is installed either way; a route failure is reported next to it.
			app = s.withWeb(r.Context(), app)
			if app.WebPort == 0 {
				res["route_error"] = "the app publishes no web port, so no route was created"
			} else if route, err := s.routes.CreateAppRoute(r.Context(), network.ActorFrom(r), app.Name, app.WebPort, *in.Route); err != nil {
				res["route_error"] = network.Message(err)
			} else {
				res["route"] = route
			}
		}
		httpserver.WriteJSON(w, http.StatusAccepted, res)
	})

	rt.HandleFunc("GET /api/v1/apps/{name}", read, func(w http.ResponseWriter, r *http.Request) {
		d, err := s.Get(r.Context(), r.PathValue("name"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, d)
	})

	rt.HandleFunc("POST /api/v1/apps/{name}/update", manage, func(w http.ResponseWriter, r *http.Request) {
		var in UpdateInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if in.ApproveExceptions {
			if err := identity.CheckStepUp(r.Context()); err != nil {
				writeErr(w, r, err)
				return
			}
		}
		app, job, err := s.Update(r.Context(), actorFrom(r), r.PathValue("name"), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		res := map[string]any{"app": app, "job_id": job}
		// A new version may publish its web interface on another port.
		if port := s.latestWebPort(r.Context(), app); port > 0 && s.routes != nil && s.routes.Configured() {
			if err := s.routes.MoveAppRoutes(r.Context(), network.ActorFrom(r), app.Name, port); err != nil {
				res["route_error"] = network.Message(err)
			}
		}
		httpserver.WriteJSON(w, http.StatusAccepted, res)
	})

	rt.HandleFunc("POST /api/v1/apps/{name}/remove", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DeleteData bool `json:"delete_data"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		name := r.PathValue("name")
		if _, err := s.app(r.Context(), s.db, name); err != nil {
			writeErr(w, r, err)
			return
		}
		// Deleting data cannot be undone: it needs step-up (AT-F05-03, AT-F09-04).
		if in.DeleteData {
			if err := identity.CheckStepUp(r.Context()); err != nil {
				writeErr(w, r, err)
				return
			}
		}
		job, err := s.Remove(r.Context(), actorFrom(r), name, in.DeleteData)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		res := map[string]any{"job_id": job}
		if s.routes != nil && s.routes.Configured() {
			if err := s.routes.RemoveAppRoutes(r.Context(), network.ActorFrom(r), name); err != nil {
				res["route_error"] = network.Message(err)
			}
		}
		httpserver.WriteJSON(w, http.StatusAccepted, res)
	})
}
