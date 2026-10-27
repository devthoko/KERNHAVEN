package apps

import (
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
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
	case errors.Is(err, ErrExists), errors.Is(err, stacks.ErrExists), errors.Is(err, ErrUpToDate):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, jobs.ErrDuplicate):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", "another operation on this app is queued or running")
	case errors.Is(err, ErrApproval), errors.Is(err, stacks.ErrForbiddenException):
		httpserver.WriteError(w, r, http.StatusForbidden, "approval_required", err.Error())
	case errors.Is(err, stacks.ErrBlocked):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "url_blocked", err.Error())
	case errors.Is(err, identity.ErrInvalidCredentials):
		httpserver.WriteError(w, r, http.StatusForbidden, "reauthentication_failed", "the password is not correct")
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
		src, err := s.AddSource(r.Context(), actorFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, src)
	})

	rt.HandleFunc("DELETE /api/v1/catalog/sources/{id}", sources, func(w http.ResponseWriter, r *http.Request) {
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
		app, job, err := s.Install(r.Context(), actorFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"app": app, "job_id": job})
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
		app, job, err := s.Update(r.Context(), actorFrom(r), r.PathValue("name"), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"app": app, "job_id": job})
	})

	rt.HandleFunc("POST /api/v1/apps/{name}/remove", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			DeleteData bool   `json:"delete_data"`
			Password   string `json:"password"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		name := r.PathValue("name")
		if _, err := s.app(r.Context(), s.db, name); err != nil {
			writeErr(w, r, err)
			return
		}
		// Deleting data cannot be undone: confirm with the password (AT-F05-03).
		if in.DeleteData {
			p, _ := identity.FromContext(r.Context())
			if err := ids.Reauthenticate(r.Context(), p, identity.MetaFrom(r), in.Password, "app.remove", "app:"+name); err != nil {
				writeErr(w, r, err)
				return
			}
		}
		job, err := s.Remove(r.Context(), actorFrom(r), name, in.DeleteData)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": job})
	})
}
