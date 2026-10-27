package stacks

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

func actorFrom(r *http.Request) Actor {
	m := identity.MetaFrom(r)
	a := Actor{Name: "system", RequestID: m.RequestID, IP: m.IP}
	if p, ok := identity.FromContext(r.Context()); ok {
		a.ID, a.Name, a.CanApprove = p.User.ID, p.User.Username, p.Has(authz.PolicyExceptions)
	}
	return a
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	var pe *PolicyError
	switch {
	case errors.As(err, &pe):
		code := "policy_violation"
		if !pe.Evaluation.Valid {
			code = "validation_failed"
		}
		httpserver.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":      map[string]string{"code": code, "message": err.Error(), "request_id": httpserver.RequestID(r.Context())},
			"evaluation": pe.Evaluation,
		})
	case errors.As(err, &ve):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.Message)
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrExists), errors.Is(err, ErrDeployed):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, jobs.ErrDuplicate):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", "a deployment or teardown of this stack is already queued or running")
	case errors.Is(err, ErrForbiddenException):
		httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, ErrBlocked):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "url_blocked", err.Error())
	default:
		httpserver.InternalError(w, r, err)
	}
}

// Register adds the stack routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.ContainersRead))
	manage := httpserver.RequirePermission(string(authz.ContainersManage))

	rt.HandleFunc("GET /api/v1/stacks", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.st.list(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"stacks": list})
	})

	rt.HandleFunc("POST /api/v1/stacks", manage, func(w http.ResponseWriter, r *http.Request) {
		var in RevisionInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		st, _, err := s.Create(r.Context(), actorFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, st)
	})

	rt.HandleFunc("POST /api/v1/stacks/validate", manage, func(w http.ResponseWriter, r *http.Request) {
		var in RevisionInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		var stackID int64
		if st, err := s.st.byName(r.Context(), s.st.db, in.Name); err == nil {
			stackID = st.ID
		}
		vars, err := s.mergedVars(r.Context(), stackID, in.Variables)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		ev, _ := s.evaluate(in.Name, in.Compose, vars, in.Exceptions)
		httpserver.WriteJSON(w, http.StatusOK, ev)
	})

	rt.HandleFunc("POST /api/v1/stacks/import-url", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			URL string `json:"url"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		a := actorFrom(r)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		content, err := s.fetcher.Fetch(ctx, in.URL)
		result := audit.Success
		if err != nil {
			result = audit.Failure
		}
		_ = s.audit.Record(context.WithoutCancel(r.Context()), a.event("stack.import_url", "url", result, "url", in.URL))
		if err != nil {
			if errors.Is(err, ErrBlocked) {
				writeErr(w, r, err)
				return
			}
			httpserver.WriteError(w, r, http.StatusBadGateway, "download_failed", err.Error())
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"compose": content})
	})

	rt.HandleFunc("GET /api/v1/stacks/{name}", read, func(w http.ResponseWriter, r *http.Request) {
		st, err := s.st.byName(r.Context(), s.st.db, r.PathValue("name"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		latest, err := s.st.revision(r.Context(), s.st.db, st.ID, st.LatestRevision)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		vars, err := s.PublicVariables(r.Context(), st.ID)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		a := actorFrom(r)
		resp := map[string]any{"stack": st, "latest": latest, "variables": vars}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if rt, err := s.Runtime(ctx, st.Name, a.Name, a.RequestID); err == nil {
			resp["services"] = rt
		} else if errors.Is(err, agentclient.ErrUnavailable) {
			resp["services_error"] = "the host agent is not running or not reachable"
		} else {
			resp["services_error"] = err.Error()
		}
		httpserver.WriteJSON(w, http.StatusOK, resp)
	})

	rt.HandleFunc("DELETE /api/v1/stacks/{name}", manage, func(w http.ResponseWriter, r *http.Request) {
		if err := s.Delete(r.Context(), actorFrom(r), r.PathValue("name")); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("GET /api/v1/stacks/{name}/revisions", read, func(w http.ResponseWriter, r *http.Request) {
		st, err := s.st.byName(r.Context(), s.st.db, r.PathValue("name"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		revs, err := s.st.revisions(r.Context(), st.ID)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"revisions": revs})
	})

	rt.HandleFunc("POST /api/v1/stacks/{name}/revisions", manage, func(w http.ResponseWriter, r *http.Request) {
		var in RevisionInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		rev, _, err := s.AddRevision(r.Context(), actorFrom(r), r.PathValue("name"), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, rev)
	})

	rt.HandleFunc("GET /api/v1/stacks/{name}/revisions/{number}", read, func(w http.ResponseWriter, r *http.Request) {
		st, err := s.st.byName(r.Context(), s.st.db, r.PathValue("name"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		n, err := strconv.Atoi(r.PathValue("number"))
		if err != nil {
			writeErr(w, r, ErrNotFound)
			return
		}
		rev, err := s.st.revision(r.Context(), s.st.db, st.ID, n)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, rev)
	})

	rt.HandleFunc("PUT /api/v1/stacks/{name}/variables", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Variables []VariableInput `json:"variables"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if err := s.SetVariables(r.Context(), actorFrom(r), r.PathValue("name"), in.Variables); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("POST /api/v1/stacks/{name}/deploy", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Revision int `json:"revision"`
		}
		if r.ContentLength != 0 && httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if s.agent == nil {
			httpserver.WriteError(w, r, http.StatusServiceUnavailable, "agent_unavailable", "no host agent is configured")
			return
		}
		id, err := s.Deploy(r.Context(), actorFrom(r), r.PathValue("name"), in.Revision)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]int64{"job_id": id})
	})

	rt.HandleFunc("POST /api/v1/stacks/{name}/down", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			RemoveVolumes bool `json:"remove_volumes"`
		}
		if r.ContentLength != 0 && httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if s.agent == nil {
			httpserver.WriteError(w, r, http.StatusServiceUnavailable, "agent_unavailable", "no host agent is configured")
			return
		}
		id, err := s.Down(r.Context(), actorFrom(r), r.PathValue("name"), in.RemoveVolumes)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]int64{"job_id": id})
	})
}
