package network

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
)

// ActorFrom returns the actor of an authenticated request.
func ActorFrom(r *http.Request) Actor {
	m := identity.MetaFrom(r)
	a := Actor{Name: "system", RequestID: m.RequestID, IP: m.IP}
	if p, ok := identity.FromContext(r.Context()); ok {
		a.ID, a.Name = p.User.ID, p.User.Username
	}
	return a
}

// WriteErr maps service errors to HTTP responses.
func WriteErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	var ae *agentclient.Error
	switch {
	case errors.As(err, &ve):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.Msg)
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "route not found")
	case errors.Is(err, ErrExists):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, ErrGateDenied):
		httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, ErrGateRedirect):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
	case errors.Is(err, identity.ErrStepUpRequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "step_up_required", err.Error())
	case errors.Is(err, ErrUnavailable), errors.Is(err, agentclient.ErrUnavailable):
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "proxy_unavailable", "the reverse proxy service is not configured or not reachable")
	case errors.As(err, &ae):
		switch ae.Code {
		case agentproto.CodeProxyRejected:
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "proxy_rejected", ae.Message+" — the previous configuration stays active")
		case agentproto.CodeProxyUnavailable:
			httpserver.WriteError(w, r, http.StatusServiceUnavailable, "proxy_unavailable", ae.Message)
		case agentproto.CodeInvalidParams:
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ae.Message)
		default:
			httpserver.InternalError(w, r, err)
		}
	default:
		httpserver.InternalError(w, r, err)
	}
}

// Message describes a route error for users when it is reported next to
// another result (app install, update, removal).
func Message(err error) string {
	var ve *ValidationError
	var ae *agentclient.Error
	switch {
	case errors.As(err, &ve):
		return ve.Msg
	case errors.Is(err, ErrExists), errors.Is(err, identity.ErrStepUpRequired):
		return err.Error()
	case errors.Is(err, ErrUnavailable), errors.Is(err, agentclient.ErrUnavailable):
		return "the reverse proxy service is not configured or not reachable"
	case errors.As(err, &ae) && ae.Code != agentproto.CodeInternal:
		return ae.Message
	default:
		return "the route could not be changed"
	}
}

func routeID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "route not found")
		return 0, false
	}
	return id, true
}

// stepUp: publishing a service or changing its protection is security relevant (AT-F09-04).
func stepUp(w http.ResponseWriter, r *http.Request) bool {
	if err := identity.CheckStepUp(r.Context()); err != nil {
		WriteErr(w, r, err)
		return false
	}
	return true
}

// Register adds the network routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.NetworkRead))
	manage := httpserver.RequirePermission(string(authz.NetworkManage))

	rt.HandleFunc("GET /api/v1/network/routes", read, func(w http.ResponseWriter, r *http.Request) {
		routes, err := s.List(r.Context())
		if err != nil {
			WriteErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"routes": routes, "proxy": s.State(r.Context())})
	})
	rt.HandleFunc("POST /api/v1/network/routes", manage, func(w http.ResponseWriter, r *http.Request) {
		var in RouteInput
		if httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		route, err := s.Create(r.Context(), ActorFrom(r), in)
		if err != nil {
			WriteErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, route)
	})
	rt.HandleFunc("PUT /api/v1/network/routes/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := routeID(w, r)
		var in RouteInput
		if !ok || httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		route, err := s.Update(r.Context(), ActorFrom(r), id, in)
		if err != nil {
			WriteErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, route)
	})
	rt.HandleFunc("DELETE /api/v1/network/routes/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := routeID(w, r)
		if !ok || !stepUp(w, r) {
			return
		}
		if err := s.Delete(r.Context(), ActorFrom(r), id); err != nil {
			WriteErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/network/apply", manage, func(w http.ResponseWriter, r *http.Request) {
		if err := s.Apply(r.Context(), ActorFrom(r)); err != nil {
			WriteErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, s.State(r.Context()))
	})
	rt.HandleFunc("GET /api/v1/network/overview", read, func(w http.ResponseWriter, r *http.Request) {
		ov, err := s.Overview(r.Context(), ActorFrom(r))
		if err != nil {
			WriteErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, ov)
	})

	// The gate page of the UI (any signed-in user; the route's role decides).
	rt.HandleFunc("POST /api/v1/proxy/gate", httpserver.RequirePermission(string(authz.SelfManage)), func(w http.ResponseWriter, r *http.Request) {
		var in GateRequest
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		p, _ := identity.FromContext(r.Context())
		redirect, err := s.Gate(r.Context(), p, identity.MetaFrom(r), in)
		if err != nil {
			WriteErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"redirect": redirect})
	})
	// Called by Caddy only; Caddy answers 404 for these paths on the Kernhaven host.
	rt.HandleFunc("GET "+proxy.AuthPath, httpserver.Public(), s.forwardAuth)
	rt.HandleFunc("GET "+proxy.CallbackPath, httpserver.Public(), s.callback)
}
