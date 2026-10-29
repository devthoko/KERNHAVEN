package alerts

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

func actorFrom(r *http.Request) Actor {
	m := identity.MetaFrom(r)
	a := Actor{Name: "system", RequestID: m.RequestID, IP: m.IP}
	if p, ok := identity.FromContext(r.Context()); ok {
		a.ID, a.Name = p.User.ID, p.User.Username
	}
	return a
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.Msg)
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrExists):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, identity.ErrStepUpRequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "step_up_required", err.Error())
	default:
		httpserver.InternalError(w, r, err)
	}
}

// stepUp: a channel decides where the Core sends data and holds credentials.
func stepUp(w http.ResponseWriter, r *http.Request) bool {
	if err := identity.CheckStepUp(r.Context()); err != nil {
		writeErr(w, r, err)
		return false
	}
	return true
}

func channelID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, r, ErrNotFound)
		return 0, false
	}
	return id, true
}

// Register adds the alert and notification routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.AlertsRead))
	manage := httpserver.RequirePermission(string(authz.AlertsManage))

	rt.HandleFunc("GET /api/v1/alerts", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Alerts(r.Context(), r.URL.Query().Get("state") == "firing")
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"alerts": list})
	})
	rt.HandleFunc("GET /api/v1/alerts/rules", read, func(w http.ResponseWriter, r *http.Request) {
		rules, err := s.Rules(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"rules": rules})
	})
	rt.HandleFunc("PUT /api/v1/alerts/rules/{rule}", manage, func(w http.ResponseWriter, r *http.Request) {
		var in RuleInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		rule, err := s.SetRule(r.Context(), actorFrom(r), r.PathValue("rule"), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, rule)
	})
	rt.HandleFunc("GET /api/v1/alerts/deliveries", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Deliveries(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"deliveries": list})
	})
	rt.HandleFunc("GET /api/v1/notify/channels", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Channels(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"channels": list})
	})
	rt.HandleFunc("POST /api/v1/notify/channels", manage, func(w http.ResponseWriter, r *http.Request) {
		var in ChannelInput
		if httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		c, err := s.SaveChannel(r.Context(), actorFrom(r), 0, in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, c)
	})
	rt.HandleFunc("PUT /api/v1/notify/channels/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := channelID(w, r)
		var in ChannelInput
		if !ok || httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		c, err := s.SaveChannel(r.Context(), actorFrom(r), id, in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, c)
	})
	rt.HandleFunc("DELETE /api/v1/notify/channels/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := channelID(w, r)
		if !ok || !stepUp(w, r) {
			return
		}
		if err := s.DeleteChannel(r.Context(), actorFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/notify/channels/{id}/test", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := channelID(w, r)
		if !ok {
			return
		}
		d, err := s.Test(r.Context(), actorFrom(r), id)
		if err != nil && !errors.Is(err, ErrNotFound) && d.ID == 0 {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, d)
	})
}
