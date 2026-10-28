package certs

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	switch {
	case errors.As(err, &ve):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.Msg)
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrInUse):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	default:
		network.WriteErr(w, r, err)
	}
}

func stepUp(w http.ResponseWriter, r *http.Request) bool {
	if err := identity.CheckStepUp(r.Context()); err != nil {
		writeErr(w, r, err)
		return false
	}
	return true
}

// Register adds the TLS routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.NetworkRead))
	manage := httpserver.RequirePermission(string(authz.NetworkManage))

	rt.HandleFunc("GET /api/v1/tls", read, func(w http.ResponseWriter, r *http.Request) {
		hosts, err := s.Hosts(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		certs, err := s.certificates(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		st, err := s.settings(r.Context(), s.db)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		res := map[string]any{"hosts": hosts, "certificates": certs, "settings": st}
		if ca, err := s.Root(r.Context(), network.ActorFrom(r)); err == nil {
			res["root_sha256"] = ca.SHA256
		}
		httpserver.WriteJSON(w, http.StatusOK, res)
	})
	rt.HandleFunc("GET /api/v1/tls/root.crt", httpserver.RequirePermission(string(authz.SelfManage)), func(w http.ResponseWriter, r *http.Request) {
		ca, err := s.Root(r.Context(), network.ActorFrom(r))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="kernhaven-root-ca.crt"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(ca.RootPEM))
	})
	rt.HandleFunc("PUT /api/v1/tls/settings", manage, func(w http.ResponseWriter, r *http.Request) {
		var in SettingsInput
		if httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		st, err := s.SetSettings(r.Context(), network.ActorFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, st)
	})
	rt.HandleFunc("PUT /api/v1/tls/hosts/{host}", manage, func(w http.ResponseWriter, r *http.Request) {
		var in HostInput
		if httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		h, job, err := s.SetHost(r.Context(), network.ActorFrom(r), r.PathValue("host"), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		res := map[string]any{"host": h}
		if job > 0 {
			res["job_id"] = job
		}
		httpserver.WriteJSON(w, http.StatusOK, res)
	})
	rt.HandleFunc("POST /api/v1/tls/hosts/{host}/renew", manage, func(w http.ResponseWriter, r *http.Request) {
		if !stepUp(w, r) {
			return
		}
		job, err := s.Renew(r.Context(), network.ActorFrom(r), r.PathValue("host"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": job})
	})
	rt.HandleFunc("POST /api/v1/tls/certificates", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CertificatePEM string `json:"certificate_pem"`
			KeyPEM         string `json:"key_pem"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		c, err := s.Upload(r.Context(), network.ActorFrom(r), in.CertificatePEM, in.KeyPEM)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, c)
	})
	rt.HandleFunc("DELETE /api/v1/tls/certificates/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil || id <= 0 {
			writeErr(w, r, ErrNotFound)
			return
		}
		if !stepUp(w, r) {
			return
		}
		if err := s.DeleteCertificate(r.Context(), network.ActorFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
