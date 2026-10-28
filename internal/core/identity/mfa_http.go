package identity

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// loginResponse is a session or an MFA challenge.
type loginResponse struct {
	sessionResponse
	MFARequired bool     `json:"mfa_required"`
	MFAToken    string   `json:"mfa_token,omitempty"`
	Methods     []string `json:"methods,omitempty"`
}

func (s *Service) writeLogin(w http.ResponseWriter, res LoginResult) {
	if res.Principal == nil {
		httpserver.WriteJSON(w, http.StatusOK, loginResponse{MFARequired: true, MFAToken: res.MFAToken, Methods: res.Methods})
		return
	}
	s.setCookie(w, res.Token)
	httpserver.WriteJSON(w, http.StatusOK, loginResponse{sessionResponse: newSessionResponse(res.Principal)})
}

// ceremonyInput carries a WebAuthn response from the browser.
type ceremonyInput struct {
	Token      string          `json:"token"`
	MFAToken   string          `json:"mfa_token"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func decodeCeremony(w http.ResponseWriter, r *http.Request) (ceremonyInput, bool) {
	var in ceremonyInput
	if httpserver.DecodeJSON(w, r, &in) != nil {
		return in, false
	}
	if len(in.Credential) == 0 {
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", "credential is required")
		return in, false
	}
	return in, true
}

func (s *Service) registerMFA(rt *httpserver.Router) {
	public := httpserver.Public()
	self := httpserver.RequirePermission(string(authz.SelfManage))
	security := httpserver.RequirePermission(string(authz.SecurityManage))
	usersManage := httpserver.RequirePermission(string(authz.UsersManage))
	originOK := func(w http.ResponseWriter, r *http.Request) bool {
		if !s.originAllowed(r) {
			httpserver.WriteError(w, r, http.StatusForbidden, "origin_rejected", "cross-origin request rejected")
			return false
		}
		return true
	}

	// ---- sign-in second step and passkey sign-in (public, rate-limited) ----
	rt.HandleFunc("POST /api/v1/auth/login/mfa", public, func(w http.ResponseWriter, r *http.Request) {
		if !originOK(w, r) {
			return
		}
		var in struct {
			MFAToken     string `json:"mfa_token"`
			Code         string `json:"code"`
			RecoveryCode string `json:"recovery_code"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		res, err := s.CompleteMFA(r.Context(), MetaFrom(r), in.MFAToken, in.Code, in.RecoveryCode)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		s.writeLogin(w, res)
	})
	rt.HandleFunc("POST /api/v1/auth/login/mfa/passkey/begin", public, func(w http.ResponseWriter, r *http.Request) {
		if !originOK(w, r) {
			return
		}
		var in struct {
			MFAToken string `json:"mfa_token"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		c, err := s.BeginMFAPasskey(r.Context(), MetaFrom(r), in.MFAToken)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, c)
	})
	rt.HandleFunc("POST /api/v1/auth/login/mfa/passkey/finish", public, func(w http.ResponseWriter, r *http.Request) {
		if !originOK(w, r) {
			return
		}
		in, ok := decodeCeremony(w, r)
		if !ok {
			return
		}
		res, err := s.FinishMFAPasskey(r.Context(), MetaFrom(r), in.MFAToken, in.Token, in.Credential)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		s.writeLogin(w, res)
	})
	rt.HandleFunc("POST /api/v1/auth/passkey/begin", public, func(w http.ResponseWriter, r *http.Request) {
		if !originOK(w, r) {
			return
		}
		_, _ = io.Copy(io.Discard, r.Body)
		c, err := s.BeginPasskeyLogin(r.Context(), MetaFrom(r))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, c)
	})
	rt.HandleFunc("POST /api/v1/auth/passkey/finish", public, func(w http.ResponseWriter, r *http.Request) {
		if !originOK(w, r) {
			return
		}
		in, ok := decodeCeremony(w, r)
		if !ok {
			return
		}
		res, err := s.FinishPasskeyLogin(r.Context(), MetaFrom(r), in.Token, in.Credential)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		s.writeLogin(w, res)
	})

	// ---- the own account ----
	rt.HandleFunc("GET /api/v1/auth/mfa", self, func(w http.ResponseWriter, r *http.Request) {
		st, err := s.MFAStatus(r.Context(), principal(r).User.ID)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, st)
	})
	rt.HandleFunc("POST /api/v1/auth/step-up", self, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Password     string `json:"password"`
			Code         string `json:"code"`
			RecoveryCode string `json:"recovery_code"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		p := principal(r)
		if err := s.StepUp(r.Context(), p, MetaFrom(r), in.Password, in.Code, in.RecoveryCode); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/auth/step-up/passkey/begin", self, func(w http.ResponseWriter, r *http.Request) {
		c, err := s.BeginStepUpPasskey(r.Context(), principal(r))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, c)
	})
	rt.HandleFunc("POST /api/v1/auth/step-up/passkey/finish", self, func(w http.ResponseWriter, r *http.Request) {
		in, ok := decodeCeremony(w, r)
		if !ok {
			return
		}
		if err := s.FinishStepUpPasskey(r.Context(), principal(r), MetaFrom(r), in.Token, in.Credential); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/auth/mfa/totp", self, func(w http.ResponseWriter, r *http.Request) {
		secret, uri, err := s.BeginTOTP(r.Context(), principal(r))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"secret": secret, "otpauth_url": uri})
	})
	rt.HandleFunc("POST /api/v1/auth/mfa/totp/confirm", self, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Code string `json:"code"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		codes, err := s.ConfirmTOTP(r.Context(), principal(r), MetaFrom(r), in.Code)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
	})
	rt.HandleFunc("DELETE /api/v1/auth/mfa/totp", self, func(w http.ResponseWriter, r *http.Request) {
		if err := s.DisableTOTP(r.Context(), principal(r), MetaFrom(r)); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/auth/mfa/recovery-codes", self, func(w http.ResponseWriter, r *http.Request) {
		codes, err := s.RegenerateRecoveryCodes(r.Context(), principal(r), MetaFrom(r))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
	})
	rt.HandleFunc("POST /api/v1/auth/passkeys/begin", self, func(w http.ResponseWriter, r *http.Request) {
		c, err := s.BeginPasskeyRegistration(r.Context(), principal(r))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, c)
	})
	rt.HandleFunc("POST /api/v1/auth/passkeys/finish", self, func(w http.ResponseWriter, r *http.Request) {
		in, ok := decodeCeremony(w, r)
		if !ok {
			return
		}
		pk, err := s.FinishPasskeyRegistration(r.Context(), principal(r), MetaFrom(r), in.Token, in.Name, in.Credential)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, pk)
	})
	rt.HandleFunc("DELETE /api/v1/auth/passkeys/{id}", self, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if err := s.DeletePasskey(r.Context(), principal(r), MetaFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("PUT /api/v1/auth/password-login", self, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Enabled bool `json:"enabled"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if err := s.SetPasswordLogin(r.Context(), principal(r), MetaFrom(r), in.Enabled); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	// ---- administration ----
	rt.HandleFunc("GET /api/v1/auth/mfa-policy", security, func(w http.ResponseWriter, r *http.Request) {
		pol, err := s.GetMFAPolicy(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"required": pol})
	})
	rt.HandleFunc("PUT /api/v1/auth/mfa-policy", security, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Required map[authz.Role]bool `json:"required"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		for role := range in.Required {
			if !role.Valid() {
				httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", "unknown role "+string(role))
				return
			}
		}
		if err := s.SetMFAPolicy(r.Context(), principal(r), MetaFrom(r), in.Required); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/users/{id}/mfa/reset", usersManage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if err := s.ResetMFA(r.Context(), principal(r), MetaFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
