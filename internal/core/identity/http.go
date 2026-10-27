package identity

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// CSRFHeader carries the session's CSRF token on unsafe requests.
const CSRFHeader = "X-CSRF-Token"

// CookieName returns the session cookie name for the configured origin.
// The __Host- prefix pins the cookie to this host, path / and HTTPS.
func (s *Service) CookieName() string {
	if s.secure() {
		return "__Host-kh_session"
	}
	return "kh_session"
}

func (s *Service) secure() bool { return strings.HasPrefix(s.cfg.Origin, "https://") }

func (s *Service) setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.CookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   int(s.cfg.AbsoluteTimeout / time.Second),
		HttpOnly: true,
		Secure:   s.secure(),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Service) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.CookieName(), Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: s.secure(), SameSite: http.SameSiteStrictMode,
	})
}

// MetaFrom extracts request metadata for auditing.
func MetaFrom(r *http.Request) Meta {
	return Meta{
		RequestID: httpserver.RequestID(r.Context()),
		IP:        httpserver.ClientIP(r),
		UserAgent: r.UserAgent(),
	}
}

// originAllowed implements the CSRF origin check for unsafe methods
// (AT-F08-04).
func (s *Service) originAllowed(r *http.Request) bool {
	if origin := r.Header.Get("Origin"); origin != "" {
		return origin == s.cfg.Origin
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" {
		return site == "same-origin"
	}
	return true // non-browser client; session routes still require the CSRF token
}

// Guard enforces authentication, CSRF protection and the route permission.
// It is the httpserver.Guard for every non-public route.
func (s *Service) Guard(permission string, next http.Handler) http.Handler {
	perm := authz.Permission(permission)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var token string
		if c, err := r.Cookie(s.CookieName()); err == nil {
			token = c.Value
		}
		p, err := s.Authenticate(r.Context(), token)
		if err != nil {
			if !errors.Is(err, ErrUnauthenticated) {
				httpserver.InternalError(w, r, err)
				return
			}
			if token != "" {
				s.clearCookie(w)
			}
			httpserver.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		if !httpserver.IsSafeMethod(r.Method) {
			if !s.originAllowed(r) {
				httpserver.WriteError(w, r, http.StatusForbidden, "origin_rejected", "cross-origin request rejected")
				return
			}
			if !p.CheckCSRF(r.Header.Get(CSRFHeader)) {
				httpserver.WriteError(w, r, http.StatusForbidden, "csrf_failed", "missing or invalid CSRF token")
				return
			}
		}
		if !p.Has(perm) {
			s.record(r.Context(), withDetails(actorEvent(p, MetaFrom(r), "authz.denied", r.Method+" "+r.URL.Path, audit.Denied),
				"permission", permission))
			httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", "you do not have permission for this action")
			return
		}
		next.ServeHTTP(w, r.WithContext(withPrincipal(r.Context(), p)))
	})
}

// writeErr maps service errors to HTTP responses.
func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	var rl *RateLimitError
	switch {
	case errors.As(err, &ve):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.Error())
	case errors.As(err, &rl):
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(rl.RetryAfter.Seconds()))))
		httpserver.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", "too many attempts; try again later")
	case errors.Is(err, ErrInvalidCredentials):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "invalid_credentials", "invalid username or password")
	case errors.Is(err, ErrInvalidSetupToken):
		httpserver.WriteError(w, r, http.StatusUnauthorized, "invalid_setup_token", err.Error())
	case errors.Is(err, ErrSetupClosed):
		httpserver.WriteError(w, r, http.StatusConflict, "setup_closed", err.Error())
	case errors.Is(err, ErrForbidden):
		httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", "you do not have permission for this action")
	case errors.Is(err, ErrSelf), errors.Is(err, ErrLastOwner):
		httpserver.WriteError(w, r, http.StatusConflict, "not_allowed", err.Error())
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrConflict):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", "a user with this username already exists")
	default:
		httpserver.InternalError(w, r, err)
	}
}

func principal(r *http.Request) *Principal {
	p, ok := FromContext(r.Context())
	if !ok {
		// Unreachable for guarded routes; fail closed.
		panic("identity: guarded handler without principal")
	}
	return p
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
		return 0, false
	}
	return id, true
}

// sessionResponse describes the current login to the client.
type sessionResponse struct {
	User        User               `json:"user"`
	Permissions []authz.Permission `json:"permissions"`
	CSRFToken   string             `json:"csrf_token"`
	ExpiresAt   time.Time          `json:"expires_at"`
}

func newSessionResponse(p *Principal) sessionResponse {
	return sessionResponse{User: p.User, Permissions: p.User.Role.Permissions(), CSRFToken: p.Session.CSRFToken, ExpiresAt: p.Session.AbsoluteExpiresAt}
}

type sessionView struct {
	Session
	Current bool `json:"current"`
}

// Register adds the setup, auth and user routes.
func (s *Service) Register(rt *httpserver.Router) {
	self := httpserver.RequirePermission(string(authz.SelfManage))
	usersRead := httpserver.RequirePermission(string(authz.UsersRead))
	usersManage := httpserver.RequirePermission(string(authz.UsersManage))
	s.registerPreferences(rt)

	rt.HandleFunc("GET /api/v1/setup", httpserver.Public(), func(w http.ResponseWriter, r *http.Request) {
		required, err := s.SetupRequired(r.Context())
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]bool{"required": required})
	})

	rt.HandleFunc("POST /api/v1/setup", httpserver.Public(), func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) {
			httpserver.WriteError(w, r, http.StatusForbidden, "origin_rejected", "cross-origin request rejected")
			return
		}
		var in SetupInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		token, p, err := s.CompleteSetup(r.Context(), MetaFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		s.setCookie(w, token)
		httpserver.WriteJSON(w, http.StatusCreated, newSessionResponse(p))
	})

	rt.HandleFunc("POST /api/v1/auth/login", httpserver.Public(), func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) {
			httpserver.WriteError(w, r, http.StatusForbidden, "origin_rejected", "cross-origin request rejected")
			return
		}
		var in struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		token, p, err := s.Login(r.Context(), MetaFrom(r), strings.TrimSpace(in.Username), in.Password)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		s.setCookie(w, token)
		httpserver.WriteJSON(w, http.StatusOK, newSessionResponse(p))
	})

	rt.HandleFunc("POST /api/v1/auth/logout", self, func(w http.ResponseWriter, r *http.Request) {
		if err := s.Logout(r.Context(), principal(r), MetaFrom(r)); err != nil {
			writeErr(w, r, err)
			return
		}
		s.clearCookie(w)
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("GET /api/v1/auth/session", self, func(w http.ResponseWriter, r *http.Request) {
		httpserver.WriteJSON(w, http.StatusOK, newSessionResponse(principal(r)))
	})

	rt.HandleFunc("POST /api/v1/auth/password", self, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if err := s.ChangeOwnPassword(r.Context(), principal(r), MetaFrom(r), in.CurrentPassword, in.NewPassword); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("GET /api/v1/auth/sessions", self, func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		list, err := s.ListSessions(r.Context(), p)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		views := make([]sessionView, len(list))
		for i, sess := range list {
			views[i] = sessionView{Session: sess, Current: sess.ID == p.Session.ID}
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"sessions": views})
	})

	rt.HandleFunc("DELETE /api/v1/auth/sessions/{id}", self, func(w http.ResponseWriter, r *http.Request) {
		p := principal(r)
		id := r.PathValue("id")
		if err := s.RevokeSession(r.Context(), p, MetaFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		if id == p.Session.ID {
			s.clearCookie(w)
		}
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("GET /api/v1/users", usersRead, func(w http.ResponseWriter, r *http.Request) {
		users, err := s.ListUsers(r.Context())
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"users": users})
	})

	rt.HandleFunc("POST /api/v1/users", usersManage, func(w http.ResponseWriter, r *http.Request) {
		var in CreateUserInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		u, err := s.CreateUser(r.Context(), principal(r), MetaFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, u)
	})

	rt.HandleFunc("GET /api/v1/users/{id}", usersRead, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		u, err := s.GetUser(r.Context(), id)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, u)
	})

	rt.HandleFunc("PATCH /api/v1/users/{id}", usersManage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		var in UpdateUserInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		u, err := s.UpdateUser(r.Context(), principal(r), MetaFrom(r), id, in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, u)
	})

	rt.HandleFunc("DELETE /api/v1/users/{id}", usersManage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if err := s.DeleteUser(r.Context(), principal(r), MetaFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("POST /api/v1/users/{id}/password", usersManage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		var in struct {
			Password string `json:"password"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		if err := s.ResetPassword(r.Context(), principal(r), MetaFrom(r), id, in.Password); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
