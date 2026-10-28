package network

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
)

// The sign-in gate (AT-F11-02): Caddy asks the Core for every request to a
// gated route. Kernhaven's session cookie is host-only and SameSite=Strict,
// so the app's host gets its own cookie through a one-time code.

// codeTTL bounds the time between the gate page and the app's callback.
const codeTTL = 60 * time.Second

// Gate errors.
var (
	ErrGateDenied   = errors.New("your role cannot open this app")
	ErrGateRedirect = errors.New("the return address does not belong to this route")
)

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

// CookieName is the gate cookie of a route on the app's host.
func CookieName(id int64) string { return "kh_gate_" + strconv.FormatInt(id, 10) }

func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return strings.ToLower(host)
	}
	return strings.ToLower(h)
}

// inPrefix reports whether path p lies within prefix.
func inPrefix(p, prefix string) bool {
	return prefix == "" || p == prefix || strings.HasPrefix(p, prefix+"/")
}

// safePath accepts a same-host absolute path (no scheme, no "//", no
// backslash, no control characters) within the route's prefix.
func safePath(rd, prefix string) bool {
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.ContainsAny(rd, "\\\r\n\t") {
		return false
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return false
	}
	return inPrefix(u.Path, prefix)
}

func (s *Service) gateRoute(ctx context.Context, id int64) (Route, error) {
	r, err := scanRoute(s.db.QueryRowContext(ctx, `SELECT `+routeColumns+` FROM proxy_routes WHERE id = ? AND sso = 1`, id))
	return r, err
}

// GateRequest starts the gate for a signed-in user.
type GateRequest struct {
	RouteID int64  `json:"route_id"`
	RD      string `json:"rd"`
}

// Gate checks the user and the return address and returns the URL of the
// app's callback with a one-time code.
func (s *Service) Gate(ctx context.Context, p *identity.Principal, m identity.Meta, in GateRequest) (string, error) {
	r, err := s.gateRoute(ctx, in.RouteID)
	if err != nil {
		return "", err
	}
	a := Actor{ID: p.User.ID, Name: p.User.Username, RequestID: m.RequestID, IP: m.IP}
	target := "route:" + strconv.FormatInt(r.ID, 10)
	if p.Session.EnrollmentOnly || !p.User.Role.AtLeast(r.SSOMinRole) {
		ev := s.event(a, "proxy.gate", target, nil, "host", r.Host, "min_role", string(r.SSOMinRole))
		ev.Result = audit.Denied
		_ = s.audit.Record(context.WithoutCancel(ctx), ev)
		return "", ErrGateDenied
	}
	u, err := url.Parse(in.RD)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || hostOnly(u.Host) != r.Host || !inPrefix(u.Path, r.PathPrefix) ||
		strings.ContainsAny(in.RD, "\\\r\n\t") {
		return "", ErrGateRedirect
	}
	if port := u.Port(); port != "" && port != strconv.Itoa(s.httpsPort(ctx)) {
		return "", ErrGateRedirect
	}
	code := randomToken()
	now := s.now()
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM proxy_gate_codes WHERE expires_ms <= ?`, now.UnixMilli()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO proxy_gate_codes (code_hash, route_id, session_id, expires_ms) VALUES (?, ?, ?, ?)`,
			hashToken(code), r.ID, p.Session.ID, now.Add(codeTTL).UnixMilli()); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, now, s.event(a, "proxy.gate", target, nil, "host", r.Host))
		return err
	})
	if err != nil {
		return "", err
	}
	q := url.Values{"code": {code}, "rd": {u.RequestURI()}}
	return "https://" + u.Host + r.PathPrefix + proxy.GatePath + "?" + q.Encode(), nil
}

// routeFromCaddy returns the gated route Caddy names in the request, checked
// against the request's host.
func (s *Service) routeFromCaddy(r *http.Request) (Route, bool) {
	id, err := strconv.ParseInt(r.Header.Get(proxy.RouteHeader), 10, 64)
	if err != nil {
		return Route{}, false
	}
	route, err := s.gateRoute(r.Context(), id)
	if err != nil || hostOnly(r.Host) != route.Host {
		return Route{}, false
	}
	return route, true
}

// allowed reports whether the session behind a gate cookie may use the route.
func (s *Service) allowed(ctx context.Context, route Route, token string) (*identity.Principal, bool) {
	if token == "" || len(token) > 128 {
		return nil, false
	}
	var sid string
	err := s.db.QueryRowContext(ctx, `SELECT session_id FROM proxy_gate_sessions WHERE token_hash = ? AND route_id = ?`, hashToken(token), route.ID).Scan(&sid)
	if err != nil {
		return nil, false
	}
	p, err := s.ids.AuthenticateSession(ctx, sid)
	if err != nil || p.Session.EnrollmentOnly || !p.User.Role.AtLeast(route.SSOMinRole) {
		return nil, false
	}
	return p, true
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// forwardAuth answers Caddy's forward_auth request.
func (s *Service) forwardAuth(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	route, ok := s.routeFromCaddy(r)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	var token string
	if c, err := r.Cookie(CookieName(route.ID)); err == nil {
		token = c.Value
	}
	if p, ok := s.allowed(r.Context(), route, token); ok {
		w.Header().Set(proxy.UserHeader, p.User.Username)
		w.WriteHeader(http.StatusOK)
		return
	}
	uri := r.Header.Get("X-Forwarded-Uri")
	if !strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
		uri = route.PathPrefix + "/"
	}
	rd := "https://" + r.Host + uri
	http.Redirect(w, r, s.origin+"/gate?"+url.Values{"route": {strconv.FormatInt(route.ID, 10)}, "rd": {rd}}.Encode(), http.StatusFound)
}

// callback consumes a one-time code on the app's host and sets the cookie.
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	route, ok := s.routeFromCaddy(r)
	if !ok {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	code, rd := r.URL.Query().Get("code"), r.URL.Query().Get("rd")
	if !safePath(rd, route.PathPrefix) {
		rd = route.PathPrefix + "/"
	}
	var sid string
	err := s.db.QueryRowContext(r.Context(), `DELETE FROM proxy_gate_codes WHERE code_hash = ? AND route_id = ? AND expires_ms > ? RETURNING session_id`,
		hashToken(code), route.ID, s.now().UnixMilli()).Scan(&sid)
	if err != nil {
		http.Error(w, "This sign-in link is invalid or has expired. Open the app again.", http.StatusBadRequest)
		return
	}
	if _, err := s.ids.AuthenticateSession(r.Context(), sid); err != nil {
		http.Error(w, "Your Kernhaven session has ended. Open the app again.", http.StatusBadRequest)
		return
	}
	token := randomToken()
	if _, err := s.db.ExecContext(r.Context(), `INSERT INTO proxy_gate_sessions (token_hash, route_id, session_id, created_ms) VALUES (?, ?, ?, ?)`,
		hashToken(token), route.ID, sid, s.now().UnixMilli()); err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	path := route.PathPrefix
	if path == "" {
		path = "/"
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName(route.ID), Value: token, Path: path, HttpOnly: true,
		Secure: r.Header.Get("X-Forwarded-Proto") != "http", SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, rd, http.StatusFound)
}
