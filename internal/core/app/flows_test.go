package app

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

// AT-F08-01
func TestFirstRunSetup(t *testing.T) {
	h := newHarness(t)
	c := h.newClient()
	var st struct{ Required bool }
	c.do("GET", "/api/v1/setup", nil).expect(200).json(&st)
	if !st.Required {
		t.Fatal("setup not required on empty instance")
	}

	old, _ := h.app.Identity.PrepareSetup(context.Background())
	token, _ := h.app.Identity.PrepareSetup(context.Background()) // restart rotates the token
	body := func(tok string) map[string]string {
		return map[string]string{"token": tok, "username": "owner", "password": strongPassword}
	}
	if r := c.do("POST", "/api/v1/setup", body("wrong")); r.Code != 401 || r.errorCode() != "invalid_setup_token" {
		t.Fatalf("wrong token: %d %s", r.Code, r.Body)
	}
	if r := c.do("POST", "/api/v1/setup", body(old)); r.Code != 401 {
		t.Fatalf("rotated-out token accepted: %d", r.Code)
	}
	if r := c.do("POST", "/api/v1/setup", map[string]string{"token": token, "username": "owner", "password": "short"}); r.Code != 422 {
		t.Fatalf("weak password: %d", r.Code)
	}
	r := c.do("POST", "/api/v1/setup", body(token)).expect(201)
	var s sessionBody
	r.json(&s)
	if s.User.Role != authz.Owner || c.cookie == "" || s.CSRFToken == "" {
		t.Fatalf("setup did not log in an owner: %+v", s)
	}
	c.csrf = s.CSRFToken
	c.do("GET", "/api/v1/auth/session", nil).expect(200)

	// Single use: setup is closed, the token is gone, restarts do not reopen it.
	if r := h.newClient().do("POST", "/api/v1/setup", body(token)); r.Code != 409 || r.errorCode() != "setup_closed" {
		t.Fatalf("second setup: %d %s", r.Code, r.Body)
	}
	if tok, _ := h.app.Identity.PrepareSetup(context.Background()); tok != "" {
		t.Fatal("setup token issued although users exist")
	}
	c.do("GET", "/api/v1/setup", nil).expect(200).json(&st)
	if st.Required {
		t.Fatal("setup still required")
	}
}

// AT-F08-01
func TestSetupTokenExpires(t *testing.T) {
	h := newHarness(t)
	token, _ := h.app.Identity.PrepareSetup(context.Background())
	h.clock.Advance(24*time.Hour + time.Second)
	r := h.newClient().do("POST", "/api/v1/setup", map[string]string{"token": token, "username": "owner", "password": strongPassword})
	if r.Code != 401 {
		t.Fatalf("expired token: %d", r.Code)
	}
}

// AT-F08-02, AT-F08-03
func TestLoginAndCookieAttributes(t *testing.T) {
	h := newHarness(t)
	h.setupOwner()
	c := h.newClient()
	r := c.login("owner", strongPassword).expect(200)
	var ck *http.Cookie
	for _, x := range r.Result().Cookies() {
		ck = x
	}
	if ck == nil || ck.Name != "__Host-kh_session" || !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteStrictMode || ck.Path != "/" {
		t.Fatalf("cookie attributes: %+v", ck)
	}
	if len(ck.Value) < 40 {
		t.Fatalf("token too short: %d", len(ck.Value))
	}
	// The raw token is never stored.
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM sessions WHERE token_hash = ?`, ck.Value).Scan(&n); err != nil || n != 0 {
		t.Fatalf("raw token stored: n=%d err=%v", n, err)
	}
	// A new login creates a new session (no fixation).
	first := c.cookie
	c.login("owner", strongPassword).expect(200)
	if c.cookie == first {
		t.Fatal("session token reused across logins")
	}
}

// AT-F08-02: uniform failures for unknown, wrong, disabled.
func TestLoginFailuresAreUniform(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	id := h.createUser(owner, "dora", authz.Viewer)
	owner.do("PATCH", "/api/v1/users/"+itoa(id), map[string]any{"disabled": true}).expect(200)

	var bodies []string
	for _, cred := range [][2]string{{"nobody", strongPassword}, {"owner", "wrong password here"}, {"dora", strongPassword}} {
		r := h.newClient().login(cred[0], cred[1])
		if r.Code != 401 || r.errorCode() != "invalid_credentials" {
			t.Fatalf("%s: %d %s", cred[0], r.Code, r.Body)
		}
		bodies = append(bodies, strings.SplitN(r.Body.String(), `"request_id"`, 2)[0])
	}
	if bodies[0] != bodies[1] || bodies[1] != bodies[2] {
		t.Fatalf("failure bodies differ: %q", bodies)
	}
}

// AT-F08-02: account lockout with backoff.
func TestAccountLockout(t *testing.T) {
	h := newHarness(t)
	h.setupOwner()
	for i := 0; i < 5; i++ {
		h.newClient().login("owner", "wrong password here").expect(401)
	}
	// Correct password is refused while locked, with the same response.
	if r := h.newClient().login("owner", strongPassword); r.Code != 401 || r.errorCode() != "invalid_credentials" {
		t.Fatalf("locked login: %d", r.Code)
	}
	h.clock.Advance(61 * time.Second)
	h.newClient().login("owner", strongPassword).expect(200)

	var lockouts int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'auth.lockout'`).Scan(&lockouts); err != nil || lockouts != 1 {
		t.Fatalf("lockout audit records = %d (%v)", lockouts, err)
	}
}

// AT-F08-02: per-IP rate limit.
func TestLoginRateLimitPerIP(t *testing.T) {
	h := newHarness(t)
	h.setupOwner()
	c := h.newClient()
	for i := 0; i < 10; i++ {
		c.login("nobody", "wrong password here").expect(401)
	}
	r := c.login("nobody", "wrong password here")
	if r.Code != 429 || r.Header().Get("Retry-After") == "" {
		t.Fatalf("11th attempt: %d retry-after=%q", r.Code, r.Header().Get("Retry-After"))
	}
	h.newClient().login("owner", strongPassword).expect(200) // other IPs unaffected
}

// The rate limit keys on the client address forwarded by the local proxy,
// not on the proxy itself.
func TestRateLimitUsesForwardedClient(t *testing.T) {
	h := newHarness(t)
	h.setupOwner()
	// All requests arrive from the loopback proxy; only X-Forwarded-For differs.
	proxied := func(string) *client { return &client{h: h, ip: "127.0.0.1"} }
	for i := 0; i < 10; i++ {
		proxied("a").do("POST", "/api/v1/auth/login", map[string]string{"username": "x", "password": "y"},
			withHeader("X-Forwarded-For", "203.0.113.1")).expect(401)
	}
	proxied("a").do("POST", "/api/v1/auth/login", map[string]string{"username": "x", "password": "y"},
		withHeader("X-Forwarded-For", "203.0.113.1")).expect(429)
	proxied("b").do("POST", "/api/v1/auth/login", map[string]string{"username": "owner", "password": strongPassword},
		withHeader("X-Forwarded-For", "203.0.113.2")).expect(200)
}

// AT-F08-03: idle and absolute timeouts.
func TestSessionTimeouts(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()

	// Activity keeps the session alive past the idle timeout.
	for i := 0; i < 3; i++ {
		h.clock.Advance(20 * time.Minute)
		owner.do("GET", "/api/v1/auth/session", nil).expect(200)
	}
	// Idle for longer than 30 minutes ends it.
	h.clock.Advance(31 * time.Minute)
	if r := owner.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Fatalf("idle session still valid: %d", r.Code)
	}
	if owner.cookie != "" {
		t.Fatal("expired cookie not cleared")
	}

	// Absolute timeout ends even an active session.
	c := h.loginAs("owner")
	for elapsed := time.Duration(0); elapsed < 12*time.Hour-25*time.Minute; elapsed += 25 * time.Minute {
		h.clock.Advance(25 * time.Minute)
		c.do("GET", "/api/v1/auth/session", nil).expect(200)
	}
	h.clock.Advance(26 * time.Minute)
	if r := c.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Fatalf("session beyond absolute timeout still valid: %d", r.Code)
	}
}

// AT-F08-03
func TestLogoutInvalidatesSession(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	token := owner.cookie
	owner.do("POST", "/api/v1/auth/logout", nil).expect(204)
	stale := &client{h: h, ip: owner.ip, cookie: token, csrf: owner.csrf}
	if r := stale.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Fatalf("logged-out token still valid: %d", r.Code)
	}
}

// AT-F08-04
func TestCSRFProtection(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	body := map[string]any{"username": "eve", "role": "viewer", "password": strongPassword}
	cases := []struct {
		name string
		opts []reqOpt
		code string
	}{
		{"missing token", []reqOpt{withoutHeader("X-CSRF-Token")}, "csrf_failed"},
		{"wrong token", []reqOpt{withHeader("X-CSRF-Token", "forged")}, "csrf_failed"},
		{"foreign origin", []reqOpt{withHeader("Origin", "https://evil.example")}, "origin_rejected"},
		{"null origin", []reqOpt{withHeader("Origin", "null")}, "origin_rejected"},
		{"cross-site fetch", []reqOpt{withoutHeader("Origin"), withHeader("Sec-Fetch-Site", "cross-site")}, "origin_rejected"},
	}
	for _, tc := range cases {
		r := owner.do("POST", "/api/v1/users", body, tc.opts...)
		if r.Code != 403 || r.errorCode() != tc.code {
			t.Errorf("%s: %d %s, want 403 %s", tc.name, r.Code, r.errorCode(), tc.code)
		}
	}
	// Login and setup are origin-checked too.
	if r := h.newClient().do("POST", "/api/v1/auth/login", map[string]string{"username": "owner", "password": strongPassword},
		withHeader("Origin", "https://evil.example")); r.Code != 403 {
		t.Errorf("cross-origin login: %d", r.Code)
	}
	// Nothing was created by the rejected requests.
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM users WHERE username = 'eve'`).Scan(&n)
	if n != 0 {
		t.Fatal("CSRF-rejected request had an effect")
	}
	owner.do("POST", "/api/v1/users", body).expect(201)
}

// AT-F08-06: management rules.
func TestUserManagementRules(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	adminID := h.createUser(owner, "adele", authz.Admin)
	viewerID := h.createUser(owner, "victor", authz.Viewer)
	admin := h.loginAs("adele")

	// Admins cannot create or touch owners/admins, nor assign those roles.
	if r := admin.do("POST", "/api/v1/users", map[string]any{"username": "boss", "role": "owner", "password": strongPassword}); r.Code != 403 {
		t.Errorf("admin created owner: %d", r.Code)
	}
	if r := admin.do("PATCH", "/api/v1/users/1", map[string]any{"display_name": "x"}); r.Code != 403 {
		t.Errorf("admin modified owner: %d", r.Code)
	}
	if r := admin.do("PATCH", "/api/v1/users/"+itoa(viewerID), map[string]any{"role": "admin"}); r.Code != 403 {
		t.Errorf("admin promoted viewer to admin: %d", r.Code)
	}
	admin.do("PATCH", "/api/v1/users/"+itoa(viewerID), map[string]any{"role": "operator"}).expect(200)
	admin.do("POST", "/api/v1/users", map[string]any{"username": "olga", "role": "operator", "password": strongPassword}).expect(201)

	// Self protection.
	if r := admin.do("PATCH", "/api/v1/users/"+itoa(adminID), map[string]any{"role": "viewer"}); r.Code != 403 && r.Code != 409 {
		t.Errorf("admin changed own role: %d", r.Code)
	}
	if r := owner.do("PATCH", "/api/v1/users/1", map[string]any{"disabled": true}); r.Code != 409 {
		t.Errorf("owner disabled self: %d", r.Code)
	}
	if r := owner.do("DELETE", "/api/v1/users/1", nil); r.Code != 409 {
		t.Errorf("owner deleted self: %d", r.Code)
	}

	// Last-owner protection, then allowed once a second owner exists.
	secondID := h.createUser(owner, "otto", authz.Owner)
	second := h.loginAs("otto")
	second.do("PATCH", "/api/v1/users/1", map[string]any{"role": "admin"}).expect(200)
	if r := h.loginAs("adele").do("GET", "/api/v1/users/"+itoa(secondID), nil); r.Code != 200 {
		t.Errorf("read user: %d", r.Code)
	}
	if r := h.loginAs("owner").do("PATCH", "/api/v1/users/"+itoa(secondID), map[string]any{"disabled": true}); r.Code != 403 {
		t.Errorf("demoted admin disabled owner: %d", r.Code)
	}

	// Validation and conflicts.
	if r := second.do("POST", "/api/v1/users", map[string]any{"username": "victor", "role": "viewer", "password": strongPassword}); r.Code != 409 {
		t.Errorf("duplicate username: %d", r.Code)
	}
	for _, bad := range []map[string]any{
		{"username": "A", "role": "viewer", "password": strongPassword},
		{"username": "valid", "role": "root", "password": strongPassword},
		{"username": "valid", "role": "viewer", "password": "short"},
		{"username": "valid", "role": "viewer", "password": strongPassword, "display_name": "bad\nname"},
	} {
		if r := second.do("POST", "/api/v1/users", bad); r.Code != 422 {
			t.Errorf("invalid input %v: %d", bad, r.Code)
		}
	}
	if r := second.do("POST", "/api/v1/users", map[string]any{"username": "x1", "role": "viewer", "password": strongPassword, "is_root": true}); r.Code != 400 {
		t.Errorf("unknown field accepted: %d", r.Code)
	}
}

// AT-F08-06
func TestLastOwnerCannotBeRemoved(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	h.createUser(owner, "otto", authz.Owner)
	otto := h.loginAs("otto")
	otto.do("DELETE", "/api/v1/users/1", nil).expect(204) // two owners: allowed
	ownerAgain := h.loginAs("otto")
	// otto is now the last owner; no other owner exists to act, and self-removal is blocked.
	if r := ownerAgain.do("PATCH", "/api/v1/users/2", map[string]any{"role": "admin"}); r.Code != 409 {
		t.Fatalf("last owner demoted self: %d", r.Code)
	}
}

// AT-F08-03: privilege changes end the target's sessions.
func TestPrivilegeChangeRevokesSessions(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	id := h.createUser(owner, "victor", authz.Operator)

	victim := h.loginAs("victor")
	owner.do("PATCH", "/api/v1/users/"+itoa(id), map[string]any{"role": "viewer"}).expect(200)
	if r := victim.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Errorf("session survived role change: %d", r.Code)
	}

	victim = h.loginAs("victor")
	owner.do("POST", "/api/v1/users/"+itoa(id)+"/password", map[string]string{"password": "another strong passphrase"}).expect(204)
	if r := victim.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Errorf("session survived password reset: %d", r.Code)
	}
	h.newClient().login("victor", "another strong passphrase").expect(200)

	v := h.newClient()
	v.login("victor", "another strong passphrase").expect(200)
	owner.do("DELETE", "/api/v1/users/"+itoa(id), nil).expect(204)
	if r := v.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Errorf("session survived deletion: %d", r.Code)
	}
}

// AT-F08-03
func TestChangeOwnPassword(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	other := h.loginAs("owner")
	if r := owner.do("POST", "/api/v1/auth/password", map[string]string{"current_password": "wrong password here", "new_password": "a different passphrase"}); r.Code != 401 {
		t.Fatalf("wrong current password: %d", r.Code)
	}
	owner.do("POST", "/api/v1/auth/password", map[string]string{"current_password": strongPassword, "new_password": "a different passphrase"}).expect(204)
	owner.do("GET", "/api/v1/auth/session", nil).expect(200)
	if r := other.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Fatalf("other session survived password change: %d", r.Code)
	}
	h.newClient().login("owner", strongPassword).expect(401)
	h.newClient().login("owner", "a different passphrase").expect(200)
}

func TestSessionListAndRevoke(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	h.createUser(owner, "victor", authz.Viewer)
	v1 := h.loginAs("victor")
	v2 := h.loginAs("victor")

	var list struct {
		Sessions []struct {
			ID      string
			Current bool
			IP      string
		}
	}
	v1.do("GET", "/api/v1/auth/sessions", nil).expect(200).json(&list)
	if len(list.Sessions) != 2 {
		t.Fatalf("sessions: %+v", list)
	}
	var otherID, ownerSession string
	for _, s := range list.Sessions {
		if !s.Current {
			otherID = s.ID
		}
	}
	var ownerList struct{ Sessions []struct{ ID string } }
	owner.do("GET", "/api/v1/auth/sessions", nil).expect(200).json(&ownerList)
	ownerSession = ownerList.Sessions[0].ID

	// A viewer cannot see or revoke someone else's session.
	if r := v1.do("DELETE", "/api/v1/auth/sessions/"+ownerSession, nil); r.Code != 404 {
		t.Errorf("viewer revoked owner session: %d", r.Code)
	}
	v1.do("DELETE", "/api/v1/auth/sessions/"+otherID, nil).expect(204)
	if r := v2.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Errorf("revoked session still valid: %d", r.Code)
	}
	// Owners may revoke any session.
	var vl struct{ Sessions []struct{ ID string } }
	v1.do("GET", "/api/v1/auth/sessions", nil).expect(200).json(&vl)
	owner.do("DELETE", "/api/v1/auth/sessions/"+vl.Sessions[0].ID, nil).expect(204)
	if r := v1.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
		t.Errorf("owner-revoked session still valid: %d", r.Code)
	}
}

// AT-F10-01, AT-F10-02
func TestAuditTrail(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	id := h.createUser(owner, "victor", authz.Viewer)
	h.newClient().login("victor", "wrong password here").expect(401)
	viewer := h.loginAs("victor")
	viewer.do("GET", "/api/v1/users", nil).expect(403)
	owner.do("PATCH", "/api/v1/users/"+itoa(id), map[string]any{"role": "operator"}).expect(200)

	var res struct {
		Events []struct {
			Actor, Action, Target, Result, IP string
			RequestID                         string `json:"request_id"`
			Details                           map[string]string
		}
	}
	owner.do("GET", "/api/v1/audit?limit=50", nil).expect(200).json(&res)
	want := map[string]string{
		"auth.setup":   "success",
		"user.create":  "success",
		"auth.login":   "failure",
		"authz.denied": "denied",
		"user.update":  "success",
	}
	seen := map[string]bool{}
	for _, e := range res.Events {
		if want[e.Action] == e.Result {
			seen[e.Action] = true
			if e.RequestID == "" || e.IP == "" || e.Actor == "" || e.Target == "" {
				t.Errorf("incomplete audit record: %+v", e)
			}
		}
	}
	for a := range want {
		if !seen[a] {
			t.Errorf("no %s/%s audit record", a, want[a])
		}
	}
	var v struct {
		OK      bool
		Records int
	}
	owner.do("GET", "/api/v1/audit/verify", nil).expect(200).json(&v)
	if !v.OK || v.Records < 5 {
		t.Fatalf("verify: %+v", v)
	}
	if r := owner.do("GET", "/api/v1/audit?limit=0", nil); r.Code != 400 {
		t.Errorf("invalid limit: %d", r.Code)
	}
}

func TestVersionRequiresAuthentication(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	if r := h.newClient().do("GET", "/api/v1/version", nil); r.Code != 401 {
		t.Fatalf("anonymous version: %d", r.Code)
	}
	owner.do("GET", "/api/v1/version", nil).expect(200)
}

func TestTamperedCookieRejected(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	for _, v := range []string{owner.cookie + "x", strings.Repeat("a", 43), strings.Repeat("a", 500)} {
		c := &client{h: h, ip: owner.ip, cookie: v}
		if r := c.do("GET", "/api/v1/auth/session", nil); r.Code != 401 {
			t.Errorf("cookie %q...: %d", v[:8], r.Code)
		}
	}
}

func itoa(v int64) string { return strconv.FormatInt(v, 10) }

// AT-F01-03: preferences are stored per user on the server.
func TestPreferences(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	var p struct{ Theme string }
	owner.do("GET", "/api/v1/auth/preferences", nil).expect(200).json(&p)
	if p.Theme != "system" {
		t.Fatalf("default theme %q", p.Theme)
	}
	owner.do("PUT", "/api/v1/auth/preferences", map[string]string{"theme": "dark"}).expect(200)
	if r := owner.do("PUT", "/api/v1/auth/preferences", map[string]string{"theme": "neon"}); r.Code != 422 {
		t.Fatalf("invalid theme: %d", r.Code)
	}
	other := h.loginAs("owner") // another device
	other.do("GET", "/api/v1/auth/preferences", nil).expect(200).json(&p)
	if p.Theme != "dark" {
		t.Fatalf("theme not persisted: %q", p.Theme)
	}
}

// AT-F01-01: the web UI is served for non-API paths, never for API paths.
func TestWebUIFallback(t *testing.T) {
	h := newHarness(t)
	c := h.newClient()
	r := c.do("GET", "/users", nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), "<div id=\"root\">") {
		t.Fatalf("UI route: %d %q", r.Code, r.Body.String())
	}
	if csp := r.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("UI CSP %q", csp)
	}
	r = c.do("GET", "/api/v1/does-not-exist", nil)
	if r.Code != 404 || r.errorCode() != "not_found" {
		t.Fatalf("API 404: %d %s", r.Code, r.Body.String())
	}
	if csp := r.Header().Get("Content-Security-Policy"); !strings.HasPrefix(csp, "default-src 'none'") {
		t.Fatalf("API CSP %q", csp)
	}
}
