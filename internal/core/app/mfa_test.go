package app

import (
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

type loginBody struct {
	MFARequired           bool     `json:"mfa_required"`
	MFAToken              string   `json:"mfa_token"`
	Methods               []string `json:"methods"`
	CSRFToken             string   `json:"csrf_token"`
	MFA                   bool     `json:"mfa"`
	MFAEnrollmentRequired bool     `json:"mfa_enrollment_required"`
}

// loginPassword signs in with the password only and returns the response.
func loginPassword(h *harness, c *client, user, pw string) (response, loginBody) {
	h.t.Helper()
	r := c.do("POST", "/api/v1/auth/login", map[string]string{"username": user, "password": pw})
	var b loginBody
	if r.Code == 200 {
		r.json(&b)
		if b.CSRFToken != "" {
			c.csrf = b.CSRFToken
		}
	}
	return r, b
}

func enrolTOTP(t *testing.T, h *harness, c *client) (string, []string) {
	t.Helper()
	var begin struct {
		Secret     string `json:"secret"`
		OtpauthURL string `json:"otpauth_url"`
	}
	c.do("POST", "/api/v1/auth/mfa/totp", nil).expect(200).json(&begin)
	if len(begin.Secret) != 32 || !strings.HasPrefix(begin.OtpauthURL, "otpauth://totp/Kernhaven:") {
		t.Fatalf("totp begin %+v", begin)
	}
	c.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": "000000"}).expect(422)
	var conf struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	c.do("POST", "/api/v1/auth/mfa/totp/confirm", map[string]string{"code": totpAt(t, begin.Secret, h.clock.Now())}).expect(200).json(&conf)
	if len(conf.RecoveryCodes) != 10 {
		t.Fatalf("recovery codes %v", conf.RecoveryCodes)
	}
	return begin.Secret, conf.RecoveryCodes
}

// AT-F09-03: TOTP sign-in, replay protection, recovery codes, lockout.
func TestTOTP(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	h.clock.Advance(time.Minute)
	secret, recovery := enrolTOTP(t, h, owner)
	if !strings.Contains(h.logs.String(), "") || strings.Contains(h.logs.String(), secret) {
		t.Fatal("TOTP secret in the log")
	}

	c := h.newClient()
	h.clock.Advance(time.Minute)
	r, b := loginPassword(h, c, "owner", strongPassword)
	if r.Code != 200 || !b.MFARequired || b.MFAToken == "" || strings.Join(b.Methods, ",") != "totp,recovery_code" || b.CSRFToken != "" {
		t.Fatalf("password step: %d %+v", r.Code, b)
	}
	// No session yet.
	c.do("GET", "/api/v1/auth/session", nil).expect(401)
	code := totpAt(t, secret, h.clock.Now())
	c.do("POST", "/api/v1/auth/login/mfa", map[string]string{"mfa_token": b.MFAToken, "code": code}).expect(200).json(&b)
	if !b.MFA || b.CSRFToken == "" {
		t.Fatalf("second step %+v", b)
	}
	c.do("GET", "/api/v1/auth/session", nil).expect(200)

	// The same code cannot be used again (replay), the token neither.
	c2 := h.newClient()
	_, b2 := loginPassword(h, c2, "owner", strongPassword)
	if r := c2.do("POST", "/api/v1/auth/login/mfa", map[string]string{"mfa_token": b2.MFAToken, "code": code}); r.Code != 401 {
		t.Fatalf("replayed code: %d", r.Code)
	}
	c2.do("POST", "/api/v1/auth/login/mfa", map[string]string{"mfa_token": b.MFAToken, "code": code}).expect(401)
	// A code of the next time step works; a recovery code works exactly once.
	h.clock.Advance(30 * time.Second)
	c2.do("POST", "/api/v1/auth/login/mfa", map[string]string{"mfa_token": b2.MFAToken, "code": totpAt(t, secret, h.clock.Now())}).expect(200)
	c3 := h.newClient()
	_, b3 := loginPassword(h, c3, "owner", strongPassword)
	c3.do("POST", "/api/v1/auth/login/mfa", map[string]string{"mfa_token": b3.MFAToken, "recovery_code": strings.ToLower(recovery[0])}).expect(200)
	c4 := h.newClient()
	_, b4 := loginPassword(h, c4, "owner", strongPassword)
	c4.do("POST", "/api/v1/auth/login/mfa", map[string]string{"mfa_token": b4.MFAToken, "recovery_code": recovery[0]}).expect(401)
	var st struct {
		TOTP              bool `json:"totp"`
		RecoveryCodesLeft int  `json:"recovery_codes_left"`
	}
	owner.do("GET", "/api/v1/auth/mfa", nil).expect(200).json(&st)
	if !st.TOTP || st.RecoveryCodesLeft != 9 {
		t.Fatalf("status %+v", st)
	}
	// Five wrong codes lock the account like wrong passwords.
	c5 := h.newClient()
	_, b5 := loginPassword(h, c5, "owner", strongPassword)
	for i := 0; i < 5; i++ {
		c5.do("POST", "/api/v1/auth/login/mfa", map[string]string{"mfa_token": b5.MFAToken, "code": "123456"})
	}
	if r, _ := loginPassword(h, h.newClient(), "owner", strongPassword); r.Code != 401 {
		t.Fatalf("account not locked after wrong codes: %d", r.Code)
	}
	if auditCount(t, h, "auth.lockout", "success") == 0 || auditCount(t, h, "auth.totp_enable", "success") != 1 {
		t.Fatal("not audited")
	}
}

// AT-F09-05: MFA policy, enrolment-only sessions, downgrades, last factor.
func TestMFAPolicy(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	h.createUser(owner, "operator1", authz.Operator)
	owner.do("PUT", "/api/v1/auth/mfa-policy", map[string]any{"required": map[string]bool{"operator": true}}).expect(204)
	var pol struct{ Required map[string]bool }
	owner.do("GET", "/api/v1/auth/mfa-policy", nil).expect(200).json(&pol)
	if !pol.Required["operator"] || pol.Required["owner"] {
		t.Fatalf("policy %+v", pol)
	}

	op := h.newClient()
	_, b := loginPassword(h, op, "operator1", strongPassword)
	if !b.MFAEnrollmentRequired || b.MFARequired {
		t.Fatalf("operator sign-in %+v", b)
	}
	if r := op.do("GET", "/api/v1/jobs", nil); r.Code != 403 || r.errorCode() != "mfa_enrollment_required" {
		t.Fatalf("enrolment-only session: %d %s", r.Code, r.Body)
	}
	op.do("GET", "/api/v1/auth/mfa", nil).expect(200)
	enrolTOTP(t, h, op)
	op.do("GET", "/api/v1/jobs", nil).expect(200)
	// The last factor a policy requires cannot be removed.
	if r := op.do("DELETE", "/api/v1/auth/mfa/totp", nil); r.Code != 409 || r.errorCode() != "last_factor" {
		t.Fatalf("removing the last factor: %d %s", r.Code, r.Body)
	}

	// Downgrade needs step-up and is audited as such; operators cannot change the policy.
	op.do("PUT", "/api/v1/auth/mfa-policy", map[string]any{"required": map[string]bool{}}).expect(403)
	h.clock.Advance(11 * time.Minute)
	if r := owner.do("PUT", "/api/v1/auth/mfa-policy", map[string]any{"required": map[string]bool{"operator": false}}); r.Code != 403 || r.errorCode() != "step_up_required" {
		t.Fatalf("downgrade without step-up: %d", r.Code)
	}
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": strongPassword}).expect(204)
	owner.do("PUT", "/api/v1/auth/mfa-policy", map[string]any{"required": map[string]bool{"operator": false}}).expect(204)
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'auth.mfa_policy' AND details LIKE '%"downgrade":"true"%'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("downgrade audit: %d %v", n, err)
	}

	// An admin resets a lost second factor (step-up, audited).
	owner.do("POST", "/api/v1/users/2/mfa/reset", nil).expect(204)
	if r, b := loginPassword(h, h.newClient(), "operator1", strongPassword); r.Code != 200 || b.MFARequired {
		t.Fatalf("after reset: %d %+v", r.Code, b)
	}
}

// AT-F09-04: security-relevant actions need a recent strong authentication.
func TestStepUp(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	secret, _ := enrolTOTP(t, h, owner)
	id := h.createUser(owner, "viewer1", authz.Viewer)
	h.clock.Advance(11 * time.Minute)
	actions := []struct {
		method, path string
		body         any
	}{
		{"DELETE", "/api/v1/users/" + itoa(id), nil},
		{"PATCH", "/api/v1/users/" + itoa(id), map[string]any{"role": "operator"}},
		{"POST", "/api/v1/users/" + itoa(id) + "/password", map[string]string{"password": "another long passphrase here"}},
		{"POST", "/api/v1/users", map[string]any{"username": "admin2", "password": "another long passphrase here", "role": "admin"}},
		{"PUT", "/api/v1/auth/mfa-policy", map[string]any{"required": map[string]bool{}}},
		{"POST", "/api/v1/auth/mfa/recovery-codes", nil},
		{"DELETE", "/api/v1/auth/mfa/totp", nil},
		{"POST", "/api/v1/auth/passkeys/begin", nil},
		{"POST", "/api/v1/catalog/sources", map[string]string{"name": "x", "public_key": "AAAA"}},
		{"POST", "/api/v1/stacks", map[string]any{"name": "s", "compose": "services: {}", "exceptions": []map[string]string{{"service": "a", "rule": "privileged", "reason": "needs it for the test"}}}},
		{"POST", "/api/v1/storage/format", map[string]any{"path": "/dev/sdx", "confirm": "sdx"}},
	}
	for _, a := range actions {
		if r := owner.do(a.method, a.path, a.body); r.Code != 403 || r.errorCode() != "step_up_required" {
			t.Errorf("%s %s without step-up: %d %s", a.method, a.path, r.Code, r.Body)
		}
	}
	// With TOTP the password alone is not enough.
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": strongPassword}).expect(401)
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": strongPassword, "code": totpAt(t, secret, h.clock.Now())}).expect(204)
	for _, a := range actions {
		if r := owner.do(a.method, a.path, a.body); r.errorCode() == "step_up_required" {
			t.Errorf("%s %s still requires step-up", a.method, a.path)
		}
	}
	h.clock.Advance(11 * time.Minute)
	if r := owner.do("POST", "/api/v1/auth/mfa/recovery-codes", nil); r.errorCode() != "step_up_required" {
		t.Fatal("step-up window did not expire")
	}
}

// AT-F09-02: passkeys for sign-in, as second factor and passkey-only accounts.
func TestPasskeys(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	auth := newAuthenticator(t)
	var c ceremony
	owner.do("POST", "/api/v1/auth/passkeys/begin", nil).expect(200).json(&c)
	owner.do("POST", "/api/v1/auth/passkeys/finish", map[string]any{"token": c.Token, "name": "Laptop", "credential": auth.create(c)}).expect(201)
	var st struct {
		Passkeys []struct{ ID int64 }
	}
	owner.do("GET", "/api/v1/auth/mfa", nil).expect(200).json(&st)
	if len(st.Passkeys) != 1 {
		t.Fatalf("passkeys %+v", st)
	}

	// Usernameless sign-in.
	p := h.newClient()
	p.do("POST", "/api/v1/auth/passkey/begin", nil).expect(200).json(&c)
	var b loginBody
	p.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"token": c.Token, "credential": auth.get(c)}).expect(200).json(&b)
	if !b.MFA || b.CSRFToken == "" {
		t.Fatalf("passkey sign-in %+v", b)
	}
	// Replaying an assertion (counter not increased) and a foreign origin are rejected.
	p.do("POST", "/api/v1/auth/passkey/begin", nil).expect(200).json(&c)
	p.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"token": c.Token, "credential": auth.sign(c.Options.PublicKey.Challenge)}).expect(401)
	p.do("POST", "/api/v1/auth/passkey/begin", nil).expect(200).json(&c)
	evil := *auth
	evil.origin = "https://evil.example"
	evil.counter = auth.counter + 5
	p.do("POST", "/api/v1/auth/passkey/finish", map[string]any{"token": c.Token, "credential": evil.sign(c.Options.PublicKey.Challenge)}).expect(401)

	// With a passkey the password alone no longer signs in: passkey as second factor.
	m := h.newClient()
	_, b = loginPassword(h, m, "owner", strongPassword)
	if !b.MFARequired || strings.Join(b.Methods, ",") != "passkey" {
		t.Fatalf("password step %+v", b)
	}
	m.do("POST", "/api/v1/auth/login/mfa/passkey/begin", map[string]string{"mfa_token": b.MFAToken}).expect(200).json(&c)
	auth.counter += 10 // the stored counter moved on during the replay attempts
	m.do("POST", "/api/v1/auth/login/mfa/passkey/finish", map[string]any{"mfa_token": b.MFAToken, "token": c.Token, "credential": auth.get(c)}).expect(200)

	// Passkey-only: the password stops working; the last passkey is protected.
	owner.do("PUT", "/api/v1/auth/password-login", map[string]bool{"enabled": false}).expect(204)
	if r, _ := loginPassword(h, h.newClient(), "owner", strongPassword); r.Code != 401 {
		t.Fatalf("password sign-in of a passkey-only account: %d", r.Code)
	}
	if r := owner.do("DELETE", "/api/v1/auth/passkeys/"+itoa(st.Passkeys[0].ID), nil); r.Code != 409 {
		t.Fatalf("removing the last passkey: %d", r.Code)
	}
	// Step-up with a passkey.
	h.clock.Advance(11 * time.Minute)
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": strongPassword}).expect(401)
	owner.do("POST", "/api/v1/auth/step-up/passkey/begin", nil).expect(200).json(&c)
	owner.do("POST", "/api/v1/auth/step-up/passkey/finish", map[string]any{"token": c.Token, "credential": auth.get(c)}).expect(204)
	owner.do("PUT", "/api/v1/auth/password-login", map[string]bool{"enabled": true}).expect(204)
	if auditCount(t, h, "auth.passkey_add", "success") != 1 || auditCount(t, h, "auth.step_up", "success") != 1 {
		t.Fatal("not audited")
	}
}
