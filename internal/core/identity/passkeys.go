package identity

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
)

// PasskeyInfo is a registered passkey as shown to its owner.
type PasskeyInfo struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// newWebAuthn configures the relying party from the public origin (ADR-0024).
func newWebAuthn(origin string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, fmt.Errorf("identity: public origin %q has no host for WebAuthn", origin)
	}
	return webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: "Kernhaven",
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementRequired,
			UserVerification: protocol.VerificationRequired,
		},
	})
}

// waUser adapts a Kernhaven user to webauthn.User.
type waUser struct {
	id          int64
	handle      []byte
	name        string
	displayName string
	creds       []webauthn.Credential
}

func (u *waUser) WebAuthnID() []byte                         { return u.handle }
func (u *waUser) WebAuthnName() string                       { return u.name }
func (u *waUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// loadWAUser loads a user with its passkeys; create gives it a user handle
// if it has none yet.
func (s *Service) loadWAUser(ctx context.Context, q dbtx, userID int64, create bool) (*waUser, error) {
	u := &waUser{id: userID}
	if err := q.QueryRowContext(ctx, `SELECT username, display_name, webauthn_id FROM users WHERE id = ?`, userID).Scan(&u.name, &u.displayName, &u.handle); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if u.displayName == "" {
		u.displayName = u.name
	}
	if len(u.handle) == 0 && create {
		u.handle = make([]byte, 32)
		if _, err := rand.Read(u.handle); err != nil {
			return nil, err
		}
		if _, err := q.ExecContext(ctx, `UPDATE users SET webauthn_id = ? WHERE id = ?`, u.handle, userID); err != nil {
			return nil, err
		}
	}
	rows, err := s.db.QueryContext(ctx, `SELECT credential FROM user_passkeys WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var c webauthn.Credential
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			return nil, err
		}
		u.creds = append(u.creds, c)
	}
	return u, rows.Err()
}

func (s *Service) passkeys(ctx context.Context, userID int64) ([]PasskeyInfo, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, created_ms, last_used_ms FROM user_passkeys WHERE user_id = ? ORDER BY id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PasskeyInfo{}
	for rows.Next() {
		var pk PasskeyInfo
		var created, used int64
		if err := rows.Scan(&pk.ID, &pk.Name, &created, &used); err != nil {
			return nil, err
		}
		pk.CreatedAt = fromMS(created)
		if used > 0 {
			t := fromMS(used)
			pk.LastUsedAt = &t
		}
		out = append(out, pk)
	}
	return out, rows.Err()
}

func encodeSession(sd *webauthn.SessionData) string {
	b, _ := json.Marshal(sd)
	return string(b)
}

func decodeSession(data string) (webauthn.SessionData, error) {
	var sd webauthn.SessionData
	if err := json.Unmarshal([]byte(data), &sd); err != nil {
		return sd, ErrChallenge
	}
	return sd, nil
}

// Ceremony is what the browser needs for navigator.credentials.
type Ceremony struct {
	Token   string `json:"token"`
	Options any    `json:"options"`
}

// BeginPasskeyRegistration starts adding a passkey (step-up required, or a
// fresh enrolment-only session right after the password).
func (s *Service) BeginPasskeyRegistration(ctx context.Context, p *Principal) (Ceremony, error) {
	if err := s.RequireStepUp(p); err != nil {
		return Ceremony{}, err
	}
	u, err := s.loadWAUser(ctx, s.db, p.User.ID, true)
	if err != nil {
		return Ceremony{}, err
	}
	excl := make([]protocol.CredentialDescriptor, 0, len(u.creds))
	for i := range u.creds {
		excl = append(excl, u.creds[i].Descriptor())
	}
	opts, sd, err := s.wa.BeginRegistration(u, webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired), webauthn.WithExclusions(excl))
	if err != nil {
		return Ceremony{}, err
	}
	tok, err := s.newChallenge(ctx, s.db, p.User.ID, challengeRegister, encodeSession(sd))
	return Ceremony{Token: tok, Options: opts}, err
}

func validName(n string) (string, error) {
	n = strings.TrimSpace(n)
	if n == "" {
		n = "Passkey"
	}
	if !utf8.ValidString(n) || utf8.RuneCountInString(n) > 64 || strings.ContainsAny(n, "\x00\r\n") {
		return "", &ValidationError{Field: "name", Message: "must be at most 64 printable characters"}
	}
	return n, nil
}

// FinishPasskeyRegistration verifies the authenticator's response and stores
// the passkey (AT-F09-02). User verification is required.
func (s *Service) FinishPasskeyRegistration(ctx context.Context, p *Principal, m Meta, tok, name string, response []byte) (PasskeyInfo, error) {
	name, err := validName(name)
	if err != nil {
		return PasskeyInfo{}, err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(response))
	if err != nil {
		return PasskeyInfo{}, &ValidationError{Field: "passkey", Message: "the authenticator response could not be read"}
	}
	var info PasskeyInfo
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		uid, data, err := s.challenge(ctx, tx, tok, challengeRegister)
		if err != nil || uid != p.User.ID {
			return ErrChallenge
		}
		sd, err := decodeSession(data)
		if err != nil {
			return err
		}
		u, err := s.loadWAUser(ctx, tx, p.User.ID, false)
		if err != nil {
			return err
		}
		cred, err := s.wa.CreateCredential(u, sd, parsed)
		if err != nil {
			return &ValidationError{Field: "passkey", Message: "was not accepted: " + err.Error()}
		}
		if !cred.Flags.UserVerified {
			return &ValidationError{Field: "passkey", Message: "needs user verification (PIN or biometrics)"}
		}
		raw, _ := json.Marshal(cred)
		res, err := tx.ExecContext(ctx, `INSERT INTO user_passkeys (user_id, credential_id, name, credential, created_ms) VALUES (?, ?, ?, ?, ?)`,
			p.User.ID, cred.ID, name, string(raw), s.nowMS())
		if err != nil {
			return err
		}
		info.ID, _ = res.LastInsertId()
		info.Name, info.CreatedAt = name, fromMS(s.nowMS())
		s.dropChallenge(ctx, tx, tok)
		if err := s.factorAdded(ctx, tx, p); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "auth.passkey_add", targetUser(p.User.ID), audit.Success), "name", name))
		return err
	})
	return info, err
}

// DeletePasskey removes a passkey (step-up required).
func (s *Service) DeletePasskey(ctx context.Context, p *Principal, m Meta, id int64) error {
	if err := s.RequireStepUp(p); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var n, totp int
		if err := tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?), (SELECT COUNT(*) FROM user_totp WHERE user_id = ? AND confirmed = 1)`,
			p.User.ID, p.User.ID).Scan(&n, &totp); err != nil {
			return err
		}
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM user_passkeys WHERE id = ? AND user_id = ?`, id, p.User.ID).Scan(&name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if err := s.ensureFactorsLeft(ctx, tx, p.User.ID, totp == 1, n-1); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_passkeys WHERE id = ?`, id); err != nil {
			return err
		}
		if n-1 == 0 && totp == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, p.User.ID); err != nil {
				return err
			}
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "auth.passkey_remove", targetUser(p.User.ID), audit.Success), "name", name))
		return err
	})
}

// saveUse stores the updated sign counter after a successful assertion.
func (s *Service) saveUse(ctx context.Context, cred *webauthn.Credential) error {
	raw, _ := json.Marshal(cred)
	_, err := s.db.ExecContext(ctx, `UPDATE user_passkeys SET credential = ?, last_used_ms = ? WHERE credential_id = ?`, string(raw), s.nowMS(), cred.ID)
	return err
}

// BeginPasskeyLogin starts a usernameless sign-in with a passkey.
func (s *Service) BeginPasskeyLogin(ctx context.Context, m Meta) (Ceremony, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return Ceremony{}, &RateLimitError{RetryAfter: wait}
	}
	opts, sd, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return Ceremony{}, err
	}
	tok, err := s.newChallenge(ctx, s.db, 0, challengePasskey, encodeSession(sd))
	return Ceremony{Token: tok, Options: opts}, err
}

func (s *Service) passkeyFailure(ctx context.Context, m Meta, userID int64, name, reason string) error {
	s.record(ctx, withDetails(audit.Event{ActorID: userID, Actor: name, Action: "auth.login", Target: targetUser(userID),
		Result: audit.Failure, RequestID: m.RequestID, IP: m.IP}, "method", "passkey", "reason", reason))
	return ErrInvalidCredentials
}

// FinishPasskeyLogin signs in with a passkey alone; it counts as MFA.
func (s *Service) FinishPasskeyLogin(ctx context.Context, m Meta, tok string, response []byte) (LoginResult, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return LoginResult{}, &RateLimitError{RetryAfter: wait}
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(response))
	if err != nil {
		return LoginResult{}, s.passkeyFailure(ctx, m, 0, "", "unreadable response")
	}
	var sd webauthn.SessionData
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		_, data, err := s.challenge(ctx, tx, tok, challengePasskey)
		if err != nil {
			return err
		}
		sd, err = decodeSession(data)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	var user *waUser
	cred, err := s.wa.ValidateDiscoverableLogin(func(_, handle []byte) (webauthn.User, error) {
		var id int64
		if err := s.db.QueryRowContext(ctx, `SELECT id FROM users WHERE webauthn_id = ?`, handle).Scan(&id); err != nil {
			return nil, ErrInvalidCredentials
		}
		u, err := s.loadWAUser(ctx, s.db, id, false)
		user = u
		return u, err
	}, sd, parsed)
	if err != nil || user == nil {
		return LoginResult{}, s.passkeyFailure(ctx, m, 0, "", "assertion rejected")
	}
	return s.finishPasskeySignIn(ctx, m, tok, user, cred)
}

func (s *Service) finishPasskeySignIn(ctx context.Context, m Meta, tok string, user *waUser, cred *webauthn.Credential) (LoginResult, error) {
	if cred.Authenticator.CloneWarning {
		return LoginResult{}, s.passkeyFailure(ctx, m, user.id, user.name, "signature counter went backwards (cloned authenticator?)")
	}
	u, err := s.getUser(ctx, s.db, user.id)
	if err != nil {
		return LoginResult{}, err
	}
	var locked int64
	_ = s.db.QueryRowContext(ctx, `SELECT locked_until_ms FROM users WHERE id = ?`, user.id).Scan(&locked)
	if u.Disabled || locked > s.nowMS() {
		return LoginResult{}, s.passkeyFailure(ctx, m, user.id, user.name, "account disabled or locked")
	}
	if err := s.saveUse(ctx, cred); err != nil {
		return LoginResult{}, err
	}
	s.dropChallenge(ctx, s.db, tok)
	return s.startSession(ctx, m, user.id, user.name, sessionKind{mfa: true}, "passkey")
}

// BeginMFAPasskey offers the passkeys of the account behind an MFA
// challenge as its second factor.
func (s *Service) BeginMFAPasskey(ctx context.Context, m Meta, mfaToken string) (Ceremony, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return Ceremony{}, &RateLimitError{RetryAfter: wait}
	}
	var c Ceremony
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		uid, _, err := s.challenge(ctx, tx, mfaToken, challengeMFA)
		if err != nil {
			return err
		}
		u, err := s.loadWAUser(ctx, tx, uid, false)
		if err != nil {
			return err
		}
		if len(u.creds) == 0 {
			return ErrChallenge
		}
		opts, sd, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
		if err != nil {
			return err
		}
		c.Options = opts
		c.Token, err = s.newChallenge(ctx, tx, uid, challengeMFAKey, encodeSession(sd))
		return err
	})
	return c, err
}

// FinishMFAPasskey completes a password sign-in with a passkey.
func (s *Service) FinishMFAPasskey(ctx context.Context, m Meta, mfaToken, tok string, response []byte) (LoginResult, error) {
	user, cred, err := s.assertion(ctx, m, tok, challengeMFAKey, 0, response)
	if err != nil {
		return LoginResult{}, err
	}
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		uid, _, err := s.challenge(ctx, tx, mfaToken, challengeMFA)
		if err == nil && uid != user.id {
			err = ErrChallenge
		}
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	s.dropChallenge(ctx, s.db, mfaToken)
	return s.finishPasskeySignIn(ctx, m, tok, user, cred)
}

// assertion verifies a passkey assertion for the user bound to the
// challenge (wantUser > 0 additionally requires that user).
func (s *Service) assertion(ctx context.Context, m Meta, tok, kind string, wantUser int64, response []byte) (*waUser, *webauthn.Credential, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return nil, nil, &RateLimitError{RetryAfter: wait}
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(response))
	if err != nil {
		return nil, nil, ErrInvalidCredentials
	}
	var uid int64
	var sd webauthn.SessionData
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var data string
		var err error
		if uid, data, err = s.challenge(ctx, tx, tok, kind); err != nil {
			return err
		}
		if wantUser > 0 && uid != wantUser {
			return ErrChallenge
		}
		sd, err = decodeSession(data)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	u, err := s.loadWAUser(ctx, s.db, uid, false)
	if err != nil {
		return nil, nil, err
	}
	cred, err := s.wa.ValidateLogin(u, sd, parsed)
	if err != nil {
		return nil, nil, s.passkeyFailure(ctx, m, uid, u.name, "assertion rejected")
	}
	return u, cred, nil
}

// BeginStepUpPasskey starts a step-up with one of the user's passkeys.
func (s *Service) BeginStepUpPasskey(ctx context.Context, p *Principal) (Ceremony, error) {
	u, err := s.loadWAUser(ctx, s.db, p.User.ID, false)
	if err != nil {
		return Ceremony{}, err
	}
	if len(u.creds) == 0 {
		return Ceremony{}, &ValidationError{Field: "passkey", Message: "none registered"}
	}
	opts, sd, err := s.wa.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return Ceremony{}, err
	}
	tok, err := s.newChallenge(ctx, s.db, p.User.ID, challengeStepUpKey, encodeSession(sd))
	return Ceremony{Token: tok, Options: opts}, err
}

// FinishStepUpPasskey completes a step-up with a passkey.
func (s *Service) FinishStepUpPasskey(ctx context.Context, p *Principal, m Meta, tok string, response []byte) error {
	_, cred, err := s.assertion(ctx, m, tok, challengeStepUpKey, p.User.ID, response)
	if err != nil {
		return err
	}
	if cred.Authenticator.CloneWarning {
		return s.passkeyFailure(ctx, m, p.User.ID, p.User.Username, "signature counter went backwards")
	}
	if err := s.saveUse(ctx, cred); err != nil {
		return err
	}
	s.dropChallenge(ctx, s.db, tok)
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if err := s.markStepUp(ctx, tx, p, true); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "auth.step_up", targetUser(p.User.ID), audit.Success), "method", "passkey"))
		return err
	})
}
