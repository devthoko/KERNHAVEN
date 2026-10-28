package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

// LoginResult is either a session (Token and Principal) or, for accounts with
// a second factor, an MFA challenge (MFAToken and Methods, M11).
type LoginResult struct {
	Token     string
	Principal *Principal
	MFAToken  string
	Methods   []string
}

// Login verifies the password. Without a second factor it creates a session;
// the raw session token is only ever sent to the client in the cookie.
func (s *Service) Login(ctx context.Context, m Meta, username, password string) (LoginResult, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		s.record(ctx, withDetails(audit.Event{Actor: username, Action: "auth.login", Target: "user:" + username,
			Result: audit.Denied, RequestID: m.RequestID, IP: m.IP}, "reason", "rate limited"))
		return LoginResult{}, &RateLimitError{RetryAfter: wait}
	}

	fail := func(reason string, userID int64) (LoginResult, error) {
		s.record(ctx, withDetails(audit.Event{ActorID: userID, Actor: username, Action: "auth.login", Target: "user:" + username,
			Result: audit.Failure, RequestID: m.RequestID, IP: m.IP}, "reason", reason))
		return LoginResult{}, ErrInvalidCredentials
	}

	var (
		id                        int64
		hash                      string
		disabled, failed, pwLogin int
		lockedUntil               int64
		role                      authz.Role
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, password_hash, disabled, failed_logins, locked_until_ms, password_login, role FROM users WHERE username = ?`,
		username).Scan(&id, &hash, &disabled, &failed, &lockedUntil, &pwLogin, &role)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = s.verify(ctx, s.dummyHash, password) // uniform timing
		return fail("unknown user", 0)
	}
	if err != nil {
		return LoginResult{}, err
	}
	if lockedUntil > s.nowMS() {
		_, _ = s.verify(ctx, s.dummyHash, password)
		return fail("account locked", id)
	}
	ok, err := s.verify(ctx, hash, password)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok {
		if err := s.registerFailure(ctx, m, id, username); err != nil {
			return LoginResult{}, err
		}
		return fail("wrong password", id)
	}
	if disabled == 1 {
		return fail("account disabled", id)
	}
	if pwLogin == 0 {
		return fail("password sign-in is off (passkey-only account)", id)
	}

	// Accounts with a second factor get a challenge instead of a session.
	methods, err := s.methods(ctx, s.db, id)
	if err != nil {
		return LoginResult{}, err
	}
	if len(methods) > 0 {
		tok, err := s.newChallenge(ctx, s.db, id, challengeMFA, "")
		if err != nil {
			return LoginResult{}, err
		}
		s.record(ctx, withDetails(audit.Event{ActorID: id, Actor: username, Action: "auth.login", Target: targetUser(id),
			Result: audit.Success, RequestID: m.RequestID, IP: m.IP}, "stage", "password", "next", strings.Join(methods, ",")))
		return LoginResult{MFAToken: tok, Methods: methods}, nil
	}
	required, err := s.mfaRequired(ctx, s.db, role)
	if err != nil {
		return LoginResult{}, err
	}
	return s.startSession(ctx, m, id, username, sessionKind{enrollmentOnly: required}, "password")
}

// startSession creates a session after a successful sign-in and audits it.
func (s *Service) startSession(ctx context.Context, m Meta, id int64, username string, kind sessionKind, method string) (LoginResult, error) {
	var token string
	var p *Principal
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins = 0, locked_until_ms = 0 WHERE id = ?`, id); err != nil {
			return err
		}
		var sess Session
		var err error
		token, sess, err = s.createSession(ctx, tx, id, m, kind)
		if err != nil {
			return err
		}
		u, err := s.getUser(ctx, tx, id)
		if err != nil {
			return err
		}
		p = &Principal{User: u, Session: sess}
		_, err = audit.Append(ctx, tx, s.now(), withDetails(audit.Event{ActorID: id, Actor: username, Action: "auth.login",
			Target: targetUser(id), Result: audit.Success, RequestID: m.RequestID, IP: m.IP},
			"session", sess.ID, "method", method, "enrollment_only", boolString(kind.enrollmentOnly)))
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	return LoginResult{Token: token, Principal: p}, nil
}

// registerFailure counts a failed password and locks the account with
// exponential backoff once the threshold is reached.
func (s *Service) registerFailure(ctx context.Context, m Meta, id int64, username string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var failed int
		if err := tx.QueryRowContext(ctx, `UPDATE users SET failed_logins = failed_logins + 1 WHERE id = ? RETURNING failed_logins`, id).Scan(&failed); err != nil {
			return err
		}
		if failed < lockoutThreshold {
			return nil
		}
		d := lockoutBase << min(failed-lockoutThreshold, 6)
		if d > lockoutMax {
			d = lockoutMax
		}
		until := s.now().Add(d)
		if _, err := tx.ExecContext(ctx, `UPDATE users SET locked_until_ms = ? WHERE id = ?`, ms(until), id); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(audit.Event{ActorID: id, Actor: username, Action: "auth.lockout",
			Target: targetUser(id), Result: audit.Success, RequestID: m.RequestID, IP: m.IP},
			"failed_logins", itoa(int64(failed)), "locked_for", d.String()))
		return err
	})
}

// sessionKind describes how a session was established.
type sessionKind struct {
	mfa            bool // a second factor or passkey was verified
	enrollmentOnly bool // MFA required by policy but not enrolled
}

func (s *Service) createSession(ctx context.Context, tx *sql.Tx, userID int64, m Meta, kind sessionKind) (string, Session, error) {
	now := s.now()
	token := randomToken(32)
	sess := Session{
		ID:                randomHex(16),
		UserID:            userID,
		CSRFToken:         randomToken(32),
		CreatedAt:         now.UTC().Truncate(time.Millisecond),
		LastSeenAt:        now.UTC().Truncate(time.Millisecond),
		AbsoluteExpiresAt: now.Add(s.cfg.AbsoluteTimeout).UTC().Truncate(time.Millisecond),
		IP:                m.IP,
		UserAgent:         truncateString(m.UserAgent, 256),
	}
	sess.IdleExpiresAt = minTime(now.Add(s.cfg.IdleTimeout), sess.AbsoluteExpiresAt).UTC().Truncate(time.Millisecond)
	// Signing in is a strong authentication: it opens the step-up window.
	sess.StepUpAt, sess.EnrollmentOnly = sess.CreatedAt, kind.enrollmentOnly
	var mfaMS int64
	if kind.mfa {
		sess.MFAAt, mfaMS = sess.CreatedAt, ms(sess.CreatedAt)
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO sessions
		(id, token_hash, user_id, csrf_token, created_ms, last_seen_ms, idle_expires_ms, absolute_expires_ms, ip, user_agent, mfa_ms, step_up_ms, enrollment_only)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sha256Hex(token), userID, sess.CSRFToken, ms(sess.CreatedAt), ms(sess.LastSeenAt),
		ms(sess.IdleExpiresAt), ms(sess.AbsoluteExpiresAt), sess.IP, sess.UserAgent, mfaMS, ms(sess.StepUpAt), boolInt(kind.enrollmentOnly))
	return token, sess, err
}

const sessionColumns = `s.id, s.user_id, s.csrf_token, s.created_ms, s.last_seen_ms, s.idle_expires_ms, s.absolute_expires_ms, s.ip, s.user_agent,
	s.mfa_ms, s.step_up_ms, s.enrollment_only`

func scanSession(row rowScanner) (Session, error) {
	var sess Session
	var created, seen, idle, abs, mfa, stepUp int64
	var enrol int
	err := row.Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &created, &seen, &idle, &abs, &sess.IP, &sess.UserAgent, &mfa, &stepUp, &enrol)
	if mfa > 0 {
		sess.MFAAt = fromMS(mfa)
	}
	sess.StepUpAt, sess.EnrollmentOnly = fromMS(stepUp), enrol == 1
	sess.CreatedAt, sess.LastSeenAt, sess.IdleExpiresAt, sess.AbsoluteExpiresAt = fromMS(created), fromMS(seen), fromMS(idle), fromMS(abs)
	return sess, err
}

// Authenticate resolves a session token to a principal, enforcing idle and
// absolute expiry and the user's disabled flag.
func (s *Service) Authenticate(ctx context.Context, token string) (*Principal, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrUnauthenticated
	}
	sess, err := scanSession(s.db.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions s WHERE s.token_hash = ?`, sha256Hex(token)))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	now := s.now()
	if !now.Before(sess.IdleExpiresAt) || !now.Before(sess.AbsoluteExpiresAt) {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, sess.ID); err != nil {
			return nil, err
		}
		return nil, ErrUnauthenticated
	}
	u, err := s.getUser(ctx, s.db, sess.UserID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrUnauthenticated
		}
		return nil, err
	}
	if u.Disabled {
		return nil, ErrUnauthenticated
	}
	if now.Sub(sess.LastSeenAt) >= lastSeenGranularity {
		sess.LastSeenAt = now.UTC().Truncate(time.Millisecond)
		sess.IdleExpiresAt = minTime(now.Add(s.cfg.IdleTimeout), sess.AbsoluteExpiresAt).UTC().Truncate(time.Millisecond)
		if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_ms = ?, idle_expires_ms = ? WHERE id = ?`,
			ms(sess.LastSeenAt), ms(sess.IdleExpiresAt), sess.ID); err != nil {
			return nil, err
		}
	}
	return &Principal{User: u, Session: sess}, nil
}

// CheckCSRF compares the request token with the session's (constant time).
func (p *Principal) CheckCSRF(token string) bool {
	return token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(p.Session.CSRFToken)) == 1
}

// Logout ends p's current session.
func (s *Service) Logout(ctx context.Context, p *Principal, m Meta) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, p.Session.ID); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), actorEvent(p, m, "auth.logout", targetSession(p.Session.ID), audit.Success))
		return err
	})
}

// ListSessions returns the active sessions of p's user.
func (s *Service) ListSessions(ctx context.Context, p *Principal) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessionColumns+` FROM sessions s
		WHERE s.user_id = ? AND s.idle_expires_ms > ? AND s.absolute_expires_ms > ? ORDER BY s.created_ms DESC`,
		p.User.ID, s.nowMS(), s.nowMS())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// RevokeSession ends session id. Users may revoke their own sessions; others'
// sessions need sessions.manage. Foreign sessions are reported as not found
// to callers without that permission.
func (s *Service) RevokeSession(ctx context.Context, p *Principal, m Meta, id string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var owner int64
		err := tx.QueryRowContext(ctx, `SELECT user_id FROM sessions WHERE id = ?`, id).Scan(&owner)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if owner != p.User.ID && !p.Has(authz.SessionsManage) {
			return ErrNotFound
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "session.revoke", targetSession(id), audit.Success),
			"session_user", targetUser(owner)))
		return err
	})
}

// PurgeExpiredSessions deletes expired sessions and returns how many.
func (s *Service) PurgeExpiredSessions(ctx context.Context) (int64, error) {
	now := s.nowMS()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE idle_expires_ms <= ? OR absolute_expires_ms <= ?`, now, now)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func truncateString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
