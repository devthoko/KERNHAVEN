package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

// Login verifies credentials and creates a new session. It returns the raw
// session token, which is only ever sent to the client in the cookie.
func (s *Service) Login(ctx context.Context, m Meta, username, password string) (string, *Principal, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		s.record(ctx, withDetails(audit.Event{Actor: username, Action: "auth.login", Target: "user:" + username,
			Result: audit.Denied, RequestID: m.RequestID, IP: m.IP}, "reason", "rate limited"))
		return "", nil, &RateLimitError{RetryAfter: wait}
	}

	fail := func(reason string, userID int64) (string, *Principal, error) {
		s.record(ctx, withDetails(audit.Event{ActorID: userID, Actor: username, Action: "auth.login", Target: "user:" + username,
			Result: audit.Failure, RequestID: m.RequestID, IP: m.IP}, "reason", reason))
		return "", nil, ErrInvalidCredentials
	}

	var (
		id               int64
		hash             string
		disabled, failed int
		lockedUntil      int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT id, password_hash, disabled, failed_logins, locked_until_ms FROM users WHERE username = ?`,
		username).Scan(&id, &hash, &disabled, &failed, &lockedUntil)
	if errors.Is(err, sql.ErrNoRows) {
		_, _ = s.verify(ctx, s.dummyHash, password) // uniform timing
		return fail("unknown user", 0)
	}
	if err != nil {
		return "", nil, err
	}
	if lockedUntil > s.nowMS() {
		_, _ = s.verify(ctx, s.dummyHash, password)
		return fail("account locked", id)
	}
	ok, err := s.verify(ctx, hash, password)
	if err != nil {
		return "", nil, err
	}
	if !ok {
		if err := s.registerFailure(ctx, m, id, username); err != nil {
			return "", nil, err
		}
		return fail("wrong password", id)
	}
	if disabled == 1 {
		return fail("account disabled", id)
	}

	var token string
	var p *Principal
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET failed_logins = 0, locked_until_ms = 0 WHERE id = ?`, id); err != nil {
			return err
		}
		var sess Session
		token, sess, err = s.createSession(ctx, tx, id, m)
		if err != nil {
			return err
		}
		u, err := s.getUser(ctx, tx, id)
		if err != nil {
			return err
		}
		p = &Principal{User: u, Session: sess}
		_, err = audit.Append(ctx, tx, s.now(), withDetails(audit.Event{ActorID: id, Actor: username, Action: "auth.login",
			Target: targetUser(id), Result: audit.Success, RequestID: m.RequestID, IP: m.IP}, "session", sess.ID))
		return err
	})
	if err != nil {
		return "", nil, err
	}
	return token, p, nil
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

func (s *Service) createSession(ctx context.Context, tx *sql.Tx, userID int64, m Meta) (string, Session, error) {
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
	_, err := tx.ExecContext(ctx, `INSERT INTO sessions
		(id, token_hash, user_id, csrf_token, created_ms, last_seen_ms, idle_expires_ms, absolute_expires_ms, ip, user_agent)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sess.ID, sha256Hex(token), userID, sess.CSRFToken, ms(sess.CreatedAt), ms(sess.LastSeenAt),
		ms(sess.IdleExpiresAt), ms(sess.AbsoluteExpiresAt), sess.IP, sess.UserAgent)
	return token, sess, err
}

const sessionColumns = `s.id, s.user_id, s.csrf_token, s.created_ms, s.last_seen_ms, s.idle_expires_ms, s.absolute_expires_ms, s.ip, s.user_agent`

func scanSession(row rowScanner) (Session, error) {
	var sess Session
	var created, seen, idle, abs int64
	err := row.Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &created, &seen, &idle, &abs, &sess.IP, &sess.UserAgent)
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
