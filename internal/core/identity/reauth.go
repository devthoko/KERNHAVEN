package identity

import (
	"context"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
)

// Reauthenticate confirms a destructive action with the user's current
// password (AT-F05-03). Failures count towards the account lockout like failed
// logins and are rate-limited per IP. action and target describe what is being
// confirmed for the audit log. Step-up with passkeys replaces this in M11.
func (s *Service) Reauthenticate(ctx context.Context, p *Principal, m Meta, password, action, target string) error {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		s.record(ctx, withDetails(actorEvent(p, m, "auth.reauth", target, audit.Denied), "reason", "rate limited", "for", action))
		return &RateLimitError{RetryAfter: wait}
	}
	var hash string
	var lockedUntil int64
	if err := s.db.QueryRowContext(ctx, `SELECT password_hash, locked_until_ms FROM users WHERE id = ?`, p.User.ID).Scan(&hash, &lockedUntil); err != nil {
		return err
	}
	if lockedUntil > s.nowMS() {
		_, _ = s.verify(ctx, s.dummyHash, password)
		s.record(ctx, withDetails(actorEvent(p, m, "auth.reauth", target, audit.Failure), "reason", "account locked", "for", action))
		return ErrInvalidCredentials
	}
	ok, err := s.verify(ctx, hash, password)
	if err != nil {
		return err
	}
	if !ok {
		if err := s.registerFailure(ctx, m, p.User.ID, p.User.Username); err != nil {
			return err
		}
		s.record(ctx, withDetails(actorEvent(p, m, "auth.reauth", target, audit.Failure), "reason", "wrong password", "for", action))
		return ErrInvalidCredentials
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET failed_logins = 0 WHERE id = ?`, p.User.ID); err != nil {
		return err
	}
	s.record(ctx, withDetails(actorEvent(p, m, "auth.reauth", target, audit.Success), "for", action))
	return nil
}
