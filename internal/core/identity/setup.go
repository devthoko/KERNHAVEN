package identity

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

// SetupRequired reports whether no user exists yet.
func (s *Service) SetupRequired(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n == 0, err
}

// PrepareSetup creates a fresh one-time setup token while no user exists and
// returns it (AT-F08-01). Once users exist it removes any leftover token and
// returns "".
func (s *Service) PrepareSetup(ctx context.Context) (string, error) {
	var token string
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			_, err := tx.ExecContext(ctx, `DELETE FROM setup_token`)
			return err
		}
		token = randomToken(24)
		_, err := tx.ExecContext(ctx, `INSERT INTO setup_token (id, token_hash, expires_ms) VALUES (1, ?, ?)
			ON CONFLICT (id) DO UPDATE SET token_hash = excluded.token_hash, expires_ms = excluded.expires_ms`,
			sha256Hex(token), ms(s.now().Add(s.cfg.SetupTokenTTL)))
		return err
	})
	return token, err
}

// SetupInput creates the first owner.
type SetupInput struct {
	Token       string `json:"token"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// CompleteSetup validates the setup token, creates the first owner and logs
// them in.
func (s *Service) CompleteSetup(ctx context.Context, m Meta, in SetupInput) (string, *Principal, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return "", nil, &RateLimitError{RetryAfter: wait}
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := validateUsername(in.Username); err != nil {
		return "", nil, err
	}
	if err := validateDisplayName(in.DisplayName); err != nil {
		return "", nil, err
	}
	if err := CheckPasswordPolicy(in.Username, in.Password); err != nil {
		return "", nil, err
	}
	hash, err := s.hash(ctx, in.Password)
	if err != nil {
		return "", nil, err
	}

	var token string
	var p *Principal
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrSetupClosed
		}
		var stored string
		var expires int64
		err := tx.QueryRowContext(ctx, `SELECT token_hash, expires_ms FROM setup_token WHERE id = 1`).Scan(&stored, &expires)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidSetupToken
		}
		if err != nil {
			return err
		}
		if subtle.ConstantTimeCompare([]byte(sha256Hex(in.Token)), []byte(stored)) != 1 || expires <= s.nowMS() {
			return ErrInvalidSetupToken
		}
		u, err := s.insertUser(ctx, tx, CreateUserInput{Username: in.Username, DisplayName: in.DisplayName, Role: authz.Owner}, hash)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM setup_token`); err != nil {
			return err
		}
		var sess Session
		token, sess, err = s.createSession(ctx, tx, u.ID, m)
		if err != nil {
			return err
		}
		p = &Principal{User: u, Session: sess}
		_, err = audit.Append(ctx, tx, s.now(), audit.Event{ActorID: u.ID, Actor: u.Username, Action: "auth.setup",
			Target: targetUser(u.ID), Result: audit.Success, RequestID: m.RequestID, IP: m.IP})
		return err
	})
	if errors.Is(err, ErrInvalidSetupToken) || errors.Is(err, ErrSetupClosed) {
		s.record(ctx, withDetails(audit.Event{Actor: in.Username, Action: "auth.setup", Target: "setup",
			Result: audit.Failure, RequestID: m.RequestID, IP: m.IP}, "reason", err.Error()))
	}
	if err != nil {
		return "", nil, err
	}
	return token, p, nil
}
