package identity

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,31}$`)

func validateUsername(u string) error {
	if !usernamePattern.MatchString(u) {
		return &ValidationError{Field: "username", Message: "must be 3-32 characters: lowercase letters, digits, '.', '_' or '-', starting with a letter or digit"}
	}
	return nil
}

func validateDisplayName(n string) error {
	if !utf8.ValidString(n) || utf8.RuneCountInString(n) > 64 {
		return &ValidationError{Field: "display_name", Message: "must be at most 64 characters"}
	}
	for _, r := range n {
		if unicode.IsControl(r) {
			return &ValidationError{Field: "display_name", Message: "must not contain control characters"}
		}
	}
	return nil
}

const userColumns = `id, username, display_name, role, disabled, locked_until_ms, created_ms, updated_ms`

type rowScanner interface{ Scan(dest ...any) error }

func (s *Service) scanUser(row rowScanner) (User, error) {
	var u User
	var role string
	var disabled int
	var lockedUntil, created, updated int64
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &role, &disabled, &lockedUntil, &created, &updated); err != nil {
		return User{}, err
	}
	u.Role = authz.Role(role)
	u.Disabled = disabled == 1
	u.Locked = lockedUntil > s.nowMS()
	u.CreatedAt, u.UpdatedAt = fromMS(created), fromMS(updated)
	return u, nil
}

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Service) getUser(ctx context.Context, q querier, id int64) (User, error) {
	u, err := s.scanUser(q.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// ListUsers returns all users ordered by username.
func (s *Service) ListUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := s.scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// GetUser returns one user.
func (s *Service) GetUser(ctx context.Context, id int64) (User, error) {
	return s.getUser(ctx, s.db, id)
}

// CreateUserInput is the payload for CreateUser.
type CreateUserInput struct {
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Role        authz.Role `json:"role"`
	Password    string     `json:"password"`
}

// CreateUser creates an account on behalf of p.
func (s *Service) CreateUser(ctx context.Context, p *Principal, m Meta, in CreateUserInput) (User, error) {
	// Creating owners and admins is security-relevant (AT-F09-04).
	if in.Role == authz.Owner || in.Role == authz.Admin {
		if err := s.RequireStepUp(p); err != nil {
			return User{}, err
		}
	}
	in.Username = strings.TrimSpace(in.Username)
	if err := validateUsername(in.Username); err != nil {
		return User{}, err
	}
	if err := validateDisplayName(in.DisplayName); err != nil {
		return User{}, err
	}
	if !in.Role.Valid() {
		return User{}, &ValidationError{Field: "role", Message: "must be one of owner, admin, operator, viewer"}
	}
	if !authz.CanManage(p.User.Role, in.Role) {
		s.record(ctx, withDetails(actorEvent(p, m, "user.create", "user:"+in.Username, audit.Denied), "role", string(in.Role)))
		return User{}, ErrForbidden
	}
	if err := CheckPasswordPolicy(in.Username, in.Password); err != nil {
		return User{}, err
	}
	hash, err := s.hash(ctx, in.Password)
	if err != nil {
		return User{}, err
	}
	var u User
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		u, err = s.insertUser(ctx, tx, in, hash)
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "user.create", targetUser(u.ID), audit.Success),
			"username", u.Username, "role", string(u.Role)))
		return err
	})
	return u, err
}

func (s *Service) insertUser(ctx context.Context, tx *sql.Tx, in CreateUserInput, hash string) (User, error) {
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE username = ?`, in.Username).Scan(&exists); err != nil {
		return User{}, err
	}
	if exists > 0 {
		return User{}, ErrConflict
	}
	now := s.nowMS()
	res, err := tx.ExecContext(ctx, `INSERT INTO users (username, display_name, role, password_hash, created_ms, updated_ms)
		VALUES (?, ?, ?, ?, ?, ?)`, in.Username, in.DisplayName, string(in.Role), hash, now, now)
	if err != nil {
		return User{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return User{}, err
	}
	return s.getUser(ctx, tx, id)
}

// UpdateUserInput is a partial update; nil fields are unchanged.
type UpdateUserInput struct {
	DisplayName *string     `json:"display_name"`
	Role        *authz.Role `json:"role"`
	Disabled    *bool       `json:"disabled"`
}

// UpdateUser changes display name, role or disabled state of user id.
func (s *Service) UpdateUser(ctx context.Context, p *Principal, m Meta, id int64, in UpdateUserInput) (User, error) {
	if in.Role != nil || in.Disabled != nil {
		if err := s.RequireStepUp(p); err != nil {
			return User{}, err
		}
	}
	if in.DisplayName != nil {
		if err := validateDisplayName(*in.DisplayName); err != nil {
			return User{}, err
		}
	}
	if in.Role != nil && !in.Role.Valid() {
		return User{}, &ValidationError{Field: "role", Message: "must be one of owner, admin, operator, viewer"}
	}
	var out User
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		target, err := s.getUser(ctx, tx, id)
		if err != nil {
			return err
		}
		roleChange := in.Role != nil && *in.Role != target.Role
		disableChange := in.Disabled != nil && *in.Disabled != target.Disabled
		var newRole *authz.Role
		if roleChange {
			newRole = in.Role
		}
		if err := s.checkManage(ctx, tx, p, target, newRole, roleChange || disableChange, (roleChange && *in.Role != authz.Owner) || (disableChange && *in.Disabled)); err != nil {
			return err
		}

		details := []string{}
		if in.DisplayName != nil && *in.DisplayName != target.DisplayName {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name = ? WHERE id = ?`, *in.DisplayName, id); err != nil {
				return err
			}
			details = append(details, "display_name", *in.DisplayName)
		}
		if roleChange {
			if _, err := tx.ExecContext(ctx, `UPDATE users SET role = ? WHERE id = ?`, string(*in.Role), id); err != nil {
				return err
			}
			details = append(details, "role_from", string(target.Role), "role_to", string(*in.Role))
		}
		if disableChange {
			v := 0
			if *in.Disabled {
				v = 1
			}
			if _, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, v, id); err != nil {
				return err
			}
			details = append(details, "disabled", boolString(*in.Disabled))
		}
		if len(details) == 0 {
			out = target
			return nil
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET updated_ms = ? WHERE id = ?`, s.nowMS(), id); err != nil {
			return err
		}
		// Privilege change: end all sessions of the target (AT-F08-03).
		if roleChange || disableChange {
			if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
				return err
			}
			details = append(details, "sessions_revoked", "true")
		}
		if _, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "user.update", targetUser(id), audit.Success), details...)); err != nil {
			return err
		}
		out, err = s.getUser(ctx, tx, id)
		return err
	})
	s.recordDenial(ctx, p, m, "user.update", targetUser(id), err)
	return out, err
}

// checkManage enforces management rights, self protection and the last-owner
// rule. newRole is the role being assigned (nil if unchanged). sensitive is
// true for role or disabled changes; reducesOwner is true when the change
// could remove an enabled owner.
func (s *Service) checkManage(ctx context.Context, tx *sql.Tx, p *Principal, target User, newRole *authz.Role, sensitive, reducesOwner bool) error {
	if !authz.CanManage(p.User.Role, target.Role) && target.ID != p.User.ID {
		return ErrForbidden
	}
	if newRole != nil && !authz.CanManage(p.User.Role, *newRole) {
		return ErrForbidden
	}
	if sensitive && target.ID == p.User.ID {
		return ErrSelf
	}
	if reducesOwner && target.Role == authz.Owner && !target.Disabled {
		n, err := countEnabledOwners(ctx, tx)
		if err != nil {
			return err
		}
		if n <= 1 {
			return ErrLastOwner
		}
	}
	return nil
}

func countEnabledOwners(ctx context.Context, tx *sql.Tx) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'owner' AND disabled = 0`).Scan(&n)
	return n, err
}

// DeleteUser removes user id and its sessions.
func (s *Service) DeleteUser(ctx context.Context, p *Principal, m Meta, id int64) error {
	if err := s.RequireStepUp(p); err != nil {
		return err
	}
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		target, err := s.getUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if target.ID == p.User.ID {
			return ErrSelf
		}
		if err := s.checkManage(ctx, tx, p, target, nil, true, true); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "user.delete", targetUser(id), audit.Success),
			"username", target.Username, "role", string(target.Role)))
		return err
	})
	s.recordDenial(ctx, p, m, "user.delete", targetUser(id), err)
	return err
}

// ResetPassword sets a new password for another user and ends their sessions.
func (s *Service) ResetPassword(ctx context.Context, p *Principal, m Meta, id int64, password string) error {
	if err := s.RequireStepUp(p); err != nil {
		return err
	}
	target, err := s.GetUser(ctx, id)
	if err != nil {
		return err
	}
	if target.ID == p.User.ID {
		return &ValidationError{Field: "id", Message: "use the change-password endpoint for your own account"}
	}
	if !authz.CanManage(p.User.Role, target.Role) {
		s.record(ctx, actorEvent(p, m, "user.password_reset", targetUser(id), audit.Denied))
		return ErrForbidden
	}
	if err := CheckPasswordPolicy(target.Username, password); err != nil {
		return err
	}
	hash, err := s.hash(ctx, password)
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, failed_logins = 0, locked_until_ms = 0, updated_ms = ? WHERE id = ?`,
			hash, s.nowMS(), id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "user.password_reset", targetUser(id), audit.Success), "sessions_revoked", "true"))
		return err
	})
}

// ChangeOwnPassword changes p's password after verifying the current one and
// ends all of p's other sessions.
func (s *Service) ChangeOwnPassword(ctx context.Context, p *Principal, m Meta, current, next string) error {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return &RateLimitError{RetryAfter: wait}
	}
	var hash string
	if err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, p.User.ID).Scan(&hash); err != nil {
		return err
	}
	ok, err := s.verify(ctx, hash, current)
	if err != nil {
		return err
	}
	if !ok {
		s.record(ctx, withDetails(actorEvent(p, m, "auth.password_change", targetUser(p.User.ID), audit.Failure), "reason", "wrong current password"))
		return ErrInvalidCredentials
	}
	if err := CheckPasswordPolicy(p.User.Username, next); err != nil {
		return err
	}
	newHash, err := s.hash(ctx, next)
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash = ?, updated_ms = ? WHERE id = ?`, newHash, s.nowMS(), p.User.ID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ? AND id <> ?`, p.User.ID, p.Session.ID); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "auth.password_change", targetUser(p.User.ID), audit.Success), "other_sessions_revoked", "true"))
		return err
	})
}

func (s *Service) recordDenial(ctx context.Context, p *Principal, m Meta, action, target string, err error) {
	if errors.Is(err, ErrForbidden) || errors.Is(err, ErrSelf) || errors.Is(err, ErrLastOwner) {
		s.record(ctx, withDetails(actorEvent(p, m, action, target, audit.Denied), "reason", err.Error()))
	}
}

func withDetails(ev audit.Event, kv ...string) audit.Event {
	if len(kv) == 0 {
		return ev
	}
	if ev.Details == nil {
		ev.Details = map[string]string{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		ev.Details[kv[i]] = kv[i+1]
	}
	return ev
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
