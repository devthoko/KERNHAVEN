// Package stacks manages Compose stacks: revisions, encrypted variables,
// validation with the container policy and journaled deployments (M7).
package stacks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
)

// Errors.
var (
	ErrNotFound = errors.New("stack not found")
	ErrExists   = errors.New("a stack with this name already exists")
	ErrDeployed = errors.New("the stack is deployed; take it down first")
	// ErrManaged protects the stacks of installed apps from direct changes.
	ErrManaged = errors.New("this stack belongs to an installed app; change it on the app's page")
)

// Stack is the API view of a stack.
type Stack struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	LatestRevision   int       `json:"latest_revision"`
	DeployedRevision int       `json:"deployed_revision"`
	Status           string    `json:"status"`
	StatusMessage    string    `json:"status_message,omitempty"`
	ManagedBy        string    `json:"managed_by"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Exception is an owner-approved policy exception for one service.
type Exception struct {
	Service    string `json:"service"`
	Rule       string `json:"rule"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by,omitempty"`
}

// Revision is one immutable version of a stack's Compose file.
type Revision struct {
	Number     int         `json:"number"`
	Compose    string      `json:"compose,omitempty"`
	Comment    string      `json:"comment"`
	Exceptions []Exception `json:"exceptions"`
	CreatedBy  string      `json:"created_by"`
	CreatedAt  time.Time   `json:"created_at"`
}

// Variable is a stack variable. Value is empty for secrets in API output.
type Variable struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Secret bool   `json:"secret"`
}

var varNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

type store struct {
	db  *sql.DB
	box *secretbox.Box
	now func() time.Time
}

func (st *store) nowMS() int64 { return st.now().UnixMilli() }

const stackCols = `id, name, latest_revision, deployed_revision, status, status_message, managed_by, created_ms, updated_ms`

func scanStack(row interface{ Scan(...any) error }) (Stack, error) {
	var s Stack
	var c, u int64
	err := row.Scan(&s.ID, &s.Name, &s.LatestRevision, &s.DeployedRevision, &s.Status, &s.StatusMessage, &s.ManagedBy, &c, &u)
	s.CreatedAt, s.UpdatedAt = time.UnixMilli(c).UTC(), time.UnixMilli(u).UTC()
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrNotFound
	}
	return s, err
}

type querier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

func (st *store) list(ctx context.Context) ([]Stack, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT `+stackCols+` FROM stacks ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Stack{}
	for rows.Next() {
		s, err := scanStack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (st *store) byName(ctx context.Context, q querier, name string) (Stack, error) {
	return scanStack(q.QueryRowContext(ctx, `SELECT `+stackCols+` FROM stacks WHERE name = ?`, name))
}

func (st *store) byID(ctx context.Context, q querier, id int64) (Stack, error) {
	return scanStack(q.QueryRowContext(ctx, `SELECT `+stackCols+` FROM stacks WHERE id = ?`, id))
}

func (st *store) setStatus(ctx context.Context, id int64, status, msg string, deployed *int) error {
	q := `UPDATE stacks SET status = ?, status_message = ?, updated_ms = ?`
	args := []any{status, msg, st.nowMS()}
	if deployed != nil {
		q += `, deployed_revision = ?`
		args = append(args, *deployed)
	}
	_, err := st.db.ExecContext(ctx, q+` WHERE id = ?`, append(args, id)...)
	return err
}

func (st *store) revision(ctx context.Context, q querier, stackID int64, n int) (Revision, error) {
	var r Revision
	var exc string
	var created int64
	err := q.QueryRowContext(ctx, `SELECT number, compose, comment, exceptions, created_by_name, created_ms
		FROM stack_revisions WHERE stack_id = ? AND number = ?`, stackID, n).
		Scan(&r.Number, &r.Compose, &r.Comment, &exc, &r.CreatedBy, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.CreatedAt = time.UnixMilli(created).UTC()
	if err := json.Unmarshal([]byte(exc), &r.Exceptions); err != nil {
		return r, fmt.Errorf("revision exceptions: %w", err)
	}
	return r, nil
}

func (st *store) revisions(ctx context.Context, stackID int64) ([]Revision, error) {
	rows, err := st.db.QueryContext(ctx, `SELECT number, comment, exceptions, created_by_name, created_ms
		FROM stack_revisions WHERE stack_id = ? ORDER BY number DESC`, stackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Revision{}
	for rows.Next() {
		var r Revision
		var exc string
		var created int64
		if err := rows.Scan(&r.Number, &r.Comment, &exc, &r.CreatedBy, &created); err != nil {
			return nil, err
		}
		r.CreatedAt = time.UnixMilli(created).UTC()
		_ = json.Unmarshal([]byte(exc), &r.Exceptions)
		out = append(out, r)
	}
	return out, rows.Err()
}

func varContext(stackID int64, name string) string {
	return fmt.Sprintf("stack:%d/var:%s", stackID, name)
}

// variables returns decrypted variables (secrets included; never send to clients).
func (st *store) variables(ctx context.Context, q querier, stackID int64) ([]Variable, error) {
	rows, err := q.QueryContext(ctx, `SELECT name, secret, value FROM stack_variables WHERE stack_id = ? ORDER BY name`, stackID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Variable{}
	for rows.Next() {
		var v Variable
		var secret int
		var ct []byte
		if err := rows.Scan(&v.Name, &secret, &ct); err != nil {
			return nil, err
		}
		v.Secret = secret == 1
		if v.Value, err = st.box.Open(ct, varContext(stackID, v.Name)); err != nil {
			return nil, fmt.Errorf("variable %s: %w", v.Name, err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// replaceVariables stores vars; a secret without a value keeps its stored value.
func (st *store) replaceVariables(ctx context.Context, tx *sql.Tx, stackID int64, vars []VariableInput) error {
	current, err := st.variables(ctx, tx, stackID)
	if err != nil {
		return err
	}
	old := map[string]Variable{}
	for _, v := range current {
		old[v.Name] = v
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM stack_variables WHERE stack_id = ?`, stackID); err != nil {
		return err
	}
	for _, v := range vars {
		value := v.Value
		if v.Secret && v.Value == nil {
			prev, ok := old[v.Name]
			if !ok || !prev.Secret {
				return &ValidationError{Message: fmt.Sprintf("secret %s has no value", v.Name)}
			}
			value = &prev.Value
		}
		if value == nil {
			return &ValidationError{Message: fmt.Sprintf("variable %s has no value", v.Name)}
		}
		ct, err := st.box.Seal(*value, varContext(stackID, v.Name))
		if err != nil {
			return err
		}
		secret := 0
		if v.Secret {
			secret = 1
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO stack_variables (stack_id, name, secret, value, updated_ms) VALUES (?, ?, ?, ?, ?)`,
			stackID, v.Name, secret, ct, st.nowMS()); err != nil {
			return err
		}
	}
	return nil
}

// VariableInput is a variable in a request; Value nil keeps a stored secret.
type VariableInput struct {
	Name   string  `json:"name"`
	Value  *string `json:"value"`
	Secret bool    `json:"secret"`
}

// ValidationError is a client error.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

func validateVariables(vars []VariableInput) error {
	if len(vars) > 128 {
		return &ValidationError{"at most 128 variables"}
	}
	seen := map[string]bool{}
	for _, v := range vars {
		if !varNameRe.MatchString(v.Name) {
			return &ValidationError{fmt.Sprintf("invalid variable name %q", v.Name)}
		}
		if seen[v.Name] {
			return &ValidationError{fmt.Sprintf("duplicate variable %s", v.Name)}
		}
		seen[v.Name] = true
		if v.Value != nil && len(*v.Value) > 16<<10 {
			return &ValidationError{fmt.Sprintf("value of %s is longer than 16 KiB", v.Name)}
		}
	}
	return nil
}
