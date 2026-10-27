// Package jobs runs persistent, journaled background jobs that survive
// crashes and restarts (M3, AT-F18-01/02).
package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// State is a job's lifecycle state.
type State string

const (
	Queued       State = "queued"
	Running      State = "running"
	Compensating State = "compensating"
	Succeeded    State = "succeeded"
	Failed       State = "failed"
	Cancelled    State = "cancelled"
)

// Terminal reports whether s is final.
func (s State) Terminal() bool { return s == Succeeded || s == Failed || s == Cancelled }

// Step is one journaled unit of work. Run and Compensate must be idempotent:
// a crash after the effect but before the journal commit repeats the call.
type Step struct {
	Name       string
	Run        func(ctx context.Context, sc *StepContext) error
	Compensate func(ctx context.Context, sc *StepContext) error // optional
}

// Kind describes a job type registered by a module.
type Kind struct {
	Name        string
	MaxAttempts int // default 3
	// Plan validates the payload and returns the ordered steps. It must be
	// deterministic for a given payload: it is called again after restarts.
	Plan func(payload json.RawMessage) ([]Step, error)
}

// permanentError marks an error as not retryable.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// Permanent wraps err so the job fails (and compensates) without retrying.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err}
}

// IsPermanent reports whether err was wrapped with Permanent.
func IsPermanent(err error) bool {
	var p *permanentError
	return errors.As(err, &p)
}

var (
	// ErrNotFound means no such job.
	ErrNotFound = errors.New("job not found")
	// ErrDuplicate means a non-terminal job with the same dedupe key exists.
	ErrDuplicate = errors.New("an equivalent job is already queued or running")
	// ErrFinished means the job already reached a terminal state.
	ErrFinished = errors.New("job has already finished")
)

var kindName = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// Service stores and queries jobs; Runner executes them.
type Service struct {
	db    *sql.DB
	now   func() time.Time
	kinds map[string]Kind
}

// New returns a Service. now may be nil (time.Now).
func New(db *sql.DB, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, now: now, kinds: map[string]Kind{}}
}

// Register adds a job kind. It panics on invalid or duplicate kinds because
// kinds are wired at startup by code.
func (s *Service) Register(k Kind) {
	if !kindName.MatchString(k.Name) || k.Plan == nil {
		panic("jobs: invalid kind " + k.Name)
	}
	if _, dup := s.kinds[k.Name]; dup {
		panic("jobs: duplicate kind " + k.Name)
	}
	if k.MaxAttempts <= 0 {
		k.MaxAttempts = 3
	}
	s.kinds[k.Name] = k
}

// Request describes a job to enqueue.
type Request struct {
	Kind      string
	Payload   any    // marshalled to JSON
	CreatedBy int64  // user id, 0 for system
	DedupeKey string // optional
}

// Enqueue validates and stores a job in its own transaction.
func (s *Service) Enqueue(ctx context.Context, req Request) (int64, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	id, err := s.EnqueueTx(ctx, tx, req)
	if err != nil {
		return 0, err
	}
	return id, tx.Commit()
}

// EnqueueTx stores a job inside the caller's transaction, so that a module's
// state change, its audit record and the job commit atomically.
func (s *Service) EnqueueTx(ctx context.Context, tx *sql.Tx, req Request) (int64, error) {
	k, ok := s.kinds[req.Kind]
	if !ok {
		return 0, fmt.Errorf("jobs: unknown kind %q", req.Kind)
	}
	payload, err := json.Marshal(req.Payload)
	if err != nil {
		return 0, fmt.Errorf("jobs: payload: %w", err)
	}
	steps, err := k.Plan(payload)
	if err != nil {
		return 0, fmt.Errorf("jobs: invalid payload for %s: %w", req.Kind, err)
	}
	if len(steps) == 0 {
		return 0, fmt.Errorf("jobs: kind %s planned no steps", req.Kind)
	}
	now := s.now().UnixMilli()
	var dedupe any
	if req.DedupeKey != "" {
		dedupe = req.DedupeKey
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO jobs (kind, state, payload, dedupe_key, created_by, max_attempts, next_run_ms, created_ms, updated_ms)
		VALUES (?, 'queued', ?, ?, ?, ?, ?, ?, ?)`, req.Kind, string(payload), dedupe, req.CreatedBy, k.MaxAttempts, now, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return 0, ErrDuplicate
		}
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	for i, st := range steps {
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_steps (job_id, idx, name, state) VALUES (?, ?, ?, 'pending')`, id, i, st.Name); err != nil {
			return 0, err
		}
	}
	return id, nil
}

// RequestCancel asks for a job to be cancelled. Running jobs stop at the next
// heartbeat; queued jobs are cancelled by the next worker that claims them.
func (s *Service) RequestCancel(ctx context.Context, id int64) error {
	var state string
	err := s.db.QueryRowContext(ctx, `SELECT state FROM jobs WHERE id = ?`, id).Scan(&state)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if State(state).Terminal() {
		return ErrFinished
	}
	_, err = s.db.ExecContext(ctx, `UPDATE jobs SET cancel_requested = 1, next_run_ms = MIN(next_run_ms, ?), updated_ms = ? WHERE id = ?`,
		s.now().UnixMilli(), s.now().UnixMilli(), id)
	return err
}

// Job is the public view of a job.
type Job struct {
	ID              int64      `json:"id"`
	Kind            string     `json:"kind"`
	State           State      `json:"state"`
	Attempts        int        `json:"attempts"`
	MaxAttempts     int        `json:"max_attempts"`
	CreatedBy       int64      `json:"created_by"`
	CancelRequested bool       `json:"cancel_requested"`
	NeedsAttention  bool       `json:"needs_attention"`
	Error           string     `json:"error,omitempty"`
	StepsDone       int        `json:"steps_done"`
	StepsTotal      int        `json:"steps_total"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	FinishedAt      *time.Time `json:"finished_at,omitempty"`
	Steps           []StepView `json:"steps,omitempty"`
	Logs            []LogLine  `json:"logs,omitempty"`
}

// StepView is a journal entry.
type StepView struct {
	Index       int        `json:"index"`
	Name        string     `json:"name"`
	State       string     `json:"state"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// LogLine is a job log entry.
type LogLine struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

func optTime(v int64) *time.Time {
	if v == 0 {
		return nil
	}
	t := time.UnixMilli(v).UTC()
	return &t
}

const jobColumns = `j.id, j.kind, j.state, j.attempts, j.max_attempts, j.created_by, j.cancel_requested, j.needs_attention, j.error,
	j.created_ms, j.updated_ms, j.started_ms, j.finished_ms,
	(SELECT count(*) FROM job_steps s WHERE s.job_id = j.id AND s.state <> 'pending'),
	(SELECT count(*) FROM job_steps s WHERE s.job_id = j.id)`

func scanJob(row interface{ Scan(...any) error }) (Job, error) {
	var j Job
	var state string
	var cancel, attention int
	var created, updated, started, finished int64
	err := row.Scan(&j.ID, &j.Kind, &state, &j.Attempts, &j.MaxAttempts, &j.CreatedBy, &cancel, &attention, &j.Error,
		&created, &updated, &started, &finished, &j.StepsDone, &j.StepsTotal)
	j.State = State(state)
	j.CancelRequested, j.NeedsAttention = cancel == 1, attention == 1
	j.CreatedAt, j.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	j.StartedAt, j.FinishedAt = optTime(started), optTime(finished)
	return j, err
}

// Filter selects jobs for List.
type Filter struct {
	State State
	Kind  string
	Limit int // 1..200, default 50
}

// List returns jobs, newest first.
func (s *Service) List(ctx context.Context, f Filter) ([]Job, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	q := `SELECT ` + jobColumns + ` FROM jobs j WHERE 1=1`
	var args []any
	if f.State != "" {
		q += ` AND j.state = ?`
		args = append(args, string(f.State))
	}
	if f.Kind != "" {
		q += ` AND j.kind = ?`
		args = append(args, f.Kind)
	}
	q += ` ORDER BY j.id DESC LIMIT ?`
	args = append(args, f.Limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// Get returns one job with its steps and logs.
func (s *Service) Get(ctx context.Context, id int64) (Job, error) {
	j, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobColumns+` FROM jobs j WHERE j.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT idx, name, state, completed_ms FROM job_steps WHERE job_id = ? ORDER BY idx`, id)
	if err != nil {
		return Job{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var v StepView
		var completed int64
		if err := rows.Scan(&v.Index, &v.Name, &v.State, &completed); err != nil {
			return Job{}, err
		}
		v.CompletedAt = optTime(completed)
		j.Steps = append(j.Steps, v)
	}
	if err := rows.Err(); err != nil {
		return Job{}, err
	}
	lrows, err := s.db.QueryContext(ctx, `SELECT ts_ms, level, message FROM job_logs WHERE job_id = ? ORDER BY id`, id)
	if err != nil {
		return Job{}, err
	}
	defer lrows.Close()
	for lrows.Next() {
		var l LogLine
		var ts int64
		if err := lrows.Scan(&ts, &l.Level, &l.Message); err != nil {
			return Job{}, err
		}
		l.Time = time.UnixMilli(ts).UTC()
		j.Logs = append(j.Logs, l)
	}
	return j, lrows.Err()
}

// PurgeFinished deletes terminal jobs finished before cutoff.
func (s *Service) PurgeFinished(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM jobs WHERE state IN ('succeeded', 'failed', 'cancelled') AND finished_ms > 0 AND finished_ms < ?`,
		cutoff.UnixMilli())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// maxLogLines bounds job_logs per job.
const maxLogLines = 500

// appendLog writes a bounded log line for a job.
func (s *Service) appendLog(ctx context.Context, id int64, level, msg string) error {
	if utf8.RuneCountInString(msg) > 1000 {
		msg = string([]rune(msg)[:1000]) + "…"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO job_logs (job_id, ts_ms, level, message)
		SELECT ?, ?, ?, ? WHERE (SELECT count(*) FROM job_logs WHERE job_id = ?) < ?`,
		id, s.now().UnixMilli(), level, msg, id, maxLogLines)
	return err
}
