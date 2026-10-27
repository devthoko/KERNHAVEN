package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// RunnerOptions tune the runner; zero values select production defaults.
type RunnerOptions struct {
	Workers      int           // default 2
	Lease        time.Duration // default 30s
	Heartbeat    time.Duration // default 10s
	PollInterval time.Duration // default 1s
	BackoffBase  time.Duration // default 2s
	BackoffMax   time.Duration // default 5m
}

func (o *RunnerOptions) defaults() {
	if o.Workers <= 0 {
		o.Workers = 2
	}
	if o.Lease <= 0 {
		o.Lease = 30 * time.Second
	}
	if o.Heartbeat <= 0 {
		o.Heartbeat = 10 * time.Second
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.BackoffBase <= 0 {
		o.BackoffBase = 2 * time.Second
	}
	if o.BackoffMax <= 0 {
		o.BackoffMax = 5 * time.Minute
	}
}

// Runner claims and executes jobs.
type Runner struct {
	s    *Service
	log  *slog.Logger
	opts RunnerOptions
	id   string

	mu       sync.Mutex
	started  bool
	stopping bool
	wake     chan struct{}
	quit     chan struct{}
	hardStop context.CancelFunc
	runCtx   context.Context
	wg       sync.WaitGroup
}

// NewRunner returns a runner for s.
func NewRunner(s *Service, log *slog.Logger, opts RunnerOptions) *Runner {
	opts.defaults()
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return &Runner{s: s, log: log, opts: opts, id: hex.EncodeToString(b), wake: make(chan struct{}, 1), quit: make(chan struct{})}
}

// Wake makes an idle worker look for work immediately (call after Enqueue).
func (r *Runner) Wake() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// Recover resets jobs interrupted by a previous process. Call once at startup
// before Start; the Core runs as a single instance.
func (r *Runner) Recover(ctx context.Context) error {
	now := r.s.now().UnixMilli()
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	rows, err := tx.QueryContext(ctx, `SELECT id, attempts, max_attempts FROM jobs WHERE state = 'running'`)
	if err != nil {
		return err
	}
	type interrupted struct{ id, attempts, max int64 }
	var list []interrupted
	for rows.Next() {
		var j interrupted
		if err := rows.Scan(&j.id, &j.attempts, &j.max); err != nil {
			rows.Close()
			return err
		}
		list = append(list, j)
	}
	rows.Close()
	for _, j := range list {
		if j.attempts >= j.max {
			_, err = tx.ExecContext(ctx, `UPDATE jobs SET state = 'compensating', outcome = 'failed',
				error = 'interrupted by a restart too many times', lease_owner = '', lease_expires_ms = 0, next_run_ms = ?, updated_ms = ? WHERE id = ?`,
				now, now, j.id)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE jobs SET state = 'queued', lease_owner = '', lease_expires_ms = 0, next_run_ms = ?, updated_ms = ? WHERE id = ?`,
				now, now, j.id)
		}
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO job_logs (job_id, ts_ms, level, message) VALUES (?, ?, 'warn', 'interrupted by a restart; resuming from the step journal')`,
			j.id, now); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET lease_owner = '', lease_expires_ms = 0 WHERE state = 'compensating'`); err != nil {
		return err
	}
	if len(list) > 0 {
		r.log.Warn("recovered interrupted jobs", "count", len(list))
	}
	return tx.Commit()
}

// Start launches the workers.
func (r *Runner) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return
	}
	r.started = true
	r.runCtx, r.hardStop = context.WithCancel(context.Background())
	for i := 0; i < r.opts.Workers; i++ {
		r.wg.Add(1)
		go r.worker()
	}
}

// Stop stops claiming new jobs and waits for running steps until ctx ends;
// then it cancels them. Interrupted jobs are requeued without consuming an
// attempt.
func (r *Runner) Stop(ctx context.Context) {
	r.mu.Lock()
	if !r.started || r.stopping {
		r.mu.Unlock()
		return
	}
	r.stopping = true
	close(r.quit)
	r.mu.Unlock()

	done := make(chan struct{})
	go func() { r.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-ctx.Done():
		r.hardStop()
		<-done
	}
	r.hardStop()
}

func (r *Runner) stopRequested() bool {
	select {
	case <-r.quit:
		return true
	default:
		return false
	}
}

func (r *Runner) worker() {
	defer r.wg.Done()
	t := time.NewTicker(r.opts.PollInterval)
	defer t.Stop()
	for {
		if r.stopRequested() {
			return
		}
		c, err := r.claim()
		if err != nil {
			r.log.Error("job claim failed", "error", err.Error())
		}
		if c != nil {
			r.execute(c)
			continue
		}
		select {
		case <-r.quit:
			return
		case <-r.wake:
		case <-t.C:
		}
	}
}

type claimed struct {
	id          int64
	kind        string
	state       State
	outcome     string
	payload     json.RawMessage
	attempts    int
	maxAttempts int
	cancel      bool
}

func (r *Runner) claim() (*claimed, error) {
	now := r.s.now().UnixMilli()
	var c claimed
	var state, payload string
	var cancel int
	err := r.s.db.QueryRowContext(r.runCtx, `UPDATE jobs SET
			state = CASE state WHEN 'queued' THEN 'running' ELSE state END,
			attempts = attempts + CASE WHEN state = 'queued' AND cancel_requested = 0 THEN 1 ELSE 0 END,
			started_ms = CASE started_ms WHEN 0 THEN ? ELSE started_ms END,
			lease_owner = ?, lease_expires_ms = ?, updated_ms = ?
		WHERE id = (SELECT id FROM jobs
			WHERE (state = 'queued' AND next_run_ms <= ?) OR (state = 'compensating' AND lease_expires_ms <= ?)
			ORDER BY id LIMIT 1)
		RETURNING id, kind, state, outcome, payload, attempts, max_attempts, cancel_requested`,
		now, r.id, now+r.opts.Lease.Milliseconds(), now, now, now).
		Scan(&c.id, &c.kind, &state, &c.outcome, &payload, &c.attempts, &c.maxAttempts, &cancel)
	if errors.Is(err, sql.ErrNoRows) || errors.Is(err, context.Canceled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	c.state, c.payload, c.cancel = State(state), json.RawMessage(payload), cancel == 1
	return &c, nil
}

// errCancelRequested is the cancellation cause for a user cancel.
var errCancelRequested = errors.New("cancel requested")

type stepRecord struct {
	state   string
	outputs map[string]json.RawMessage
}

func (r *Runner) loadJournal(ctx context.Context, id int64) ([]stepRecord, error) {
	rows, err := r.s.db.QueryContext(ctx, `SELECT state, outputs FROM job_steps WHERE job_id = ? ORDER BY idx`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stepRecord
	for rows.Next() {
		var rec stepRecord
		var outputs string
		if err := rows.Scan(&rec.state, &outputs); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(outputs), &rec.outputs); err != nil {
			return nil, fmt.Errorf("step outputs: %w", err)
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// execute runs one claimed job until it finishes, is requeued or the runner
// stops. Database errors leave the job leased; Recover or lease expiry picks
// it up again.
func (r *Runner) execute(c *claimed) {
	ctx := r.runCtx
	log := r.log.With("job_id", c.id, "kind", c.kind)

	k, ok := r.s.kinds[c.kind]
	var steps []Step
	var err error
	if ok {
		steps, err = k.Plan(c.payload)
	} else {
		err = fmt.Errorf("unknown job kind %q", c.kind)
	}
	if err != nil {
		r.finish(c.id, Failed, "cannot plan job: "+err.Error(), true)
		return
	}
	journal, err := r.loadJournal(ctx, c.id)
	if err != nil || len(journal) != len(steps) {
		r.finish(c.id, Failed, fmt.Sprintf("step journal does not match plan (%d entries, %d steps)", len(journal), len(steps)), true)
		return
	}

	// jobCtx is cancelled by a user cancel (via the heartbeat) or by a hard
	// stop. Compensation runs under ctx only, so a cancel request cannot
	// interrupt a rollback.
	jobCtx, cancel := context.WithCancelCause(ctx)
	hbCtx, hbStop := context.WithCancel(ctx)
	hbDone := make(chan struct{})
	go r.heartbeat(hbCtx, c.id, cancel, hbDone)
	defer func() { hbStop(); <-hbDone; cancel(nil) }()

	if c.state == Compensating {
		r.compensate(ctx, c, steps, journal, State(c.outcome), "")
		return
	}
	if c.cancel {
		r.compensate(ctx, c, steps, journal, Cancelled, "cancelled by user")
		return
	}

	_ = r.s.appendLog(ctx, c.id, "info", fmt.Sprintf("attempt %d of %d started", c.attempts, c.maxAttempts))
	for i, st := range steps {
		if journal[i].state != "pending" {
			continue
		}
		if r.stopRequested() {
			r.release(c.id, fmt.Sprintf("stopped before step %q", st.Name))
			return
		}
		sc := &StepContext{JobID: c.id, Payload: c.payload, Attempt: c.attempts, r: r, journal: journal, index: i}
		runErr := st.Run(jobCtx, sc)
		if runErr == nil {
			if err := r.markStep(c.id, i, "done", sc.pending); err != nil {
				log.Error("journal write failed", "step", st.Name, "error", err.Error())
				return
			}
			journal[i].state = "done"
			journal[i].outputs = mergeOutputs(journal[i].outputs, sc.pending)
			continue
		}

		switch {
		case errors.Is(context.Cause(jobCtx), errCancelRequested):
			_ = r.s.appendLog(context.Background(), c.id, "warn", fmt.Sprintf("step %q interrupted by cancel", st.Name))
			r.compensate(ctx, c, steps, journal, Cancelled, "cancelled by user")
		case r.stopRequested() || ctx.Err() != nil:
			r.release(c.id, fmt.Sprintf("step %q interrupted by shutdown", st.Name))
		case !IsPermanent(runErr) && c.attempts < c.maxAttempts:
			delay := r.backoff(c.attempts)
			_ = r.s.appendLog(ctx, c.id, "warn", fmt.Sprintf("step %q failed: %v; retrying in %s", st.Name, runErr, delay))
			r.requeue(c.id, delay, runErr.Error())
		default:
			msg := fmt.Sprintf("step %q failed: %v", st.Name, runErr)
			_ = r.s.appendLog(ctx, c.id, "error", msg)
			r.compensate(ctx, c, steps, journal, Failed, msg)
		}
		return
	}
	_ = r.s.appendLog(ctx, c.id, "info", "all steps completed")
	r.finish(c.id, Succeeded, "", false)
}

// compensate undoes completed steps in reverse order and ends the job with
// outcome. A failing compensation leaves the job failed and flagged.
func (r *Runner) compensate(ctx context.Context, c *claimed, steps []Step, journal []stepRecord, outcome State, reason string) {
	now := r.s.now().UnixMilli()
	if _, err := r.s.db.ExecContext(context.Background(), `UPDATE jobs SET state = 'compensating', outcome = ?,
			error = CASE WHEN ? <> '' THEN ? ELSE error END, updated_ms = ? WHERE id = ?`,
		string(outcome), reason, reason, now, c.id); err != nil {
		r.log.Error("job state write failed", "job_id", c.id, "error", err.Error())
		return
	}
	for i := len(steps) - 1; i >= 0; i-- {
		if journal[i].state != "done" || steps[i].Compensate == nil {
			continue
		}
		if r.stopRequested() {
			r.releaseCompensation(c.id)
			return
		}
		sc := &StepContext{JobID: c.id, Payload: c.payload, Attempt: c.attempts, r: r, journal: journal, index: i}
		if err := steps[i].Compensate(ctx, sc); err != nil {
			if r.stopRequested() {
				r.releaseCompensation(c.id)
				return
			}
			msg := fmt.Sprintf("rollback of step %q failed: %v; manual attention required", steps[i].Name, err)
			_ = r.s.appendLog(context.Background(), c.id, "error", msg)
			r.finishAttention(c.id, msg)
			return
		}
		if err := r.markStep(c.id, i, "compensated", sc.pending); err != nil {
			r.log.Error("journal write failed", "job_id", c.id, "error", err.Error())
			return
		}
		journal[i].state = "compensated"
		_ = r.s.appendLog(context.Background(), c.id, "info", fmt.Sprintf("rolled back step %q", steps[i].Name))
	}
	r.finish(c.id, outcome, "", false)
}

func (r *Runner) heartbeat(ctx context.Context, id int64, cancel context.CancelCauseFunc, done chan struct{}) {
	defer close(done)
	t := time.NewTicker(r.opts.Heartbeat)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		now := r.s.now().UnixMilli()
		var cancelReq int
		err := r.s.db.QueryRowContext(ctx, `UPDATE jobs SET lease_expires_ms = ? WHERE id = ? AND lease_owner = ? RETURNING cancel_requested`,
			now+r.opts.Lease.Milliseconds(), id, r.id).Scan(&cancelReq)
		if err == nil && cancelReq == 1 {
			cancel(errCancelRequested) // idempotent; keep renewing the lease
		}
	}
}

func (r *Runner) backoff(attempt int) time.Duration {
	d := r.opts.BackoffBase << min(attempt-1, 20)
	if d > r.opts.BackoffMax || d <= 0 {
		d = r.opts.BackoffMax
	}
	return d
}

func (r *Runner) markStep(id int64, idx int, state string, outputs map[string]json.RawMessage) error {
	ctx := context.Background() // journal writes must not be lost to cancellation
	tx, err := r.s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	var current string
	if err := tx.QueryRowContext(ctx, `SELECT outputs FROM job_steps WHERE job_id = ? AND idx = ?`, id, idx).Scan(&current); err != nil {
		return err
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal([]byte(current), &merged); err != nil {
		return err
	}
	b, err := json.Marshal(mergeOutputs(merged, outputs))
	if err != nil {
		return err
	}
	now := r.s.now().UnixMilli()
	if _, err := tx.ExecContext(ctx, `UPDATE job_steps SET state = ?, outputs = ?, completed_ms = ? WHERE job_id = ? AND idx = ?`,
		state, string(b), now, id, idx); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET updated_ms = ? WHERE id = ?`, now, id); err != nil {
		return err
	}
	return tx.Commit()
}

func mergeOutputs(a, b map[string]json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func (r *Runner) exec(query string, args ...any) {
	if _, err := r.s.db.ExecContext(context.Background(), query, args...); err != nil {
		r.log.Error("job state write failed", "error", err.Error())
	}
}

func (r *Runner) finish(id int64, state State, errMsg string, logIt bool) {
	now := r.s.now().UnixMilli()
	if logIt && errMsg != "" {
		_ = r.s.appendLog(context.Background(), id, "error", errMsg)
	}
	r.exec(`UPDATE jobs SET state = ?, error = CASE WHEN ? <> '' THEN ? ELSE error END,
		lease_owner = '', lease_expires_ms = 0, finished_ms = ?, updated_ms = ? WHERE id = ?`,
		string(state), errMsg, errMsg, now, now, id)
}

func (r *Runner) finishAttention(id int64, msg string) {
	now := r.s.now().UnixMilli()
	r.exec(`UPDATE jobs SET state = 'failed', needs_attention = 1, error = ?, lease_owner = '', lease_expires_ms = 0,
		finished_ms = ?, updated_ms = ? WHERE id = ?`, msg, now, now, id)
}

func (r *Runner) requeue(id int64, delay time.Duration, errMsg string) {
	now := r.s.now()
	r.exec(`UPDATE jobs SET state = 'queued', error = ?, lease_owner = '', lease_expires_ms = 0, next_run_ms = ?, updated_ms = ? WHERE id = ?`,
		errMsg, now.Add(delay).UnixMilli(), now.UnixMilli(), id)
}

// release requeues a job interrupted by shutdown without consuming an attempt.
func (r *Runner) release(id int64, why string) {
	_ = r.s.appendLog(context.Background(), id, "warn", why+"; will resume after restart")
	now := r.s.now().UnixMilli()
	r.exec(`UPDATE jobs SET state = 'queued', attempts = MAX(attempts - 1, 0), lease_owner = '', lease_expires_ms = 0,
		next_run_ms = ?, updated_ms = ? WHERE id = ?`, now, now, id)
}

func (r *Runner) releaseCompensation(id int64) {
	r.exec(`UPDATE jobs SET lease_owner = '', lease_expires_ms = 0 WHERE id = ?`, id)
}

// StepContext gives a step access to its job and to step outputs.
type StepContext struct {
	JobID   int64
	Payload json.RawMessage
	Attempt int

	r       *Runner
	journal []stepRecord
	index   int
	pending map[string]json.RawMessage
}

// Logf appends a line to the job log.
func (sc *StepContext) Logf(format string, args ...any) {
	_ = sc.r.s.appendLog(context.Background(), sc.JobID, "info", fmt.Sprintf(format, args...))
}

// SetOutput records a value that is persisted with this step's completion.
func (sc *StepContext) SetOutput(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if sc.pending == nil {
		sc.pending = map[string]json.RawMessage{}
	}
	sc.pending[key] = b
	return nil
}

// Output reads a value recorded by step stepIndex (this or an earlier step).
func (sc *StepContext) Output(stepIndex int, key string, v any) (bool, error) {
	if stepIndex == sc.index {
		if raw, ok := sc.pending[key]; ok {
			return true, json.Unmarshal(raw, v)
		}
	}
	if stepIndex < 0 || stepIndex >= len(sc.journal) {
		return false, fmt.Errorf("no step %d", stepIndex)
	}
	raw, ok := sc.journal[stepIndex].outputs[key]
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal(raw, v)
}
