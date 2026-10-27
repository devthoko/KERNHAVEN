package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

var fastOpts = RunnerOptions{Workers: 2, Lease: 300 * time.Millisecond, Heartbeat: 20 * time.Millisecond,
	PollInterval: 10 * time.Millisecond, BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// recorder captures step and compensation calls.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, s)
}

func (r *recorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

type testPayload struct {
	Steps int `json:"steps"`
}

// kindBuilder makes a kind whose step i calls run(i) and compensate(i).
func kind(name string, maxAttempts int, run func(ctx context.Context, i int, sc *StepContext) error, comp func(i int) error) Kind {
	return Kind{Name: name, MaxAttempts: maxAttempts, Plan: func(raw json.RawMessage) ([]Step, error) {
		var p testPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		if p.Steps < 1 || p.Steps > 10 {
			return nil, errors.New("steps must be 1..10")
		}
		steps := make([]Step, p.Steps)
		for i := range steps {
			i := i
			steps[i] = Step{Name: "step" + string(rune('0'+i)), Run: func(ctx context.Context, sc *StepContext) error { return run(ctx, i, sc) }}
			if comp != nil {
				steps[i].Compensate = func(context.Context, *StepContext) error { return comp(i) }
			}
		}
		return steps, nil
	}}
}

func waitState(t *testing.T, s *Service, id int64, want State) Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := s.Get(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if j.State == want {
			return j
		}
		if j.State.Terminal() || time.Now().After(deadline) {
			t.Fatalf("job %d state %s (error %q), want %s; logs %+v", id, j.State, j.Error, want, j.Logs)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func startRunner(t *testing.T, s *Service) *Runner {
	t.Helper()
	r := NewRunner(s, quietLog(), fastOpts)
	if err := r.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	r.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		r.Stop(ctx)
	})
	return r
}

func hasLog(j Job, substr string) bool {
	for _, l := range j.Logs {
		if strings.Contains(l.Message, substr) {
			return true
		}
	}
	return false
}

// AT-F18-01
func TestJobSucceedsAndPassesOutputs(t *testing.T) {
	s := New(openDB(t), nil)
	rec := &recorder{}
	s.Register(kind("test.ok", 3, func(_ context.Context, i int, sc *StepContext) error {
		rec.add("run" + string(rune('0'+i)))
		switch i {
		case 0:
			return sc.SetOutput("container", "abc123")
		case 2:
			var v string
			ok, err := sc.Output(0, "container", &v)
			if err != nil || !ok || v != "abc123" {
				return Permanent(errors.New("output from step 0 missing"))
			}
		}
		return nil
	}, nil))
	id, err := s.Enqueue(context.Background(), Request{Kind: "test.ok", Payload: testPayload{3}, CreatedBy: 7})
	if err != nil {
		t.Fatal(err)
	}
	queued, _ := s.Get(context.Background(), id)
	if queued.StepsTotal != 3 || queued.StepsDone != 0 || queued.State != Queued {
		t.Fatalf("queued job: %+v", queued)
	}
	startRunner(t, s)
	j := waitState(t, s, id, Succeeded)
	if got := strings.Join(rec.list(), ","); got != "run0,run1,run2" {
		t.Fatalf("calls %s", got)
	}
	if j.Attempts != 1 || j.StepsDone != 3 || j.CreatedBy != 7 || j.FinishedAt == nil || j.StartedAt == nil {
		t.Fatalf("job %+v", j)
	}
	for _, st := range j.Steps {
		if st.State != "done" || st.CompletedAt == nil {
			t.Fatalf("step %+v", st)
		}
	}
	if !hasLog(j, "all steps completed") {
		t.Fatalf("logs %+v", j.Logs)
	}
}

// AT-F18-01: retryable errors back off and retry; done steps are not repeated.
func TestRetryResumesFromJournal(t *testing.T) {
	s := New(openDB(t), nil)
	rec := &recorder{}
	var failures atomic.Int32
	s.Register(kind("test.retry", 3, func(_ context.Context, i int, sc *StepContext) error {
		rec.add("run" + string(rune('0'+i)))
		if i == 1 && failures.Load() < 2 {
			failures.Add(1)
			return errors.New("transient")
		}
		return nil
	}, nil))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.retry", Payload: testPayload{2}})
	startRunner(t, s)
	j := waitState(t, s, id, Succeeded)
	if got := strings.Join(rec.list(), ","); got != "run0,run1,run1,run1" {
		t.Fatalf("calls %s (step 0 must not repeat)", got)
	}
	if j.Attempts != 3 || !hasLog(j, "retrying") {
		t.Fatalf("job %+v", j)
	}
}

// AT-F18-01: permanent failure rolls back completed steps in reverse order.
func TestPermanentFailureCompensatesInReverse(t *testing.T) {
	s := New(openDB(t), nil)
	rec := &recorder{}
	s.Register(kind("test.perm", 3, func(_ context.Context, i int, _ *StepContext) error {
		if i == 2 {
			return Permanent(errors.New("image not allowed"))
		}
		return nil
	}, func(i int) error { rec.add("undo" + string(rune('0'+i))); return nil }))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.perm", Payload: testPayload{3}})
	startRunner(t, s)
	j := waitState(t, s, id, Failed)
	if got := strings.Join(rec.list(), ","); got != "undo1,undo0" {
		t.Fatalf("compensations %s", got)
	}
	if j.Attempts != 1 || !strings.Contains(j.Error, "image not allowed") || j.NeedsAttention {
		t.Fatalf("job %+v", j)
	}
	states := []string{j.Steps[0].State, j.Steps[1].State, j.Steps[2].State}
	if strings.Join(states, ",") != "compensated,compensated,pending" {
		t.Fatalf("journal %v", states)
	}
}

func TestAttemptsExhaustedFails(t *testing.T) {
	s := New(openDB(t), nil)
	s.Register(kind("test.exhaust", 2, func(_ context.Context, i int, _ *StepContext) error {
		return errors.New("always")
	}, nil))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.exhaust", Payload: testPayload{1}})
	startRunner(t, s)
	j := waitState(t, s, id, Failed)
	if j.Attempts != 2 {
		t.Fatalf("attempts %d", j.Attempts)
	}
}

// AT-F18-01
func TestCancelQueuedJob(t *testing.T) {
	s := New(openDB(t), nil)
	rec := &recorder{}
	s.Register(kind("test.cq", 3, func(context.Context, int, *StepContext) error { rec.add("run"); return nil }, nil))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.cq", Payload: testPayload{2}})
	if err := s.RequestCancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	startRunner(t, s)
	j := waitState(t, s, id, Cancelled)
	if len(rec.list()) != 0 || j.Attempts != 0 {
		t.Fatalf("cancelled job ran: calls %v attempts %d", rec.list(), j.Attempts)
	}
	if err := s.RequestCancel(context.Background(), id); !errors.Is(err, ErrFinished) {
		t.Fatalf("cancel finished job: %v", err)
	}
	if err := s.RequestCancel(context.Background(), 9999); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancel missing job: %v", err)
	}
}

// AT-F18-01: a running step is interrupted and earlier steps are rolled back.
func TestCancelRunningJob(t *testing.T) {
	s := New(openDB(t), nil)
	rec := &recorder{}
	started := make(chan struct{})
	s.Register(kind("test.cr", 3, func(ctx context.Context, i int, _ *StepContext) error {
		if i == 1 {
			close(started)
			<-ctx.Done()
			return ctx.Err()
		}
		return nil
	}, func(i int) error { rec.add("undo" + string(rune('0'+i))); return nil }))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.cr", Payload: testPayload{3}})
	startRunner(t, s)
	<-started
	if err := s.RequestCancel(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	j := waitState(t, s, id, Cancelled)
	if got := strings.Join(rec.list(), ","); got != "undo0" {
		t.Fatalf("compensations %s", got)
	}
	if !strings.Contains(j.Error, "cancelled") {
		t.Fatalf("error %q", j.Error)
	}
}

func TestCompensationFailureNeedsAttention(t *testing.T) {
	s := New(openDB(t), nil)
	s.Register(kind("test.cf", 3, func(_ context.Context, i int, _ *StepContext) error {
		if i == 1 {
			return Permanent(errors.New("boom"))
		}
		return nil
	}, func(int) error { return errors.New("cannot undo") }))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.cf", Payload: testPayload{2}})
	startRunner(t, s)
	j := waitState(t, s, id, Failed)
	if !j.NeedsAttention || !strings.Contains(j.Error, "manual attention") {
		t.Fatalf("job %+v", j)
	}
}

// Graceful shutdown requeues without consuming an attempt.
func TestShutdownRequeuesWithoutConsumingAttempt(t *testing.T) {
	s := New(openDB(t), nil)
	started := make(chan struct{}, 1)
	s.Register(kind("test.sd", 3, func(ctx context.Context, i int, _ *StepContext) error {
		started <- struct{}{}
		<-ctx.Done()
		return ctx.Err()
	}, nil))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.sd", Payload: testPayload{1}})
	r := NewRunner(s, quietLog(), fastOpts)
	r.Start()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r.Stop(ctx)
	j, _ := s.Get(context.Background(), id)
	if j.State != Queued || j.Attempts != 0 || !hasLog(j, "interrupted by shutdown") {
		t.Fatalf("job after shutdown: %+v", j)
	}
}

// AT-F18-02 (in-process part): interrupted jobs are requeued or failed.
func TestRecoverInterruptedJobs(t *testing.T) {
	db := openDB(t)
	s := New(db, nil)
	s.Register(kind("test.rec", 2, func(context.Context, int, *StepContext) error { return nil }, nil))
	a, _ := s.Enqueue(context.Background(), Request{Kind: "test.rec", Payload: testPayload{1}})
	b, _ := s.Enqueue(context.Background(), Request{Kind: "test.rec", Payload: testPayload{1}})
	if _, err := db.Exec(`UPDATE jobs SET state = 'running', attempts = 1, lease_owner = 'dead', lease_expires_ms = 9999999999999 WHERE id = ?`, a); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE jobs SET state = 'running', attempts = 2, lease_owner = 'dead', lease_expires_ms = 9999999999999 WHERE id = ?`, b); err != nil {
		t.Fatal(err)
	}
	startRunner(t, s)
	ja := waitState(t, s, a, Succeeded)
	jb := waitState(t, s, b, Failed)
	if ja.Attempts != 2 || !hasLog(ja, "interrupted by a restart") {
		t.Fatalf("resumed job %+v", ja)
	}
	if !strings.Contains(jb.Error, "too many times") {
		t.Fatalf("exhausted job %+v", jb)
	}
}

func TestDedupeKey(t *testing.T) {
	s := New(openDB(t), nil)
	s.Register(kind("test.dd", 1, func(context.Context, int, *StepContext) error { return nil }, nil))
	ctx := context.Background()
	id, err := s.Enqueue(ctx, Request{Kind: "test.dd", Payload: testPayload{1}, DedupeKey: "app:nextcloud"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Enqueue(ctx, Request{Kind: "test.dd", Payload: testPayload{1}, DedupeKey: "app:nextcloud"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("duplicate: %v", err)
	}
	startRunner(t, s)
	waitState(t, s, id, Succeeded)
	if _, err := s.Enqueue(ctx, Request{Kind: "test.dd", Payload: testPayload{1}, DedupeKey: "app:nextcloud"}); err != nil {
		t.Fatalf("re-enqueue after finish: %v", err)
	}
}

func TestEnqueueValidation(t *testing.T) {
	s := New(openDB(t), nil)
	s.Register(kind("test.val", 1, func(context.Context, int, *StepContext) error { return nil }, nil))
	ctx := context.Background()
	if _, err := s.Enqueue(ctx, Request{Kind: "test.unknown", Payload: testPayload{1}}); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := s.Enqueue(ctx, Request{Kind: "test.val", Payload: testPayload{0}}); err == nil {
		t.Error("invalid payload accepted")
	}
	if _, err := s.Enqueue(ctx, Request{Kind: "test.val", Payload: func() {}}); err == nil {
		t.Error("unmarshalable payload accepted")
	}
	for _, bad := range []Kind{{Name: "Bad Name", Plan: func(json.RawMessage) ([]Step, error) { return nil, nil }}, {Name: "test.noplan"}, {Name: "test.val", Plan: func(json.RawMessage) ([]Step, error) { return nil, nil }}} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%q) did not panic", bad.Name)
				}
			}()
			s.Register(bad)
		}()
	}
}

func TestUnknownKindAtRuntimeFails(t *testing.T) {
	db := openDB(t)
	producer := New(db, nil)
	producer.Register(kind("test.gone", 1, func(context.Context, int, *StepContext) error { return nil }, nil))
	id, _ := producer.Enqueue(context.Background(), Request{Kind: "test.gone", Payload: testPayload{1}})
	consumer := New(db, nil) // e.g. after a downgrade that removed the kind
	startRunner(t, consumer)
	j := waitState(t, consumer, id, Failed)
	if !strings.Contains(j.Error, "unknown job kind") {
		t.Fatalf("error %q", j.Error)
	}
}

func TestJobLogsBounded(t *testing.T) {
	s := New(openDB(t), nil)
	s.Register(kind("test.log", 1, func(context.Context, int, *StepContext) error { return nil }, nil))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.log", Payload: testPayload{1}})
	for i := 0; i < maxLogLines+100; i++ {
		if err := s.appendLog(context.Background(), id, "info", strings.Repeat("x", 2000)); err != nil {
			t.Fatal(err)
		}
	}
	j, _ := s.Get(context.Background(), id)
	if len(j.Logs) != maxLogLines || len([]rune(j.Logs[0].Message)) != 1001 {
		t.Fatalf("logs %d, len %d", len(j.Logs), len([]rune(j.Logs[0].Message)))
	}
}

func TestListAndPurge(t *testing.T) {
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	s := New(openDB(t), clock)
	s.Register(kind("test.lp", 1, func(context.Context, int, *StepContext) error { return nil }, nil))
	id, _ := s.Enqueue(context.Background(), Request{Kind: "test.lp", Payload: testPayload{1}})
	startRunner(t, s)
	waitState(t, s, id, Succeeded)
	list, _ := s.List(context.Background(), Filter{State: Succeeded})
	if len(list) != 1 || list[0].ID != id {
		t.Fatalf("list %+v", list)
	}
	if n, _ := s.PurgeFinished(context.Background(), now.Add(-time.Hour)); n != 0 {
		t.Fatalf("purged recent job")
	}
	if n, _ := s.PurgeFinished(context.Background(), now.Add(time.Hour)); n != 1 {
		t.Fatalf("did not purge old job")
	}
	if _, err := s.Get(context.Background(), id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purged job still present: %v", err)
	}
}
