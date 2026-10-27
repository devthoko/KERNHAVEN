package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

// The crash tests run the runner in a child process (this test binary
// re-executed) and kill it with SIGKILL at chosen points, then restart it.
// This exercises the real recovery path: SQLite journal, Recover, resume.

const (
	envChild   = "KH_JOBS_CRASH_CHILD"
	envDir     = "KH_JOBS_CRASH_DIR"
	envFail    = "KH_JOBS_CRASH_FAIL_LAST"
	crashKind  = "crash.files"
	crashSteps = 4
)

func TestMain(m *testing.M) {
	if os.Getenv(envChild) == "1" {
		os.Exit(crashChild(os.Getenv(envDir), os.Getenv(envFail) == "1"))
	}
	os.Exit(m.Run())
}

// touch appends a marker line; markers record that a point was reached.
func touch(dir, name string) {
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err == nil {
		f.WriteString("x\n")
		f.Close()
	}
}

// effect creates effect-i exactly once and logs the creation; repeated calls
// after a crash find the file and do nothing (idempotent step).
func effect(dir string, i int) error {
	f, err := os.OpenFile(filepath.Join(dir, fmt.Sprintf("effect-%d", i)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	f.Close()
	touch(dir, "effects.log")
	return nil
}

func undo(dir string, i int) error {
	err := os.Remove(filepath.Join(dir, fmt.Sprintf("effect-%d", i)))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err == nil {
		touch(dir, "undo.log")
	}
	return err
}

func crashKindDef(dir string, failLast bool) Kind {
	return Kind{Name: crashKind, MaxAttempts: 5, Plan: func(json.RawMessage) ([]Step, error) {
		steps := make([]Step, crashSteps)
		for i := range steps {
			i := i
			steps[i] = Step{
				Name: fmt.Sprintf("step%d", i),
				Run: func(ctx context.Context, sc *StepContext) error {
					touch(dir, fmt.Sprintf("started-%d", i))
					time.Sleep(300 * time.Millisecond) // kill window
					if failLast && i == crashSteps-1 {
						return Permanent(errors.New("last step fails"))
					}
					return effect(dir, i)
				},
				Compensate: func(ctx context.Context, sc *StepContext) error {
					touch(dir, fmt.Sprintf("comp-started-%d", i))
					time.Sleep(300 * time.Millisecond) // kill window
					return undo(dir, i)
				},
			}
		}
		return steps, nil
	}}
}

// crashChild runs the runner until the single job is terminal.
func crashChild(dir string, failLast bool) int {
	db, err := store.Open(context.Background(), filepath.Join(dir, store.FileName))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	defer db.Close()
	s := New(db, nil)
	s.Register(crashKindDef(dir, failLast))
	r := NewRunner(s, quietLog(), RunnerOptions{Workers: 1, Lease: 500 * time.Millisecond, Heartbeat: 50 * time.Millisecond, PollInterval: 20 * time.Millisecond})
	if err := r.Recover(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	r.Start()
	defer r.Stop(context.Background())
	for {
		var state string
		if err := db.QueryRow(`SELECT state FROM jobs WHERE id = 1`).Scan(&state); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		if State(state).Terminal() {
			return 0
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func startChild(t *testing.T, dir string, failLast bool) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), envChild+"=1", envDir+"="+dir)
	if failLast {
		cmd.Env = append(cmd.Env, envFail+"=1")
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	return cmd
}

func waitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", path)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func lines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Count(string(b), "\n")
}

func prepareCrashJob(t *testing.T, failLast bool) (string, *Service) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open(context.Background(), filepath.Join(dir, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := New(db, nil)
	s.Register(crashKindDef(dir, failLast))
	if _, err := s.Enqueue(context.Background(), Request{Kind: crashKind, Payload: struct{}{}}); err != nil {
		t.Fatal(err)
	}
	return dir, s
}

func killAndWait(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_, _ = cmd.Process.Wait()
}

func finish(t *testing.T, cmd *exec.Cmd) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("child exited with %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("child did not finish")
	}
}

// AT-F18-02: SIGKILL during each step; the restarted process completes the
// job, every effect happens exactly once, and the journal is consistent.
func TestCrashDuringEachStepRecovers(t *testing.T) {
	if testing.Short() {
		t.Skip("process crash test")
	}
	for k := 0; k < crashSteps; k++ {
		t.Run(fmt.Sprintf("kill in step %d", k), func(t *testing.T) {
			dir, s := prepareCrashJob(t, false)
			child := startChild(t, dir, false)
			waitFile(t, filepath.Join(dir, fmt.Sprintf("started-%d", k)))
			killAndWait(t, child)

			j, err := s.Get(context.Background(), 1)
			if err != nil {
				t.Fatal(err)
			}
			if j.State != Running || j.StepsDone != k {
				t.Fatalf("after kill: state %s, steps done %d, want running/%d", j.State, j.StepsDone, k)
			}

			finish(t, startChild(t, dir, false))
			j, _ = s.Get(context.Background(), 1)
			if j.State != Succeeded || j.StepsDone != crashSteps || j.Attempts != 2 {
				t.Fatalf("after restart: %+v", j)
			}
			if !hasLog(j, "interrupted by a restart") {
				t.Fatalf("no recovery log: %+v", j.Logs)
			}
			if n := lines(t, filepath.Join(dir, "effects.log")); n != crashSteps {
				t.Fatalf("effects applied %d times, want %d", n, crashSteps)
			}
			for i := 0; i < crashSteps; i++ {
				if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("effect-%d", i))); err != nil {
					t.Fatalf("effect %d missing", i)
				}
				// Steps finished before the crash are not re-run.
				want := 1
				if i == k {
					want = 2
				}
				if n := lines(t, filepath.Join(dir, fmt.Sprintf("started-%d", i))); n != want {
					t.Fatalf("step %d started %d times, want %d", i, n, want)
				}
			}
		})
	}
}

// AT-F18-02: SIGKILL during rollback; the restarted process finishes the
// rollback without repeating completed compensations.
func TestCrashDuringCompensationRecovers(t *testing.T) {
	if testing.Short() {
		t.Skip("process crash test")
	}
	dir, s := prepareCrashJob(t, true)
	child := startChild(t, dir, true)
	waitFile(t, filepath.Join(dir, "comp-started-1")) // rollback runs 2, 1, 0
	killAndWait(t, child)

	j, _ := s.Get(context.Background(), 1)
	if j.State != Compensating {
		t.Fatalf("after kill: state %s", j.State)
	}
	finish(t, startChild(t, dir, true))
	j, _ = s.Get(context.Background(), 1)
	if j.State != Failed || j.NeedsAttention || !strings.Contains(j.Error, "last step fails") {
		t.Fatalf("after restart: %+v", j)
	}
	for i := 0; i < crashSteps-1; i++ {
		if _, err := os.Stat(filepath.Join(dir, fmt.Sprintf("effect-%d", i))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("effect %d not rolled back", i)
		}
	}
	if n := lines(t, filepath.Join(dir, "undo.log")); n != crashSteps-1 {
		t.Fatalf("undo applied %d times, want %d", n, crashSteps-1)
	}
	if n := lines(t, filepath.Join(dir, "comp-started-2")); n != 1 {
		t.Fatalf("completed compensation of step 2 repeated %d times", n)
	}
}
