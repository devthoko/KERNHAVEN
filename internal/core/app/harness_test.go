package app

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

const testOrigin = "https://kernhaven.test"

// strongPassword is accepted by the policy for any test username.
const strongPassword = "correct horse battery staple"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type harness struct {
	t     *testing.T
	app   *App
	db    *sql.DB
	clock *clock
	logs  *bytes.Buffer
	ipSeq atomic.Int64
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), filepath.Join(dir, store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })

	cfg := config.Default()
	cfg.Storage.DataDir = dir
	cfg.Server.PublicOrigin = testOrigin
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)}
	var logs bytes.Buffer
	a, err := New(db, cfg, slog.New(slog.NewJSONHandler(&logs, nil)), Options{
		Now:  clk.Now,
		Hash: identity.HashParams{Memory: 64, Time: 1, Threads: 1},
		Runner: jobs.RunnerOptions{Workers: 2, Lease: 300 * time.Millisecond, Heartbeat: 20 * time.Millisecond,
			PollInterval: 10 * time.Millisecond, BackoffBase: 10 * time.Millisecond, BackoffMax: 50 * time.Millisecond},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: t, app: a, db: db, clock: clk, logs: &logs}
}

// client simulates one browser: it keeps the session cookie and CSRF token
// and sends the configured Origin on unsafe requests.
type client struct {
	h      *harness
	ip     string
	cookie string
	csrf   string
}

func (h *harness) newClient() *client {
	n := h.ipSeq.Add(1)
	return &client{h: h, ip: fmt.Sprintf("198.51.%d.%d", n/250, n%250+1)}
}

type response struct {
	*httptest.ResponseRecorder
	t *testing.T
}

func (r response) json(v any) {
	r.t.Helper()
	if err := json.Unmarshal(r.Body.Bytes(), v); err != nil {
		r.t.Fatalf("decode %s: %v", r.Body.String(), err)
	}
}

func (r response) errorCode() string {
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	_ = json.Unmarshal(r.Body.Bytes(), &body)
	return body.Error.Code
}

func (r response) expect(status int) response {
	r.t.Helper()
	if r.Code != status {
		r.t.Fatalf("status %d, want %d; body: %s", r.Code, status, r.Body.String())
	}
	return r
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func withoutHeader(k string) reqOpt { return func(r *http.Request) { r.Header.Del(k) } }

func (c *client) do(method, path string, body any, opts ...reqOpt) response {
	c.h.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.h.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, rd)
	req.RemoteAddr = c.ip + ":40000"
	req.Header.Set("User-Agent", "kernhaven-test")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", testOrigin)
	}
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: c.h.app.Identity.CookieName(), Value: c.cookie})
	}
	if c.csrf != "" {
		req.Header.Set(identity.CSRFHeader, c.csrf)
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	c.h.app.Handler.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == c.h.app.Identity.CookieName() {
			if ck.MaxAge < 0 {
				c.cookie = ""
			} else {
				c.cookie = ck.Value
			}
		}
	}
	return response{rec, c.h.t}
}

type sessionBody struct {
	User struct {
		ID       int64      `json:"id"`
		Username string     `json:"username"`
		Role     authz.Role `json:"role"`
	} `json:"user"`
	Permissions []string `json:"permissions"`
	CSRFToken   string   `json:"csrf_token"`
}

func (c *client) login(username, password string) response {
	c.h.t.Helper()
	r := c.do("POST", "/api/v1/auth/login", map[string]string{"username": username, "password": password})
	if r.Code == http.StatusOK {
		var s sessionBody
		r.json(&s)
		c.csrf = s.CSRFToken
	}
	return r
}

// setupOwner completes first-run setup and returns the logged-in owner.
func (h *harness) setupOwner() *client {
	h.t.Helper()
	token, err := h.app.Identity.PrepareSetup(context.Background())
	if err != nil || token == "" {
		h.t.Fatalf("PrepareSetup: %q %v", token, err)
	}
	c := h.newClient()
	r := c.do("POST", "/api/v1/setup", map[string]string{"token": token, "username": "owner", "password": strongPassword}).expect(http.StatusCreated)
	var s sessionBody
	r.json(&s)
	c.csrf = s.CSRFToken
	return c
}

// createUser creates a user through the API as owner and returns its id.
func (h *harness) createUser(owner *client, username string, role authz.Role) int64 {
	h.t.Helper()
	r := owner.do("POST", "/api/v1/users", map[string]any{"username": username, "role": role, "password": strongPassword}).expect(http.StatusCreated)
	var u struct{ ID int64 }
	r.json(&u)
	return u.ID
}

// loginAs returns a fresh client logged in as username.
func (h *harness) loginAs(username string) *client {
	h.t.Helper()
	c := h.newClient()
	c.login(username, strongPassword).expect(http.StatusOK)
	return c
}

// startJobs runs the job runner for the duration of the test.
func (h *harness) startJobs() {
	h.t.Helper()
	if err := h.app.Runner.Recover(context.Background()); err != nil {
		h.t.Fatal(err)
	}
	h.app.Runner.Start()
	h.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		h.app.Runner.Stop(ctx)
	})
}

func (h *harness) waitJob(id int64, want jobs.State) jobs.Job {
	h.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		j, err := h.app.Jobs.Get(context.Background(), id)
		if err != nil {
			h.t.Fatal(err)
		}
		if j.State == want {
			return j
		}
		if j.State.Terminal() || time.Now().After(deadline) {
			h.t.Fatalf("job %d: %s (%s), want %s", id, j.State, j.Error, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
