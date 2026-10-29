package alerts

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/certs"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/metrics"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

type fakeSources struct {
	mu      sync.Mutex
	health  []metrics.Check
	cpu     float64
	host    metrics.Host
	inv     agentproto.StorageInventory
	certs   []certs.Certificate
	failed  []jobs.Job
	records []audit.Record
	chainOK bool
}

func (f *fakeSources) sources() Sources {
	return Sources{
		Health: func(context.Context) []metrics.Check {
			f.mu.Lock()
			defer f.mu.Unlock()
			return append([]metrics.Check{}, f.health...)
		},
		Host:       func() (metrics.Host, error) { f.mu.Lock(); defer f.mu.Unlock(); return f.host, nil },
		CPUAverage: func(time.Duration) (float64, int) { f.mu.Lock(); defer f.mu.Unlock(); return f.cpu, 10 },
		Storage: func(context.Context) (agentproto.StorageInventory, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.inv, nil
		},
		Certificates: func(context.Context) ([]certs.Certificate, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.certs, nil
		},
		FailedJobs: func(_ context.Context, since time.Time) ([]jobs.Job, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			out := []jobs.Job{}
			for _, j := range f.failed {
				if j.FinishedAt.After(since) {
					out = append(out, j)
				}
			}
			return out, nil
		},
		Audit: func(_ context.Context, after int64, limit int) ([]audit.Record, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			out := []audit.Record{}
			for _, r := range f.records {
				if r.Seq > after && len(out) < limit {
					out = append(out, r)
				}
			}
			return out, nil
		},
		VerifyAudit: func(context.Context) (audit.VerifyResult, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			return audit.VerifyResult{OK: f.chainOK, BrokenAt: 7, Reason: "hash mismatch"}, nil
		},
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type receiver struct {
	mu     sync.Mutex
	msgs   []Message
	status int
}

func (r *receiver) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	defer r.mu.Unlock()
	var m Message
	_ = json.Unmarshal(b, &m)
	r.msgs = append(r.msgs, m)
	if r.status != 0 {
		w.WriteHeader(r.status)
	}
}

func (r *receiver) titles() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := []string{}
	for _, m := range r.msgs {
		out = append(out, m.State+": "+m.Title)
	}
	return out
}

type env struct {
	t   *testing.T
	s   *Service
	src *fakeSources
	clk *testClock
	rcv *receiver
	ch  Channel
	ctx context.Context
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(dir, "kh.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	box, err := secretbox.Open(filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	clk := &testClock{t: time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)}
	src := &fakeSources{chainOK: true}
	s := New(db, box, audit.New(db, clk.now), Sender{Guard: Guard{AllowLoopback: true}}, src.sources(), "https://kernhaven.test", slog.New(slog.NewTextHandler(io.Discard, nil)), clk.now)
	rcv := &receiver{}
	srv := httptest.NewServer(rcv)
	t.Cleanup(srv.Close)
	e := &env{t: t, s: s, src: src, clk: clk, rcv: rcv, ctx: ctx}
	secret := "hook-secret"
	e.ch, err = s.SaveChannel(ctx, Actor{Name: "owner"}, 0, ChannelInput{Name: "hook", Kind: KindWebhook, Config: ChannelConfig{URL: srv.URL}, Secret: &secret})
	if err != nil {
		t.Fatal(err)
	}
	rules, _ := s.Rules(ctx)
	for _, r := range rules {
		if _, err := s.SetRule(ctx, Actor{Name: "owner"}, r.Rule, RuleInput{Enabled: true, Params: r.Params, Channels: []int64{e.ch.ID}}); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) round() {
	e.s.Evaluate(e.ctx)
	e.s.Deliver(e.ctx)
}

func (e *env) firing() []string {
	list, _ := e.s.Alerts(e.ctx, true)
	out := []string{}
	for _, a := range list {
		out = append(out, a.Rule+"/"+a.Key)
	}
	return out
}

func (e *env) expectSent(want ...string) {
	e.t.Helper()
	got := e.rcv.titles()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		e.t.Fatalf("sent %q\nwant %q", got, want)
	}
}

// AT-F16-02, AT-F16-03: state rules fire once, resolve once.
func TestStateRules(t *testing.T) {
	e := newEnv(t)
	e.src.health = []metrics.Check{{Name: "monitor", Label: "Monitor service", Status: metrics.StatusDown, Detail: "not reachable"}}
	e.round() // one check: not yet
	e.expectSent()
	e.round()
	e.expectSent("firing: Monitor service is down")
	e.round() // still down: deduplicated
	e.round()
	e.expectSent("firing: Monitor service is down")
	e.src.health[0].Status = metrics.StatusOK
	e.round()
	e.expectSent("firing: Monitor service is down", "resolved: Resolved: Monitor service is down")
	if len(e.firing()) != 0 {
		t.Fatal("still firing")
	}

	// CPU, memory, disk capacity and SMART (AT-F06-04).
	passed := false
	e.src.cpu = 95
	e.src.host = metrics.Host{Memory: agentproto.MemoryInfo{Total: 100}, MemoryUsed: 50}
	e.src.inv = agentproto.StorageInventory{Disks: []agentproto.Disk{{Path: "/dev/sdb", Name: "sdb", Model: "Disk", Serial: "S1",
		SMART: agentproto.SMART{Available: true, Passed: &passed, Message: "reallocated sectors"},
		FileSystems: []agentproto.FileSystem{{Path: "/dev/sdb1", FSType: "ext4", FSSizeBytes: 100, FSUsedBytes: 96, Mountpoints: []string{"/srv/kernhaven/data"}},
			{Path: "/dev/sdb2", FSSizeBytes: 100, FSUsedBytes: 99}}}}} // sdb2 is not mounted
	e.round()
	got := strings.Join(e.firing(), ",")
	for _, want := range []string{"cpu_high/host", "disk_full//dev/sdb1", "smart_failed//dev/sdb"} {
		if !strings.Contains(got, want) {
			t.Errorf("%s not firing in %s", want, got)
		}
	}
	if strings.Contains(got, "memory_high") || strings.Contains(got, "sdb2") {
		t.Fatalf("firing %s", got)
	}
	// Thresholds are editable; a disabled rule ends its alerts without a message.
	n := len(e.rcv.titles())
	r, _ := e.s.SetRule(e.ctx, Actor{Name: "owner"}, RuleDiskFull, RuleInput{Enabled: true, Params: map[string]float64{"percent": 97}, Channels: []int64{e.ch.ID}})
	if r.Params["percent"] != 97 {
		t.Fatalf("params %+v", r.Params)
	}
	e.round()
	if strings.Contains(strings.Join(e.firing(), ","), "disk_full") {
		t.Fatal("disk_full still firing above the new threshold")
	}
	e.s.SetRule(e.ctx, Actor{Name: "owner"}, RuleCPUHigh, RuleInput{Enabled: false})
	e.round()
	if strings.Contains(strings.Join(e.firing(), ","), "cpu_high") || len(e.rcv.titles()) != n+1 /* disk resolved */ {
		t.Fatalf("disabled rule: %v %v", e.firing(), e.rcv.titles())
	}
	if _, err := e.s.SetRule(e.ctx, Actor{}, RuleCPUHigh, RuleInput{Params: map[string]float64{"percent": 150}}); err == nil {
		t.Fatal("out-of-range threshold accepted")
	}
	if _, err := e.s.SetRule(e.ctx, Actor{}, RuleCPUHigh, RuleInput{Params: map[string]float64{"cores": 1}}); err == nil {
		t.Fatal("unknown parameter accepted")
	}
	if _, err := e.s.SetRule(e.ctx, Actor{}, RuleCPUHigh, RuleInput{Channels: []int64{999}}); err == nil {
		t.Fatal("unknown channel accepted")
	}
}

// AT-F12-04: one warning per stage (30, 14, 3 days, expired).
func TestCertificateExpiry(t *testing.T) {
	e := newEnv(t)
	now := e.clk.now()
	e.src.certs = []certs.Certificate{
		{ID: 1, Names: []string{"media.lan"}, Hosts: []string{"media.lan"}, Issuer: "CN=Own", NotAfter: now.Add(20 * 24 * time.Hour)},
		{ID: 2, Names: []string{"old.lan"}, Hosts: nil, NotAfter: now.Add(24 * time.Hour)}, // not in use
	}
	e.round()
	e.round()
	e.expectSent("firing: Certificate for media.lan expires in 20 days (2026-11-18)")
	e.clk.add(8 * 24 * time.Hour) // 12 days left
	e.round()
	e.clk.add(9 * 24 * time.Hour) // 3 days left
	e.round()
	e.clk.add(24 * time.Hour) // 2 days left: same stage, nothing new
	e.round()
	e.clk.add(3 * 24 * time.Hour) // expired
	e.round()
	e.round()
	got := e.rcv.titles()
	if len(got) != 4 || !strings.Contains(got[1], "expires in 12 days") || !strings.Contains(got[2], "expires in 3 days") || !strings.Contains(got[3], "has expired") {
		t.Fatalf("stages %q", got)
	}
	list, _ := e.s.Alerts(e.ctx, false)
	if list[0].Severity != "critical" || list[3].Severity != "warning" {
		t.Fatalf("severities %+v", list)
	}
}

// Failed jobs and security events are events: each is sent once.
func TestEvents(t *testing.T) {
	e := newEnv(t)
	at := func(d time.Duration) *time.Time { v := e.clk.now().Add(d); return &v }
	e.src.failed = []jobs.Job{{ID: 1, Kind: "stack.deploy", Error: "old", FinishedAt: at(-time.Hour)}}
	e.src.records = []audit.Record{{Seq: 1, Action: "user.create", Result: audit.Success, Details: map[string]string{"role": "owner", "username": "old"}}}
	e.round() // first run starts after existing failures and records
	e.expectSent()

	e.clk.add(time.Minute)
	e.src.failed = append(e.src.failed, jobs.Job{ID: 2, Kind: "backup.run", Error: "target unreachable", FinishedAt: at(0)})
	add := func(r audit.Record) {
		r.Seq = int64(len(e.src.records) + 1)
		r.Time = e.clk.now()
		e.src.records = append(e.src.records, r)
	}
	add(audit.Record{Action: "auth.lockout", Target: "user:3", Details: map[string]string{"failed_logins": "5"}})
	add(audit.Record{Action: "auth.mfa_policy", Result: audit.Success, Actor: "owner", Details: map[string]string{"downgrade": "true", "required_removed": "admin"}})
	add(audit.Record{Action: "user.update", Result: audit.Success, Actor: "owner", Target: "user:4", Details: map[string]string{"role_from": "viewer", "role_to": "admin"}})
	add(audit.Record{Action: "user.update", Result: audit.Success, Details: map[string]string{"role_from": "admin", "role_to": "viewer"}}) // not an escalation
	for i := 0; i < 9; i++ {
		add(audit.Record{Action: "auth.login", Result: audit.Failure})
	}
	e.round()
	got := e.rcv.titles()
	if len(got) != 4 || !strings.Contains(strings.Join(got, "|"), "Job #2 (backup.run) failed") || !strings.Contains(strings.Join(got, "|"), "A user became admin") {
		t.Fatalf("events %q", got)
	}
	// The tenth failed sign-in within 10 minutes makes a burst, sent once.
	add(audit.Record{Action: "auth.login", Result: audit.Failure})
	e.round()
	add(audit.Record{Action: "auth.login", Result: audit.Failure})
	e.round()
	if got := e.rcv.titles(); len(got) != 5 || !strings.Contains(got[4], "failed sign-ins") {
		t.Fatalf("burst %q", got)
	}
	// A broken audit chain fires until it verifies again.
	e.src.chainOK = false
	e.clk.add(time.Hour)
	e.round()
	if !strings.Contains(strings.Join(e.firing(), ","), "security/audit_chain") {
		t.Fatalf("chain %v", e.firing())
	}
	e.src.chainOK = true
	e.clk.add(time.Hour)
	e.round()
	if len(e.firing()) != 0 {
		t.Fatalf("chain still firing")
	}
}

// AT-F16-03: retries with backoff, final failure, rate limit, delivery log.
func TestDelivery(t *testing.T) {
	e := newEnv(t)
	e.rcv.status = http.StatusBadGateway
	e.src.health = []metrics.Check{{Name: "agent", Label: "Host agent", Status: metrics.StatusDown}}
	e.round()
	e.round() // fires; first attempt fails
	ds, _ := e.s.Deliveries(e.ctx)
	if len(ds) != 1 || ds[0].Status != "pending" || ds[0].Attempts != 1 || !strings.Contains(ds[0].LastError, "HTTP 502") || !ds[0].NextAt.Equal(e.clk.now().Add(time.Minute)) {
		t.Fatalf("after one attempt %+v", ds)
	}
	e.s.Deliver(e.ctx) // not due yet
	for i, wait := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute} {
		e.clk.add(wait - time.Second)
		e.s.Deliver(e.ctx)
		if ds, _ = e.s.Deliveries(e.ctx); ds[0].Attempts != i+1 {
			t.Fatalf("attempt %d too early: %+v", i+2, ds[0])
		}
		e.clk.add(time.Second)
		e.s.Deliver(e.ctx)
	}
	ds, _ = e.s.Deliveries(e.ctx)
	if ds[0].Status != "failed" || ds[0].Attempts != MaxAttempts || len(e.rcv.titles()) != MaxAttempts {
		t.Fatalf("final %+v, %d requests", ds[0], len(e.rcv.titles()))
	}

	// Rate limit: 20 per channel and hour, then dropped.
	e.rcv.status = 0
	for i := 0; i < RatePerHour+2; i++ {
		// Several jobs finish in the same millisecond; none is lost.
		e.src.failed = append(e.src.failed, jobs.Job{ID: int64(100 + i), Kind: "x", FinishedAt: ptr(e.clk.now().Add(time.Second + time.Duration(i/3)*time.Millisecond))})
	}
	e.clk.add(2 * time.Second)
	e.round()
	ds, _ = e.s.Deliveries(e.ctx)
	counts := map[string]int{}
	for _, d := range ds {
		if d.Kind == "fire" && strings.Contains(d.Title, "Job #") {
			counts[d.Status]++
		}
	}
	if counts["sent"] != RatePerHour || counts["dropped"] < 1 {
		t.Fatalf("rate limit %v", counts)
	}
	// A test message ignores the rate limit and reports its result at once.
	d, err := e.s.Test(e.ctx, Actor{Name: "owner"}, e.ch.ID)
	if err != nil || d.Status != "sent" || d.Kind != "test" {
		t.Fatalf("test %+v %v", d, err)
	}
}

func ptr(t time.Time) *time.Time { return &t }
