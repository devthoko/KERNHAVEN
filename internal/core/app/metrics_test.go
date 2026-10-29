package app

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	"github.com/devthoko/KERNHAVEN/internal/agent/monitor"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/metrics"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
)

// fakeHost writes /proc and /sys fixtures for the real monitor role.
type fakeHost struct {
	t                   *testing.T
	proc, sys           string
	busy, total         uint64
	readSectors, rxByte uint64
}

func (f *fakeHost) write() {
	f.t.Helper()
	files := map[string]string{
		filepath.Join(f.proc, "stat"):                          fmt.Sprintf("cpu  %d 0 0 %d 0 0 0 0 0 0\ncpu0 1 0 0 1 0 0 0 0 0 0\ncpu1 1 0 0 1 0 0 0 0 0 0\n", f.busy, f.total-f.busy),
		filepath.Join(f.proc, "meminfo"):                       "MemTotal: 8000000 kB\nMemAvailable: 6000000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n",
		filepath.Join(f.proc, "loadavg"):                       "1.50 1.00 0.50 1/100 42\n",
		filepath.Join(f.proc, "diskstats"):                     fmt.Sprintf("   8 0 sda 1 0 %d 0 1 0 0 0 0 0 0\n", f.readSectors),
		filepath.Join(f.proc, "net/dev"):                       fmt.Sprintf("h\nh\n  eth0: %d 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n", f.rxByte),
		filepath.Join(f.sys, "block/sda/size"):                 "1",
		filepath.Join(f.sys, "class/hwmon/hwmon0/name"):        "cpu_thermal",
		filepath.Join(f.sys, "class/hwmon/hwmon0/temp1_input"): "51000",
	}
	for p, s := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			f.t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			f.t.Fatal(err)
		}
	}
}

// withMonitor starts a Core with the monitor role on fixtures and a Docker agent.
func withMonitor(t *testing.T) (*harness, *fakeHost, *memDocker) {
	t.Helper()
	dir := t.TempDir()
	monSock, dockerSock := filepath.Join(dir, "monitor.sock"), filepath.Join(dir, "agent.sock")
	h := newHarnessWith(t, func(c *config.Config) {
		c.Agent.MonitorSocket, c.Agent.Socket = monSock, dockerSock
		c.Agent.StorageSocket, c.Agent.FilesSocket = "", ""
	})
	fh := &fakeHost{t: t, proc: filepath.Join(dir, "proc"), sys: filepath.Join(dir, "sys"), busy: 1000, total: 10000}
	fh.write()
	serveAgent(t, h, monSock, nil, agent.Options{Monitor: &monitor.Reader{Proc: fh.proc, Sys: fh.sys, Now: h.clock.Now}})
	md := newMemDocker()
	md.stats = map[string]agentproto.ContainerStats{}
	serveAgent(t, h, dockerSock, md, agent.Options{})
	return h, fh, md
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// AT-F13-01, AT-F13-02: rates from two readings of the real monitor role and
// the Docker agent.
func TestMetricsNow(t *testing.T) {
	h, fh, md := withMonitor(t)
	owner := h.setupOwner()
	h.createUser(owner, "viewer1", authz.Viewer)
	viewer := h.loginAs("viewer1")
	ctx := context.Background()
	if r := viewer.do("GET", "/api/v1/metrics/host", nil); r.Code != 503 || r.errorCode() != "metrics_pending" {
		t.Fatalf("before a reading: %d %s", r.Code, r.Body)
	}
	md.mu.Lock()
	md.containers["web"] = agentproto.ContainerSummary{ID: "id-web", Names: []string{"web"}, State: "running"}
	md.stats["web"] = agentproto.ContainerStats{CPUNanos: 1e9, SystemNanos: 100e9, OnlineCPUs: 4, Memory: 50 << 20, MemoryLimit: 256 << 20, NetRx: 1000, BlockWrite: 0}
	md.mu.Unlock()
	h.app.Metrics.Sample(ctx)

	// 15 s later: 150 of 1000 jiffies busy, 2000 sectors read, 15000 bytes received.
	h.clock.Advance(15 * time.Second)
	fh.busy, fh.total, fh.readSectors, fh.rxByte = fh.busy+150, fh.total+1000, 2000, 15000
	fh.write()
	md.mu.Lock()
	md.stats["web"] = agentproto.ContainerStats{CPUNanos: 4e9, SystemNanos: 120e9, OnlineCPUs: 4, Memory: 60 << 20, MemoryLimit: 256 << 20, NetRx: 31000, BlockWrite: 1500}
	md.mu.Unlock()
	h.app.Metrics.Sample(ctx)

	var host metrics.Host
	viewer.do("GET", "/api/v1/metrics/host", nil).expect(200).json(&host)
	if host.CPUPercent == nil || !near(*host.CPUPercent, 15) || host.CPUs != 2 || host.Load[0] != 1.5 || host.MemoryUsed != 2000000*1024 {
		t.Fatalf("host %+v", host)
	}
	if len(host.Disks) != 1 || !near(host.Disks[0].In, 2000*512/15.0) || len(host.Interfaces) != 1 || !near(host.Interfaces[0].In, 1000) {
		t.Fatalf("rates %+v %+v", host.Disks, host.Interfaces)
	}
	if len(host.Temperatures) != 1 || host.Temperatures[0].Celsius != 51 {
		t.Fatalf("temperatures %+v", host.Temperatures)
	}
	var cs struct{ Containers []metrics.Container }
	viewer.do("GET", "/api/v1/metrics/containers", nil).expect(200).json(&cs)
	c := cs.Containers[0]
	// 3e9 of 20e9 host nanoseconds = 15 % of the whole host (not 60 % of one
	// CPU as `docker stats` shows); 30000 bytes in 15 s.
	if len(cs.Containers) != 1 || c.Name != "web" || c.CPUPercent == nil || !near(*c.CPUPercent, 15) || c.Memory != 60<<20 || !near(*c.NetRx, 2000) || !near(*c.BlockWrite, 100) {
		t.Fatalf("containers %+v", cs)
	}

	var hist metrics.History
	viewer.do("GET", "/api/v1/metrics/history?series=host.cpu&range=1h", nil).expect(200).json(&hist)
	if hist.Unit != "percent" || len(hist.Points) != 1 || !near(hist.Points[0].Avg, 15) {
		t.Fatalf("history %+v", hist)
	}
	viewer.do("GET", "/api/v1/metrics/history?series=container.web.memory&range=1h", nil).expect(200).json(&hist)
	if len(hist.Points) != 2 || hist.Unit != "bytes" {
		t.Fatalf("container history %+v", hist)
	}
	viewer.do("GET", "/api/v1/metrics/history?series=host.cpu&range=5m", nil).expect(422)
	var ser struct{ Series []metrics.SeriesInfo }
	viewer.do("GET", "/api/v1/metrics/series", nil).expect(200).json(&ser)
	keys := []string{}
	for _, s := range ser.Series {
		keys = append(keys, s.Key)
	}
	for _, want := range []string{"host.cpu", "host.memory", "host.load1", "host.disk_read", "host.net_rx", "host.temp.cpu_thermal_temp1", "container.web.cpu", "container.web.blk_write"} {
		if !strings.Contains(strings.Join(keys, ","), want) {
			t.Errorf("series %s missing in %v", want, keys)
		}
	}
}

// AT-F13-03: 1-minute and 15-minute aggregates, retention and the series cap.
func TestMetricsHistory(t *testing.T) {
	h, fh, md := withMonitor(t)
	h.setupOwner()
	ctx := context.Background()
	start := h.clock.Now()
	md.mu.Lock()
	md.containers["db"] = agentproto.ContainerSummary{ID: "id-db", Names: []string{"db"}, State: "running"}
	md.mu.Unlock()
	// 40 minutes at 15 s: 10 % CPU, with a single 50 % sample in minute 3.
	for i := 0; i <= 160; i++ {
		busy := uint64(100)
		if i == 13 {
			busy = 500
		}
		fh.busy, fh.total = fh.busy+busy, fh.total+1000
		fh.write()
		h.app.Metrics.Sample(ctx)
		h.clock.Advance(15 * time.Second)
	}
	var hist metrics.History
	owner := h.loginAs("owner") // 40 minutes passed: the first session idled out
	owner.do("GET", "/api/v1/metrics/history?series=host.cpu&range=24h", nil).expect(200).json(&hist)
	if hist.Resolution != 60 || len(hist.Points) != 40 {
		t.Fatalf("minutes: %d points, resolution %d", len(hist.Points), hist.Resolution)
	}
	spike := hist.Points[3]
	if !near(spike.Max, 50) || !near(spike.Avg, 20) || !near(hist.Points[5].Avg, 10) || !near(hist.Points[5].Max, 10) {
		t.Fatalf("minute 3 %+v, minute 5 %+v", spike, hist.Points[5])
	}
	owner.do("GET", "/api/v1/metrics/history?series=host.cpu&range=7d", nil).expect(200).json(&hist)
	if hist.Resolution != 900 || len(hist.Points) != 2 || !near(hist.Points[0].Max, 50) || !near(hist.Points[1].Avg, 10) {
		t.Fatalf("quarters %+v", hist.Points)
	}
	if !hist.Points[0].T.Equal(start.Truncate(15 * time.Minute)) {
		t.Fatalf("bucket start %s", hist.Points[0].T)
	}

	// The container goes away; a day later minute points are pruned, after
	// a week its series is deleted while the host keeps reporting.
	md.mu.Lock()
	delete(md.containers, "db")
	md.mu.Unlock()
	count := func(q string, args ...any) int {
		var n int
		if err := h.db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	h.clock.Advance(25 * time.Hour)
	h.app.Metrics.Sample(ctx)
	if n := count(`SELECT count(*) FROM metric_points WHERE resolution = 60 AND ts < ?`, h.clock.Now().Add(-24*time.Hour).UnixMilli()); n != 0 {
		t.Fatalf("%d minute points older than 24 h", n)
	}
	if count(`SELECT count(*) FROM metric_points WHERE resolution = 900`) == 0 {
		t.Fatal("quarter points pruned too early")
	}
	h.clock.Advance(7 * 24 * time.Hour)
	h.app.Metrics.Sample(ctx)
	if count(`SELECT count(*) FROM metric_series WHERE key LIKE 'container.db.%'`) != 0 || count(`SELECT count(*) FROM metric_points WHERE ts < ?`, h.clock.Now().Add(-7*24*time.Hour).UnixMilli()) != 0 {
		t.Fatal("old series or points not deleted")
	}

	// At most MaxSeries series are stored.
	for i := count(`SELECT count(*) FROM metric_series`); i < metrics.MaxSeries; i++ {
		if _, err := h.db.Exec(`INSERT INTO metric_series (key, unit, last_ms) VALUES (?, 'bytes', ?)`, fmt.Sprintf("filler.%d", i), h.clock.Now().UnixMilli()); err != nil {
			t.Fatal(err)
		}
	}
	md.mu.Lock()
	md.containers["late"] = agentproto.ContainerSummary{ID: "id-late", Names: []string{"late"}, State: "running"}
	md.mu.Unlock()
	for i := 0; i < 8; i++ {
		h.app.Metrics.Sample(ctx)
		h.clock.Advance(15 * time.Second)
	}
	if count(`SELECT count(*) FROM metric_series`) != metrics.MaxSeries || count(`SELECT count(*) FROM metric_series WHERE key LIKE 'container.late.%'`) != 0 {
		t.Fatal("series cap not enforced")
	}
	if strings.Count(h.logs.String(), "metric series limit reached") != 1 {
		t.Fatal("cap not logged exactly once")
	}
}

// AT-F13-04: the health of every service.
func TestServiceHealth(t *testing.T) {
	h, _, _ := withMonitor(t)
	owner := h.setupOwner()
	h.createUser(owner, "viewer1", authz.Viewer)
	var res struct{ Services []metrics.Check }
	h.loginAs("viewer1").do("GET", "/api/v1/health/services", nil).expect(200).json(&res)
	got := map[string]string{}
	for _, c := range res.Services {
		got[c.Name] = c.Status
	}
	want := map[string]string{"core": "ok", "agent": "ok", "docker": "ok", "monitor": "ok", "storage": "not_configured", "files": "not_configured", "proxy": "not_configured", "caddy": "not_configured"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %s, want %s (%+v)", k, got[k], v, res.Services)
		}
	}

	// A configured service that does not answer is down, with the reason.
	h2 := newHarnessWith(t, func(c *config.Config) { c.Agent.MonitorSocket = filepath.Join(t.TempDir(), "missing.sock") })
	o2 := h2.setupOwner()
	o2.do("GET", "/api/v1/health/services", nil).expect(200).json(&res)
	for _, c := range res.Services {
		if c.Name == "monitor" && (c.Status != "down" || c.Detail == "") {
			t.Fatalf("monitor %+v", c)
		}
	}
	o2.do("GET", "/api/v1/metrics/host", nil).expect(503)
}
