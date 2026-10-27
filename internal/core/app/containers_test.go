package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
)

// memDocker is an in-memory Docker Engine for Core-level tests. Real Docker
// is covered by the agent integration tests.
type memDocker struct {
	mu         sync.Mutex
	containers map[string]agentproto.ContainerSummary
	labels     map[string]map[string]string
	volumes    map[string]bool
	conflict   bool
	specs      map[string]agentproto.ContainerSpec
	networks   map[string]map[string]string
	volLabels  map[string]map[string]string
	// data is the content of each volume (M8 snapshot tests).
	data      map[string]string
	exitCodes map[string]int
	// block makes Create wait for images containing "block" until closed.
	block   chan struct{}
	waiting atomic.Int32 // Create calls waiting on block
}

func newMemDocker() *memDocker {
	return &memDocker{containers: map[string]agentproto.ContainerSummary{}, labels: map[string]map[string]string{}, volumes: map[string]bool{},
		specs: map[string]agentproto.ContainerSpec{}, networks: map[string]map[string]string{}, volLabels: map[string]map[string]string{},
		data: map[string]string{}, exitCodes: map[string]int{}}
}

func (m *memDocker) Info(context.Context) (agentproto.DockerInfo, error) {
	return agentproto.DockerInfo{ServerVersion: "test"}, nil
}
func (m *memDocker) ListContainers(context.Context, bool) ([]agentproto.ContainerSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []agentproto.ContainerSummary{}
	for _, c := range m.containers {
		out = append(out, c)
	}
	return out, nil
}
func (m *memDocker) Inspect(_ context.Context, id string) (agentproto.ContainerDetail, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = m.key(id)
	c, ok := m.containers[id]
	if !ok {
		return agentproto.ContainerDetail{}, docker.ErrNotFound
	}
	exit := 0
	if c.State == "exited" {
		exit = 1
	}
	if code, ok := m.exitCodes[id]; ok {
		exit = code
	}
	return agentproto.ContainerDetail{ID: c.ID, Name: id, Status: c.State, Running: c.State == "running", ExitCode: exit, Labels: c.Labels}, nil
}

// key resolves a container name or ID (like Docker). Callers hold m.mu.
func (m *memDocker) key(ref string) string {
	for name, c := range m.containers {
		if c.ID == ref {
			return name
		}
	}
	return ref
}

func (m *memDocker) setState(id, state string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = m.key(id)
	c, ok := m.containers[id]
	if !ok {
		return false, docker.ErrNotFound
	}
	changed := c.State != state
	c.State = state
	m.containers[id] = c
	return changed, nil
}

// Start runs a container; images containing "exits" stop immediately.
// Volume-copy helpers copy the data and exit with 0; images containing
// "migrate" overwrite the data of their volumes, like a schema migration.
func (m *memDocker) Start(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	name := m.key(id)
	c := m.containers[name]
	spec := m.specs[name]
	if c.Labels[agent.LabelHelper] == "volume-copy" {
		var from, to string
		for _, mt := range spec.Mounts {
			if mt.Target == "/from" {
				from = mt.Source
			} else if mt.Target == "/to" {
				to = mt.Source
			}
		}
		m.data[to] = m.data[from]
		m.exitCodes[name] = 0
		c.State = "exited"
		m.containers[name] = c
		m.mu.Unlock()
		return true, nil
	}
	if strings.Contains(c.Image, "migrate") {
		for _, mt := range spec.Mounts {
			if mt.Type == "volume" {
				m.data[mt.Source] = "migrated by " + c.Image
			}
		}
	}
	exits := strings.Contains(c.Image, "exits")
	m.mu.Unlock()
	if exits {
		return m.setState(id, "exited")
	}
	return m.setState(id, "running")
}
func (m *memDocker) Stop(_ context.Context, id string, _ time.Duration) (bool, error) {
	return m.setState(id, "exited")
}
func (m *memDocker) Restart(_ context.Context, id string, _ time.Duration) (bool, error) {
	return m.setState(id, "running")
}
func (m *memDocker) Pause(_ context.Context, id string) (bool, error) {
	return m.setState(id, "paused")
}
func (m *memDocker) Unpause(_ context.Context, id string) (bool, error) {
	return m.setState(id, "running")
}
func (m *memDocker) Create(ctx context.Context, s agentproto.ContainerSpec, labels map[string]string) (agentproto.CreateResult, error) {
	m.mu.Lock()
	block := m.block
	m.mu.Unlock()
	if block != nil && strings.Contains(s.Image, "block") {
		m.waiting.Add(1)
		defer m.waiting.Add(-1)
		select {
		case <-block:
		case <-ctx.Done():
			return agentproto.CreateResult{}, ctx.Err()
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.exitCodes, s.Name)
	if _, dup := m.containers[s.Name]; dup {
		return agentproto.CreateResult{}, docker.ErrConflict
	}
	m.containers[s.Name] = agentproto.ContainerSummary{ID: "id-" + s.Name, Names: []string{s.Name}, Image: s.Image, State: "created", Labels: labels}
	m.specs[s.Name] = s
	m.labels[s.Name] = labels
	return agentproto.CreateResult{ID: "id-" + s.Name, Warnings: []string{}}, nil
}
func (m *memDocker) Remove(_ context.Context, id string, force, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	id = m.key(id)
	c, ok := m.containers[id]
	if !ok {
		return docker.ErrNotFound
	}
	if c.State == "running" && !force {
		return docker.ErrConflict
	}
	delete(m.containers, id)
	return nil
}
func (m *memDocker) Logs(_ context.Context, r agentproto.LogsRequest) (agentproto.Logs, error) {
	return agentproto.Logs{Lines: []agentproto.LogLine{{Stream: "stdout", Text: "hello from " + r.ID}}}, nil
}
func (m *memDocker) ListImages(context.Context) ([]agentproto.ImageSummary, error) {
	return []agentproto.ImageSummary{}, nil
}
func (m *memDocker) Pull(_ context.Context, ref string) (agentproto.PullResult, error) {
	if strings.Contains(ref, "missing") {
		return agentproto.PullResult{}, docker.ErrNotFound
	}
	return agentproto.PullResult{Reference: ref, ID: "sha256:1", Digest: ref + "@sha256:" + strings.Repeat("b", 64)}, nil
}
func (m *memDocker) RemoveImage(context.Context, string, bool) error { return nil }
func (m *memDocker) PruneImages(context.Context) (agentproto.PruneResult, error) {
	return agentproto.PruneResult{}, nil
}
func (m *memDocker) ListVolumes(context.Context) ([]agentproto.VolumeSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []agentproto.VolumeSummary{}
	for n := range m.volumes {
		out = append(out, agentproto.VolumeSummary{Name: n, Labels: m.volLabels[n]})
	}
	return out, nil
}
func (m *memDocker) CreateVolume(_ context.Context, name string, labels map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.volumes[name] = true
	m.volLabels[name] = labels
	return nil
}
func (m *memDocker) RemoveVolume(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.conflict {
		return docker.ErrConflict
	}
	delete(m.volumes, name)
	delete(m.data, name)
	return nil
}
func (m *memDocker) ListNetworks(context.Context) ([]agentproto.NetworkSummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := []agentproto.NetworkSummary{}
	for n, l := range m.networks {
		out = append(out, agentproto.NetworkSummary{ID: "net-" + n, Name: n, Labels: l})
	}
	return out, nil
}
func (m *memDocker) CreateNetwork(_ context.Context, name string, _ bool, labels map[string]string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.networks[name] = labels
	return "net-" + name, nil
}
func (m *memDocker) RemoveNetwork(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.networks, name)
	return nil
}

// withAgent returns a harness whose Core talks to a real agent server backed by memDocker.
func withAgent(t *testing.T) (*harness, *memDocker) {
	t.Helper()
	return withAgentOpts(t, nil)
}

// withAgentOpts also adjusts the Core options.
func withAgentOpts(t *testing.T, adjust func(*Options)) (*harness, *memDocker) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "agent.sock")
	h := newHarnessFull(t, func(c *config.Config) { c.Agent.Socket = sock }, adjust)
	pub, err := agentproto.ReadPublicKey(filepath.Join(h.dataDir, "agent-grant.pub"))
	if err != nil {
		t.Fatal(err)
	}
	md := newMemDocker()
	srv := agent.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, md, agent.Options{})
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return h, md
}

func auditCount(t *testing.T, h *harness, action, result string) int {
	t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = ? AND result = ?`, action, result).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

var safe = map[string]any{"name": "web", "image": "nginx:1.27", "user": "101", "memory_bytes": 268435456}

// AT-F02-01, AT-F02-02: lifecycle through the Core API, audited.
func TestContainerLifecycleThroughCore(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	h.createUser(owner, "olga", authz.Operator)

	var created struct {
		ID       string
		Warnings []string
	}
	owner.do("POST", "/api/v1/containers", map[string]any{"spec": safe, "start": true}).expect(201).json(&created)
	if created.ID != "id-web" || len(created.Warnings) == 0 {
		t.Fatalf("created %+v", created)
	}
	if md.labels["web"]["io.kernhaven.created_by"] != "owner" {
		t.Fatalf("labels %v", md.labels["web"])
	}
	var list struct{ Containers []agentproto.ContainerSummary }
	h.loginAs("olga").do("GET", "/api/v1/containers", nil).expect(200).json(&list)
	if len(list.Containers) != 1 || list.Containers[0].State != "running" {
		t.Fatalf("list %+v", list)
	}
	op := h.loginAs("olga")
	for _, a := range []string{"stop", "start", "restart", "pause", "unpause"} {
		op.do("POST", "/api/v1/containers/web/"+a, nil).expect(200)
	}
	op.do("POST", "/api/v1/containers/web/stop", map[string]int{"timeout_seconds": 3}).expect(200)
	var logs agentproto.Logs
	op.do("GET", "/api/v1/containers/web/logs?tail=50", nil).expect(200).json(&logs)
	if len(logs.Lines) != 1 || logs.Lines[0].Text != "hello from web" {
		t.Fatalf("logs %+v", logs)
	}
	if r := op.do("DELETE", "/api/v1/containers/web", nil); r.Code != 403 {
		t.Fatalf("operator removed a container: %d", r.Code)
	}
	if r := owner.do("GET", "/api/v1/containers/nope", nil); r.Code != 404 {
		t.Fatalf("missing container: %d", r.Code)
	}
	owner.do("POST", "/api/v1/containers/web/start", nil).expect(200)
	if r := owner.do("DELETE", "/api/v1/containers/web", nil); r.Code != 409 {
		t.Fatalf("remove running: %d", r.Code)
	}
	owner.do("DELETE", "/api/v1/containers/web?force=true", nil).expect(204)
	for action, n := range map[string]int{"container.create": 1, "container.stop": 2, "container.pause": 1, "container.remove": 1} {
		if got := auditCount(t, h, action, "success"); got != n {
			t.Errorf("%s success records = %d, want %d", action, got, n)
		}
	}
	if auditCount(t, h, "container.remove", "failure") != 1 {
		t.Error("failed remove not audited")
	}
}

// AT-F02-04: policy enforcement and owner-only, audited exceptions.
func TestContainerPolicyThroughCore(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	h.createUser(owner, "adele", authz.Admin)
	admin := h.loginAs("adele")
	priv := map[string]any{"name": "vpn", "image": "alpine:3", "cap_add": []string{"NET_ADMIN"}}

	var eval struct {
		Valid      bool
		Violations []struct{ Rule string }
		Warnings   []struct{ Rule string }
	}
	admin.do("POST", "/api/v1/containers/validate", priv).expect(200).json(&eval)
	if !eval.Valid || len(eval.Violations) != 1 || eval.Violations[0].Rule != "capability" || len(eval.Warnings) == 0 {
		t.Fatalf("evaluation %+v", eval)
	}

	r := admin.do("POST", "/api/v1/containers", map[string]any{"spec": priv})
	if r.Code != 422 || r.errorCode() != "policy_violation" || !strings.Contains(r.Body.String(), `"violations"`) {
		t.Fatalf("admin without exception: %d %s", r.Code, r.Body)
	}
	exc := []map[string]string{{"rule": "capability", "reason": "WireGuard needs NET_ADMIN for its interface"}}
	if r := admin.do("POST", "/api/v1/containers", map[string]any{"spec": priv, "exceptions": exc}); r.Code != 403 {
		t.Fatalf("admin approved an exception: %d", r.Code)
	}
	if r := owner.do("POST", "/api/v1/containers", map[string]any{"spec": priv, "exceptions": []map[string]string{{"rule": "capability", "reason": "short"}}}); r.Code != 422 {
		t.Fatalf("short reason accepted: %d", r.Code)
	}
	owner.do("POST", "/api/v1/containers", map[string]any{"spec": priv, "exceptions": exc}).expect(201)
	if md.labels["vpn"]["io.kernhaven.policy.exceptions"] != "capability" {
		t.Fatalf("exception label %v", md.labels["vpn"])
	}
	if auditCount(t, h, "policy.exception", "success") != 1 || auditCount(t, h, "policy.exception", "failure") != 1 {
		t.Fatal("policy exceptions not audited")
	}

	sock := map[string]any{"name": "evil", "image": "alpine:3", "mounts": []map[string]any{{"type": "bind", "source": "/var/run/docker.sock", "target": "/s"}}}
	for _, ex := range []string{"docker-socket", "bind-mount", "sensitive-path"} {
		r := owner.do("POST", "/api/v1/containers", map[string]any{"spec": sock, "exceptions": []map[string]string{{"rule": ex, "reason": "I really want the docker socket"}}})
		if r.Code != 422 {
			t.Errorf("docker socket with exception %s: %d", ex, r.Code)
		}
	}
	if _, ok := md.containers["evil"]; ok {
		t.Fatal("container with docker socket was created")
	}
	if r := owner.do("POST", "/api/v1/containers", map[string]any{"spec": map[string]any{"name": "-x", "image": "alpine"}}); r.Code != 422 || r.errorCode() != "validation_failed" {
		t.Fatalf("invalid spec: %d %s", r.Code, r.Body)
	}
	if r := owner.do("POST", "/api/v1/containers", map[string]any{"spec": map[string]any{"name": "x", "image": "alpine", "devices_cgroup": "a"}}); r.Code != 400 {
		t.Fatalf("unknown spec field: %d", r.Code)
	}
}

// AT-F02-05: pulls run as jobs and record the digest.
func TestImagePullJob(t *testing.T) {
	h, _ := withAgent(t)
	owner := h.setupOwner()
	h.startJobs()
	var res struct {
		JobID int64 `json:"job_id"`
	}
	owner.do("POST", "/api/v1/images/pull", map[string]string{"reference": "alpine:3"}).expect(202).json(&res)
	j := h.waitJob(res.JobID, jobs.Succeeded)
	found := false
	for _, l := range j.Logs {
		found = found || strings.Contains(l.Message, "alpine:3@sha256:")
	}
	if !found {
		t.Fatalf("digest not logged: %+v", j.Logs)
	}
	owner.do("POST", "/api/v1/images/pull", map[string]string{"reference": "kernhaven/missing:1"}).expect(202).json(&res)
	failed := h.waitJob(res.JobID, jobs.Failed)
	if failed.Attempts != 1 {
		t.Fatalf("not-found pull retried: %d attempts", failed.Attempts)
	}
	if r := owner.do("POST", "/api/v1/images/pull", map[string]string{"reference": "Bad Ref"}); r.Code != 422 {
		t.Fatalf("bad reference: %d", r.Code)
	}
}

// AT-F02-06: volumes, networks and conflicts.
func TestVolumesAndNetworksThroughCore(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	owner.do("POST", "/api/v1/volumes", map[string]string{"name": "data"}).expect(201)
	owner.do("POST", "/api/v1/networks", map[string]any{"name": "apps", "internal": true}).expect(201)
	md.mu.Lock()
	md.conflict = true
	md.mu.Unlock()
	if r := owner.do("DELETE", "/api/v1/volumes/data", nil); r.Code != 409 || r.errorCode() != "conflict" {
		t.Fatalf("in-use volume: %d %s", r.Code, r.Body)
	}
	if r := owner.do("DELETE", "/api/v1/networks/bridge", nil); r.Code != 422 {
		t.Fatalf("remove bridge: %d", r.Code)
	}
	owner.do("DELETE", "/api/v1/networks/apps", nil).expect(204)
	if auditCount(t, h, "volume.remove", "failure") != 1 || auditCount(t, h, "network.create", "success") != 1 {
		t.Fatal("volume/network actions not audited")
	}
}

func TestContainersWithoutAgent(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	for _, path := range []string{"/api/v1/containers", "/api/v1/images", "/api/v1/volumes", "/api/v1/networks"} {
		if r := owner.do("GET", path, nil); r.Code != http.StatusServiceUnavailable || r.errorCode() != "agent_unavailable" {
			t.Errorf("%s: %d %s", path, r.Code, r.errorCode())
		}
	}
}
