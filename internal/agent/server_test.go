package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// fakeDocker records calls; tests that expect rejection before Docker set
// forbid=true so any call fails the test.
type fakeDocker struct {
	Docker // unimplemented methods panic; tests only call recorded ones
	mu     sync.Mutex
	calls  []string
	forbid bool
	t      *testing.T
	err    error
}

func (f *fakeDocker) setForbid(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forbid = v
}

func (f *fakeDocker) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeDocker) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// syncBuffer is a log sink that tests may read while the server writes.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (f *fakeDocker) record(s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.forbid {
		f.t.Errorf("docker called although the request should have been rejected: %s", s)
	}
	f.calls = append(f.calls, s)
	return f.err
}
func (f *fakeDocker) Info(context.Context) (agentproto.DockerInfo, error) {
	return agentproto.DockerInfo{ServerVersion: "29.0.0"}, f.record("info")
}
func (f *fakeDocker) ListContainers(_ context.Context, all bool) ([]agentproto.ContainerSummary, error) {
	return []agentproto.ContainerSummary{{ID: "abc", Names: []string{"web"}}}, f.record("list")
}
func (f *fakeDocker) Inspect(_ context.Context, id string) (agentproto.ContainerDetail, error) {
	return agentproto.ContainerDetail{ID: id}, f.record("inspect " + id)
}
func (f *fakeDocker) Start(_ context.Context, id string) (bool, error) {
	return true, f.record("start " + id)
}
func (f *fakeDocker) Stop(_ context.Context, id string, d time.Duration) (bool, error) {
	return true, f.record("stop " + id + " " + d.String())
}
func (f *fakeDocker) Restart(_ context.Context, id string, d time.Duration) (bool, error) {
	return true, f.record("restart " + id + " " + d.String())
}

type env struct {
	t      *testing.T
	sock   string
	priv   ed25519.PrivateKey
	docker *fakeDocker
	http   *http.Client
	logs   *syncBuffer
}

func start(t *testing.T, allowed []uint32) *env {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	fd := &fakeDocker{t: t}
	logs := &syncBuffer{}
	srv := NewServer(slog.New(slog.NewJSONHandler(logs, nil)), pub, allowed, fd, Options{})
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	cl := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}, Timeout: 5 * time.Second}
	return &env{t: t, sock: sock, priv: priv, docker: fd, http: cl, logs: logs}
}

func self() []uint32 { return []uint32{uint32(os.Getuid())} }

func (e *env) grant(op string, params []byte, mod func(*agentproto.Grant)) string {
	now := time.Now()
	g := agentproto.Grant{Op: op, ParamsSHA256: agentproto.ParamsHash(params), Actor: "owner", RequestID: "r",
		Nonce: agentproto.NewNonce(), IssuedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(30 * time.Second).UnixMilli()}
	if mod != nil {
		mod(&g)
	}
	tok, err := agentproto.Sign(e.priv, g)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

type reply struct {
	status int
	code   string
	result json.RawMessage
}

func (e *env) post(op string, body []byte) (reply, error) {
	resp, err := e.http.Post("http://agent/v1/op/"+op, "application/json", bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out struct {
		Result json.RawMessage `json:"result"`
		Error  struct{ Code string }
	}
	_ = json.Unmarshal(data, &out)
	return reply{status: resp.StatusCode, code: out.Error.Code, result: out.Result}, nil
}

func (e *env) call(op string, params string, mod func(*agentproto.Grant)) reply {
	e.t.Helper()
	p := []byte(params)
	body, _ := json.Marshal(agentproto.Request{Grant: e.grant(op, p, mod), Params: p})
	r, err := e.post(op, body)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// AT-M4-01: the allow-list is exactly these operations — no exec, no passthrough.
func TestOperationAllowList(t *testing.T) {
	want := []string{"agent.info", "containers.create", "containers.inspect", "containers.list", "containers.logs", "containers.pause",
		"containers.remove", "containers.restart", "containers.start", "containers.stop", "containers.unpause", "docker.info",
		"images.list", "images.prune", "images.pull", "images.remove", "networks.create", "networks.list", "networks.remove",
		"volumes.copy", "volumes.create", "volumes.list", "volumes.remove"}
	if got := OperationNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("operations = %v\nwant %v\n(adding an operation requires updating this test and the M4/M6/M8/M9 design)", got, want)
	}
}

// M9: the storage role offers only these operations — no Docker access, and
// the Docker role offers no storage operation (separate privilege domains).
func TestStorageRoleAllowList(t *testing.T) {
	want := []string{"agent.info", "storage.format", "storage.inventory", "storage.mount", "storage.unmount"}
	if got := StorageOperationNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("storage operations = %v\nwant %v", got, want)
	}
	// M10: the files role is a third privilege domain (file access only).
	want = []string{"agent.info", "files.copy", "files.list", "files.mkdir", "files.rename", "files.roots", "files.trash", "files.trash.list",
		"files.trash.purge", "files.trash.restore", "files.upload.abort", "files.upload.finish"}
	if got := FilesOperationNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("files operations = %v\nwant %v", got, want)
	}
	if got := StreamOperationNames(); !reflect.DeepEqual(got, []string{"files.read", "files.upload.append"}) {
		t.Fatalf("stream operations = %v", got)
	}
	// M12: the proxy role is a fourth privilege domain (Caddy and the network overview).
	want = []string{"agent.info", "network.overview", "proxy.apply", "proxy.status"}
	if got := ProxyOperationNames(); !reflect.DeepEqual(got, want) {
		t.Fatalf("proxy operations = %v\nwant %v", got, want)
	}
}

func TestValidRequestsReachDocker(t *testing.T) {
	e := start(t, self())
	if r := e.call("agent.info", "null", nil); r.status != 200 {
		t.Fatalf("agent.info: %+v", r)
	}
	if r := e.call("docker.info", "{}", nil); r.status != 200 || !strings.Contains(string(r.result), "29.0.0") {
		t.Fatalf("docker.info: %+v", r)
	}
	e.call("containers.list", `{"all":true}`, nil)
	e.call("containers.inspect", `{"id":"web-1"}`, nil)
	e.call("containers.start", `{"id":"web-1"}`, nil)
	e.call("containers.stop", `{"id":"web-1","timeout_seconds":5}`, nil)
	e.call("containers.restart", `{"id":"0123456789ab"}`, nil)
	want := []string{"info", "list", "inspect web-1", "start web-1", "stop web-1 5s", "restart 0123456789ab 10s"}
	if !reflect.DeepEqual(e.docker.callList(), want) {
		t.Fatalf("docker calls %v, want %v", e.docker.callList(), want)
	}
	if !strings.Contains(e.logs.String(), `"actor":"owner"`) {
		t.Fatal("operations are not logged with the actor")
	}
}

// AT-M4-02
func TestUnauthorizedPeerRejected(t *testing.T) {
	e := start(t, []uint32{uint32(os.Getuid()) + 4242})
	e.docker.setForbid(true)
	p := []byte(`{}`)
	body, _ := json.Marshal(agentproto.Request{Grant: e.grant("docker.info", p, nil), Params: p})
	if r, err := e.post("docker.info", body); err == nil {
		t.Fatalf("request from unauthorized peer was answered: %+v", r)
	}
	if !strings.Contains(e.logs.String(), "unauthorized peer") {
		t.Fatal("rejection not logged")
	}
}

// AT-M4-03, AT-M4-04
func TestGrantChecks(t *testing.T) {
	e := start(t, self())
	e.docker.setForbid(true)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	_ = other
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	params := []byte(`{"id":"web"}`)

	cases := map[string][]byte{}
	mk := func(grant string, p []byte) []byte {
		b, _ := json.Marshal(agentproto.Request{Grant: grant, Params: p})
		return b
	}
	cases["missing grant"] = mk("", params)
	cases["expired"] = mk(e.grant("containers.start", params, func(g *agentproto.Grant) {
		g.IssuedAtMS -= 120000
		g.ExpiresAtMS -= 120000
	}), params)
	forged, _ := agentproto.Sign(otherPriv, agentproto.Grant{Op: "containers.start", ParamsSHA256: agentproto.ParamsHash(params), Nonce: "n",
		IssuedAtMS: time.Now().UnixMilli(), ExpiresAtMS: time.Now().Add(time.Second).UnixMilli()})
	cases["wrong key"] = mk(forged, params)
	cases["grant for another op"] = mk(e.grant("containers.inspect", params, nil), params)
	cases["params substituted"] = mk(e.grant("containers.start", params, nil), []byte(`{"id":"db"}`))
	for name, body := range cases {
		r, err := e.post("containers.start", body)
		if err != nil {
			t.Fatal(err)
		}
		if r.status != 401 || r.code != agentproto.CodeInvalidGrant {
			t.Errorf("%s: %d %s", name, r.status, r.code)
		}
	}

	// Replay: the same grant twice.
	e.docker.setForbid(false)
	body := mk(e.grant("containers.start", params, nil), params)
	if r, _ := e.post("containers.start", body); r.status != 200 {
		t.Fatalf("first use: %+v", r)
	}
	if r, _ := e.post("containers.start", body); r.status != 401 || r.code != agentproto.CodeInvalidGrant {
		t.Fatalf("replay: %+v", r)
	}
}

// AT-M4-05: invalid parameters never reach Docker.
func TestInvalidParamsRejected(t *testing.T) {
	e := start(t, self())
	e.docker.setForbid(true)
	cases := map[string]struct{ op, params string }{
		"unknown field":     {"containers.start", `{"id":"web","privileged":true}`},
		"empty id":          {"containers.start", `{"id":""}`},
		"path in id":        {"containers.inspect", `{"id":"../images"}`},
		"slash in id":       {"containers.stop", `{"id":"a/b"}`},
		"too long id":       {"containers.start", `{"id":"` + strings.Repeat("a", 129) + `"}`},
		"negative timeout":  {"containers.stop", `{"id":"web","timeout_seconds":-1}`},
		"timeout too large": {"containers.restart", `{"id":"web","timeout_seconds":301}`},
		"wrong type":        {"containers.list", `{"all":"yes"}`},
		"params for empty":  {"docker.info", `{"x":1}`},
	}
	for name, tc := range cases {
		r := e.call(tc.op, tc.params, nil)
		if r.status != 400 || r.code != agentproto.CodeInvalidParams {
			t.Errorf("%s: %d %s", name, r.status, r.code)
		}
	}
	if r := e.call("containers.exec", `{"cmd":"sh"}`, nil); r.status != 404 || r.code != agentproto.CodeUnknownOp {
		t.Errorf("unknown op: %d %s", r.status, r.code)
	}
	huge := bytes.Repeat([]byte("a"), agentproto.MaxRequestBytes+1)
	if r, _ := e.post("docker.info", huge); r.status != 413 {
		t.Errorf("oversized body: %d", r.status)
	}
	if r, _ := e.post("docker.info", []byte(`{"grant":"x","params":{},"extra":1}`)); r.status != 400 {
		t.Errorf("unknown envelope field: %d", r.status)
	}
}

// AT-M4-07: Docker failures map to typed errors.
func TestDockerErrorsMapped(t *testing.T) {
	e := start(t, self())
	for err, want := range map[error]string{docker.ErrUnavailable: agentproto.CodeDockerUnavailable, docker.ErrNotFound: agentproto.CodeNotFound, docker.ErrConflict: agentproto.CodeConflict, io.ErrUnexpectedEOF: agentproto.CodeInternal} {
		e.docker.setErr(err)
		if r := e.call("containers.start", `{"id":"web"}`, nil); r.code != want {
			t.Errorf("%v: code %s, want %s", err, r.code, want)
		}
	}
}

func TestListenSocketSafety(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "regular")
	if err := os.WriteFile(file, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(file); err == nil {
		t.Fatal("regular file replaced by socket")
	}
	sock := filepath.Join(dir, "a.sock")
	ln, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	fi, err := os.Stat(sock)
	if err == nil && fi.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode %#o", fi.Mode().Perm())
	}
	// A stale socket from a crashed agent is replaced.
	stale, _ := net.Listen("unix", filepath.Join(dir, "b.sock"))
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	stale.Close()
	ln2, err := Listen(filepath.Join(dir, "b.sock"))
	if err != nil {
		t.Fatalf("stale socket: %v", err)
	}
	ln2.Close()
}

// Malformed envelopes never crash the handler (TH-24).
func FuzzHandleOp(f *testing.F) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, self(), &fakeDocker{}, Options{})
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/op/{op}", srv.handleOp)
	f.Add("docker.info", []byte(`{"grant":"a.b","params":{}}`))
	f.Add("containers.start", []byte(`{"grant":"","params":null}`))
	f.Add("x", []byte(`{`))
	f.Fuzz(func(t *testing.T, op string, body []byte) {
		if op == "" {
			return
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("POST", "/v1/op/"+url.PathEscape(op), bytes.NewReader(body)))
		if rec.Code == 200 {
			t.Fatalf("unsigned request accepted: %s %q", op, body)
		}
	})
}
