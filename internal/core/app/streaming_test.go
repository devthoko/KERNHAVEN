package app

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
)

// fakeShell understands "echo …" and "exit N" (M6b tests).
type fakeShell struct {
	mu     sync.Mutex
	in     []byte
	frames chan docker.Frame
	code   int
	done   bool
}

func (f *fakeShell) Write(p []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.done {
		return 0, io.ErrClosedPipe
	}
	f.in = append(f.in, p...)
	for {
		i := strings.IndexByte(string(f.in), '\n')
		if i < 0 {
			return len(p), nil
		}
		line := strings.TrimSpace(string(f.in[:i]))
		f.in = f.in[i+1:]
		switch {
		case strings.HasPrefix(line, "echo "):
			f.frames <- docker.Frame{Stream: "stdout", Data: []byte(line[5:] + "\n")}
		case strings.HasPrefix(line, "exit "):
			f.code, _ = strconv.Atoi(line[5:])
			f.done = true
			close(f.frames)
			return len(p), nil
		default:
			f.frames <- docker.Frame{Stream: "stderr", Data: []byte("sh: " + line + ": not found\n")}
		}
	}
}

func (f *fakeShell) CloseStdin() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.done {
		f.done = true
		close(f.frames)
	}
	return nil
}

func (f *fakeShell) Frames(emit func(docker.Frame) error) error {
	for fr := range f.frames {
		if err := emit(fr); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeShell) ExitCode(context.Context) (int, error) { return f.code, nil }
func (f *fakeShell) Close() error                          { return f.CloseStdin() }

func (m *memDocker) ExecStream(_ context.Context, ref string, cmd []string) (agent.ExecStream, string, error) {
	return &fakeShell{frames: make(chan docker.Frame, 64)}, "exec-" + ref, nil
}

func (m *memDocker) PidMode(context.Context, string) (string, error) { return "", nil }

func (m *memDocker) FollowLogs(ctx context.Context, ref string, tail int, emit func(docker.Frame) error) error {
	for _, l := range []string{"line 1\n", "line 2\n"} {
		if err := emit(docker.Frame{Stream: "stdout", Data: []byte(l)}); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}

type sseEvent struct{ name, data string }

// stream opens a server-sent event stream as this client through a real
// HTTP server (the recorder cannot stream).
func (c *client) stream(srv *httptest.Server, path string) (<-chan sseEvent, func(), int) {
	c.h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+path, nil)
	req.Header.Set("User-Agent", "kernhaven-test")
	if c.cookie != "" {
		req.AddCookie(&http.Cookie{Name: c.h.app.Identity.CookieName(), Value: c.cookie})
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		c.h.t.Fatal(err)
	}
	ch := make(chan sseEvent, 64)
	if resp.StatusCode != 200 {
		resp.Body.Close()
		close(ch)
		return ch, cancel, resp.StatusCode
	}
	go func() {
		defer close(ch)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "event: "):
				ev.name = line[7:]
			case strings.HasPrefix(line, "data: "):
				ev.data = line[6:]
			case line == "" && ev.name != "":
				ch <- ev
				ev = sseEvent{}
			}
		}
	}()
	return ch, cancel, 200
}

func waitEvent(t *testing.T, ch <-chan sseEvent, name, contains string) sseEvent {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("stream ended before %s %q", name, contains)
			}
			if ev.name == name && strings.Contains(ev.data, contains) {
				return ev
			}
		case <-timeout:
			t.Fatalf("no %s event with %q", name, contains)
		}
	}
}

// waitChanges waits for change events of all kinds, in any order.
func waitChanges(t *testing.T, ch <-chan sseEvent, kinds ...string) {
	t.Helper()
	want := map[string]bool{}
	for _, k := range kinds {
		want[`{"type":"`+k+`"}`] = true
	}
	timeout := time.After(5 * time.Second)
	for len(want) > 0 {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatal("stream ended")
			}
			if ev.name == "change" {
				delete(want, ev.data)
			}
		case <-timeout:
			t.Fatalf("missing changes %v", want)
		}
	}
}

func deployedContainer(t *testing.T, h *harness, owner *client) string {
	t.Helper()
	createStack(t, owner)
	var job jobRef
	owner.do("POST", "/api/v1/stacks/shop/deploy", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	var list struct{ Containers []agentproto.ContainerSummary }
	owner.do("GET", "/api/v1/containers", nil).expect(200).json(&list)
	for _, c := range list.Containers {
		if c.Labels["io.kernhaven.stack"] == "shop" {
			return c.ID
		}
	}
	t.Fatal("no container")
	return ""
}

// AT-F02-07: a console for owners and admins, audited by metadata only.
func TestConsoleThroughCore(t *testing.T) {
	h, _ := withAgent(t)
	srv := httptest.NewServer(h.app.Handler)
	defer srv.Close()
	owner := h.setupOwner()
	h.startJobs()
	id := deployedContainer(t, h, owner)
	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "adele", authz.Admin)
	op, admin := h.loginAs("operator1"), h.loginAs("adele")

	op.do("POST", "/api/v1/containers/"+id+"/console", map[string]string{"shell": "sh"}).expect(403)
	if r := owner.do("POST", "/api/v1/containers/"+id+"/console", map[string]string{"shell": "/bin/zsh"}); r.Code < 400 || r.Code >= 500 {
		t.Fatalf("arbitrary shell: %d %s", r.Code, r.Body)
	}
	var opened struct{ Console string }
	owner.do("POST", "/api/v1/containers/"+id+"/console", map[string]string{"shell": "sh"}).expect(201).json(&opened)
	events, stop, code := owner.stream(srv, "/api/v1/consoles/"+opened.Console+"/stream")
	defer stop()
	if code != 200 {
		t.Fatalf("stream %d", code)
	}
	owner.do("POST", "/api/v1/consoles/"+opened.Console+"/input", map[string]string{"text": "echo hello from the container\n"}).expect(204)
	waitEvent(t, events, "output", "hello from the container")
	// Only the session that opened it can use it.
	admin.do("POST", "/api/v1/consoles/"+opened.Console+"/input", map[string]string{"text": "echo intruder\n"}).expect(404)
	if _, _, code := admin.stream(srv, "/api/v1/consoles/"+opened.Console+"/stream"); code != 404 {
		t.Fatalf("other user's stream: %d", code)
	}
	owner2 := h.loginAs("owner")
	owner2.do("POST", "/api/v1/consoles/"+opened.Console+"/input", map[string]string{"text": "echo other browser\n"}).expect(404)
	owner.do("POST", "/api/v1/consoles/"+opened.Console+"/input", map[string]string{"text": strings.Repeat("x", 5000)}).expect(413)
	owner.do("POST", "/api/v1/consoles/"+opened.Console+"/input", map[string]string{"text": "exit 3\n"}).expect(204)
	end := waitEvent(t, events, "end", `"exit_code":3`)
	_ = end
	// Ended (409) until the session is removed, then unknown (404).
	if r := owner.do("POST", "/api/v1/consoles/"+opened.Console+"/input", map[string]string{"text": "echo late\n"}); r.Code != 409 && r.Code != 404 {
		t.Fatalf("input after the end: %d", r.Code)
	}

	// Audited by metadata, never content.
	deadline := time.Now().Add(3 * time.Second)
	for auditCount(t, h, "container.console_close", "success") == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	var details string
	if err := h.db.QueryRow(`SELECT details FROM audit_events WHERE action = 'container.console_close'`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	var d map[string]string
	_ = json.Unmarshal([]byte(details), &d)
	if d["exit_code"] != "3" || d["shell"] != "sh" || d["bytes_in"] == "0" || d["bytes_out"] == "0" || strings.Contains(details, "hello") {
		t.Fatalf("close record %s", details)
	}
	if auditCount(t, h, "container.console_open", "success") != 1 {
		t.Fatal("open not audited")
	}

	// Limits: two consoles per user.
	for i := range 2 {
		var c struct{ Console string }
		admin.do("POST", "/api/v1/containers/"+id+"/console", map[string]string{"shell": "sh"}).expect(201).json(&c)
		defer admin.do("DELETE", "/api/v1/consoles/"+c.Console, nil)
		_ = i
	}
	admin.do("POST", "/api/v1/containers/"+id+"/console", map[string]string{"shell": "bash"}).expect(429)

	// Opening a console needs a recent step-up.
	h.clock.Advance(11 * time.Minute)
	owner3 := h.loginAs("owner")
	h.clock.Advance(11 * time.Minute)
	if r := owner3.do("POST", "/api/v1/containers/"+id+"/console", map[string]string{"shell": "sh"}); r.errorCode() != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.Code, r.Body)
	}
}

// AT-F01-05: changes reach the browser without polling; M6b log follow.
func TestLiveEventsAndLogFollow(t *testing.T) {
	h, _ := withAgentOpts(t, func(o *Options) { o.LiveInterval = 50 * time.Millisecond })
	srv := httptest.NewServer(h.app.Handler)
	defer srv.Close()
	owner := h.setupOwner()
	h.startJobs()
	h.createUser(owner, "viewer1", authz.Viewer)
	viewer := h.loginAs("viewer1")

	events, stop, code := owner.stream(srv, "/api/v1/events")
	defer stop()
	if code != 200 {
		t.Fatalf("events %d", code)
	}
	waitEvent(t, events, "hello", `"alerts","containers","jobs"`)
	vEvents, vStop, _ := viewer.stream(srv, "/api/v1/events")
	defer vStop()
	waitEvent(t, vEvents, "hello", `["containers","jobs"]`)
	if _, _, code := h.newClient().stream(srv, "/api/v1/events"); code != 401 {
		t.Fatalf("anonymous events: %d", code)
	}

	time.Sleep(200 * time.Millisecond)   // the poller's first round sets the baseline
	id := deployedContainer(t, h, owner) // a job and new containers
	waitChanges(t, events, "jobs", "containers")
	waitEvent(t, vEvents, "change", `"containers"`)
	owner.do("POST", "/api/v1/containers/"+id+"/stop", map[string]any{}).expect(200)
	waitEvent(t, events, "change", `"containers"`)

	logs, lstop, code := owner.stream(srv, "/api/v1/containers/"+id+"/logs/stream")
	defer lstop()
	if code != 200 {
		t.Fatalf("log stream %d", code)
	}
	waitEvent(t, logs, "log", "line 1")
	waitEvent(t, logs, "log", "line 2")
	if _, _, code := viewer.stream(srv, "/api/v1/containers/"+id+"/logs/stream"); code != 403 {
		t.Fatalf("viewer log stream: %d", code)
	}
}
