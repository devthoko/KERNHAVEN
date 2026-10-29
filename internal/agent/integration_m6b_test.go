//go:build integration

package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

// AT-F02-07, M6b log follow on a real Docker Engine.
func TestM6bConsoleAndFollow(t *testing.T) {
	sock := dockerSocket(t)
	dir := t.TempDir()
	key, err := agentclient.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := agentproto.ReadPublicKey(filepath.Join(dir, agentclient.PublicKeyFile))
	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, docker.New(sock, 30*time.Second), Options{})
	ln, err := Listen(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	cl := agentclient.New(filepath.Join(dir, "agent.sock"), key)
	do := func(op string, params, out any) error {
		return cl.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: "it", RequestID: "it"}, out)
	}
	s := suffix()
	managed, plain := "kh-it-console-"+s, "kh-it-plain-"+s
	t.Cleanup(func() {
		for _, c := range []string{managed, plain} {
			raw(t, sock, "DELETE", "/v1.44/containers/"+c+"?force=1", "")
		}
	})
	if err := do(agentproto.OpImagesPull, agentproto.ImageRef{Reference: testImage}, nil); err != nil {
		t.Fatal(err)
	}
	spec := agentproto.ContainerSpec{Name: managed, Image: testImage, User: "1000", MemoryBytes: 64 << 20,
		Cmd: []string{"sh", "-c", "i=0; while true; do i=$((i+1)); echo tick $i; sleep 0.2; done"}}
	if err := do(agentproto.OpContainersCreate, agentproto.CreateContainer{Spec: spec, Start: true}, nil); err != nil {
		t.Fatal(err)
	}
	// A container not created by Kernhaven.
	if code, body := raw(t, sock, "POST", "/v1.44/containers/create?name="+plain, `{"Image":"alpine:3","Cmd":["sleep","300"]}`); code != 201 {
		t.Fatalf("create plain: %d %s", code, body)
	}
	raw(t, sock, "POST", "/v1.44/containers/"+plain+"/start", "")

	lines := func(body io.Reader) <-chan agentproto.StreamChunk {
		ch := make(chan agentproto.StreamChunk, 64)
		go func() {
			defer close(ch)
			sc := bufio.NewScanner(body)
			for sc.Scan() {
				var c agentproto.StreamChunk
				if json.Unmarshal(sc.Bytes(), &c) == nil {
					ch <- c
				}
			}
		}()
		return ch
	}
	next := func(ch <-chan agentproto.StreamChunk, until func(agentproto.StreamChunk) bool) agentproto.StreamChunk {
		t.Helper()
		timeout := time.After(20 * time.Second)
		for {
			select {
			case c, ok := <-ch:
				if !ok {
					t.Fatal("stream ended")
				}
				if until(c) {
					return c
				}
			case <-timeout:
				t.Fatal("timeout")
			}
		}
	}

	// Log follow delivers new lines as they are written.
	fctx, fcancel := context.WithCancel(ctx)
	st, err := cl.DoStream(fctx, agentclient.Call{Op: agentproto.OpContainersLogsFollow, Params: agentproto.LogsFollow{ID: managed, Tail: 0}, Actor: "it", RequestID: "it"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	follow := lines(st.Body)
	first := next(follow, func(c agentproto.StreamChunk) bool { return strings.Contains(string(c.Data), "tick") })
	later := next(follow, func(c agentproto.StreamChunk) bool {
		return strings.Contains(string(c.Data), "tick") && string(c.Data) != string(first.Data)
	})
	t.Logf("followed %q then %q", first.Data, later.Data)
	fcancel()
	st.Body.Close()

	// The console: commands typed into the shell, the exit code at the end.
	pr, pw := io.Pipe()
	st, err = cl.DoStream(ctx, agentclient.Call{Op: agentproto.OpContainersExec, Params: agentproto.ExecStart{ID: managed, Shell: "sh"}, Actor: "it", RequestID: "it"}, pr)
	if err != nil {
		t.Fatal(err)
	}
	out := lines(st.Body)
	if c := next(out, func(agentproto.StreamChunk) bool { return true }); c.Exec == "" {
		t.Fatalf("first line %+v", c)
	}
	_, _ = io.WriteString(pw, "echo hello from $(id -u)\n")
	next(out, func(c agentproto.StreamChunk) bool { return strings.Contains(string(c.Data), "hello from 1000") })
	_, _ = io.WriteString(pw, "exit 3\n")
	end := next(out, func(c agentproto.StreamChunk) bool { return c.End })
	if end.ExitCode == nil || *end.ExitCode != 3 || end.Bytes == 0 {
		t.Fatalf("end %+v", end)
	}
	pw.Close()
	st.Body.Close()

	// Refusals arrive as the first line, while the input is still open.
	for name, p := range map[string]agentproto.ExecStart{
		"unmanaged container": {ID: plain, Shell: "sh"},
		"other program":       {ID: managed, Shell: "python"},
		"missing container":   {ID: "kh-it-missing-" + s, Shell: "sh"},
	} {
		pr, pw := io.Pipe()
		st, err := cl.DoStream(ctx, agentclient.Call{Op: agentproto.OpContainersExec, Params: p, Actor: "it", RequestID: "it"}, pr)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		c := next(lines(st.Body), func(agentproto.StreamChunk) bool { return true })
		if !c.End || c.Code == "" || c.Exec != "" {
			t.Errorf("%s: %+v", name, c)
		}
		pw.Close()
		st.Body.Close()
	}
}
