//go:build integration

package agent

// Integration tests against a real Docker Engine (AT-M4-06). Run with
//   KH_DOCKER_SOCKET=/run/user/1000/docker.sock go test -tags integration ./internal/agent/
// CI runs them against the runner's Docker Engine.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

const testImage = "alpine:3"

func dockerSocket(t *testing.T) string {
	t.Helper()
	s := os.Getenv("KH_DOCKER_SOCKET")
	if s == "" {
		t.Fatal("KH_DOCKER_SOCKET must point to a Docker Engine socket for integration tests")
	}
	return s
}

// raw issues Docker API calls the agent deliberately does not offer (pull,
// create, remove) to prepare and clean up test containers.
func raw(t *testing.T, sock, method, path string, body string) (int, string) {
	t.Helper()
	cl := &http.Client{Timeout: 5 * time.Minute, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
	req, _ := http.NewRequest(method, "http://docker"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func testContainer(t *testing.T, sock string) string {
	t.Helper()
	if code, body := raw(t, sock, "POST", "/v1.44/images/create?fromImage=alpine&tag=3", ""); code != 200 {
		t.Fatalf("pull %s: %d %s", testImage, code, body)
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "kh-it-" + hex.EncodeToString(b)
	code, body := raw(t, sock, "POST", "/v1.44/containers/create?name="+url.QueryEscape(name),
		`{"Image":"`+testImage+`","Cmd":["sleep","300"],"Labels":{"io.kernhaven.test":"1"}}`)
	if code != 201 {
		t.Fatalf("create: %d %s", code, body)
	}
	t.Cleanup(func() { raw(t, sock, "DELETE", "/v1.44/containers/"+name+"?force=1", "") })
	return name
}

// Full stack: Core client → signed grant → unix socket → agent → Docker.
func TestRealDockerThroughAgent(t *testing.T) {
	sock := dockerSocket(t)
	name := testContainer(t, sock)

	dir := t.TempDir()
	key, err := agentclient.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := agentproto.ReadPublicKey(filepath.Join(dir, agentclient.PublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, docker.New(sock, 30*time.Second), Options{})
	agentSock := filepath.Join(dir, "agent.sock")
	ln, err := Listen(agentSock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Serve(ctx, ln)
	cl := agentclient.New(agentSock, key)
	do := func(op string, params, out any) error {
		return cl.Do(context.Background(), agentclient.Call{Op: op, Params: params, Actor: "it", RequestID: "it"}, out)
	}

	var info agentproto.DockerInfo
	if err := do(agentproto.OpDockerInfo, nil, &info); err != nil {
		t.Fatal(err)
	}
	if info.ServerVersion == "" || info.NegotiatedVersion == "" {
		t.Fatalf("docker info %+v", info)
	}
	t.Logf("Docker %s (API %s, negotiated %s, rootless=%v)", info.ServerVersion, info.APIVersion, info.NegotiatedVersion, info.Rootless)

	var list []agentproto.ContainerSummary
	if err := do(agentproto.OpContainersList, agentproto.ContainersList{All: true}, &list); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range list {
		for _, n := range c.Names {
			found = found || (n == name && c.Labels["io.kernhaven.test"] == "1")
		}
	}
	if !found {
		t.Fatalf("test container %s not listed", name)
	}

	inspect := func() agentproto.ContainerDetail {
		var d agentproto.ContainerDetail
		if err := do(agentproto.OpContainersInspect, agentproto.ContainerRef{ID: name}, &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	if d := inspect(); d.Running || d.Privileged || d.Name != name {
		t.Fatalf("created container %+v", d)
	}

	var res agentproto.ActionResult
	if err := do(agentproto.OpContainersStart, agentproto.ContainerRef{ID: name}, &res); err != nil || !res.Changed {
		t.Fatalf("start: %+v %v", res, err)
	}
	if err := do(agentproto.OpContainersStart, agentproto.ContainerRef{ID: name}, &res); err != nil || res.Changed {
		t.Fatalf("second start: %+v %v", res, err)
	}
	if !inspect().Running {
		t.Fatal("not running after start")
	}
	if err := do(agentproto.OpContainersRestart, agentproto.ContainerStop{ID: name, TimeoutSeconds: 1}, &res); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := do(agentproto.OpContainersStop, agentproto.ContainerStop{ID: name, TimeoutSeconds: 1}, &res); err != nil || !res.Changed {
		t.Fatalf("stop: %+v %v", res, err)
	}
	if err := do(agentproto.OpContainersStop, agentproto.ContainerStop{ID: name, TimeoutSeconds: 1}, &res); err != nil || res.Changed {
		t.Fatalf("second stop: %+v %v", res, err)
	}
	if inspect().Running {
		t.Fatal("running after stop")
	}

	var ae *agentclient.Error
	err = do(agentproto.OpContainersInspect, agentproto.ContainerRef{ID: "kh-it-does-not-exist"}, nil)
	if !errors.As(err, &ae) || ae.Code != agentproto.CodeNotFound {
		t.Fatalf("missing container: %v", err)
	}
}
