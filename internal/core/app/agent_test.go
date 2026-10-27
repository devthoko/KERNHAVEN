package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
)

type stubDocker struct{ err error }

func (s stubDocker) Info(context.Context) (agentproto.DockerInfo, error) {
	return agentproto.DockerInfo{ServerVersion: "29.9.2", Rootless: true}, s.err
}
func (stubDocker) ListContainers(context.Context, bool) ([]agentproto.ContainerSummary, error) {
	return nil, nil
}
func (stubDocker) Inspect(context.Context, string) (agentproto.ContainerDetail, error) {
	return agentproto.ContainerDetail{}, nil
}
func (stubDocker) Start(context.Context, string) (bool, error) { return false, nil }
func (stubDocker) Stop(context.Context, string, time.Duration) (bool, error) {
	return false, nil
}
func (stubDocker) Restart(context.Context, string, time.Duration) (bool, error) {
	return false, nil
}

type agentStatus struct {
	Agent struct {
		Available bool
		Error     string
	}
	Docker struct {
		Available bool
		Error     string
		Info      *struct {
			ServerVersion string `json:"server_version"`
			Rootless      bool
		}
	}
}

// AT-M4-08: agent unavailable is reported, not an error.
func TestAgentStatusUnavailable(t *testing.T) {
	h := newHarnessWith(t, func(c *config.Config) { c.Agent.Socket = filepath.Join(t.TempDir(), "absent.sock") })
	owner := h.setupOwner()
	var st agentStatus
	owner.do("GET", "/api/v1/system/agent", nil).expect(200).json(&st)
	if st.Agent.Available || st.Agent.Error == "" || st.Docker.Available {
		t.Fatalf("status %+v", st)
	}
	// The grant key pair exists and the private key is private.
	fi, err := os.Stat(filepath.Join(h.dataDir, agentclient.PrivateKeyFile))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key: %v %v", fi, err)
	}
}

// AT-M4-08: end to end with a real agent server and the Core's key.
func TestAgentStatusAvailable(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	h := newHarnessWith(t, func(c *config.Config) { c.Agent.Socket = sock })
	pub, err := agentproto.ReadPublicKey(filepath.Join(h.dataDir, agentclient.PublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		dockerErr error
	}{{"docker up", nil}, {"docker down", errDockerDown}} {
		t.Run(tc.name, func(t *testing.T) {
			srv := agent.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, stubDocker{err: tc.dockerErr})
			ln, err := agent.Listen(sock)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { _ = srv.Serve(ctx, ln); close(done) }()
			defer func() { cancel(); <-done }()

			owner := h.setupOrLogin()
			var st agentStatus
			owner.do("GET", "/api/v1/system/agent", nil).expect(200).json(&st)
			if !st.Agent.Available {
				t.Fatalf("agent not available: %+v", st)
			}
			if tc.dockerErr == nil && (!st.Docker.Available || st.Docker.Info == nil || st.Docker.Info.ServerVersion != "29.9.2" || !st.Docker.Info.Rootless) {
				t.Fatalf("docker status %+v", st.Docker)
			}
			if tc.dockerErr != nil && (st.Docker.Available || st.Docker.Error == "") {
				t.Fatalf("docker down not reported: %+v", st.Docker)
			}
		})
	}
}

var errDockerDown = dockerDown{}

type dockerDown struct{}

func (dockerDown) Error() string {
	return "docker engine unavailable: dial unix /run/docker.sock: connect: no such file"
}
func (dockerDown) Unwrap() error { return docker.ErrUnavailable }
