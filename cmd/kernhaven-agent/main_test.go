package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

func TestMain(m *testing.M) {
	if os.Getenv("KH_RUN_AGENT") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func writeConfig(t *testing.T, extra string) (cfg, dir string) {
	t.Helper()
	dir = t.TempDir()
	if _, err := agentclient.LoadOrCreateKey(dir); err != nil {
		t.Fatal(err)
	}
	cfg = filepath.Join(dir, "agent.toml")
	body := fmt.Sprintf("socket = %q\nallowed_uids = [%d]\ngrant_public_key = %q\ndocker_socket = %q\n%s",
		filepath.Join(dir, "agent.sock"), os.Getuid(), filepath.Join(dir, agentclient.PublicKeyFile), filepath.Join(dir, "no-docker.sock"), extra)
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg, dir
}

func TestConfigErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":   "privileged = true\n",
		"no uids":       "",
		"relative sock": "",
	}
	for name, extra := range cases {
		cfg, dir := writeConfig(t, extra)
		body, _ := os.ReadFile(cfg)
		switch name {
		case "no uids":
			body = []byte(strings.Replace(string(body), fmt.Sprintf("allowed_uids = [%d]", os.Getuid()), "allowed_uids = []", 1))
		case "relative sock":
			body = []byte(strings.Replace(string(body), filepath.Join(dir, "agent.sock"), "agent.sock", 1))
		}
		_ = os.WriteFile(cfg, body, 0o600)
		var stderr bytes.Buffer
		if code := run(context.Background(), []string{"-config", cfg}, io.Discard, &stderr); code != exitConfig {
			t.Errorf("%s: exit %d (%s)", name, code, stderr.String())
		}
	}
	cfg, dir := writeConfig(t, "")
	os.Remove(filepath.Join(dir, agentclient.PublicKeyFile))
	if code := run(context.Background(), []string{"-config", cfg}, io.Discard, io.Discard); code != exitConfig {
		t.Errorf("missing public key: exit %d", code)
	}
}

// AT-M4-07 at process level: the agent runs without Docker, reports it as
// unavailable, and stops cleanly on SIGTERM.
func TestAgentProcessWithoutDocker(t *testing.T) {
	cfg, dir := writeConfig(t, "")
	cmd := exec.Command(os.Args[0], "-config", cfg)
	cmd.Env = append(os.Environ(), "KH_RUN_AGENT=1")
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	var logs strings.Builder
	logDone := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			logs.WriteString(sc.Text() + "\n")
		}
		close(logDone)
	}()

	key, err := agentclient.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	cl := agentclient.New(filepath.Join(dir, "agent.sock"), key)
	var info agentproto.AgentInfo
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = cl.Do(context.Background(), agentclient.Call{Op: agentproto.OpAgentInfo, Actor: "t"}, &info)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("agent not reachable: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	var ae *agentclient.Error
	err = cl.Do(context.Background(), agentclient.Call{Op: agentproto.OpDockerInfo, Actor: "t"}, nil)
	if !errors.As(err, &ae) || ae.Code != agentproto.CodeDockerUnavailable {
		t.Fatalf("docker.info without Docker: %v", err)
	}
	if err := cl.Do(context.Background(), agentclient.Call{Op: agentproto.OpAgentInfo, Actor: "t"}, &info); err != nil {
		t.Fatalf("agent died after Docker error: %v", err)
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	waitErr := make(chan error, 1)
	go func() { waitErr <- cmd.Wait() }()
	select {
	case err := <-waitErr:
		<-logDone
		if err != nil {
			t.Fatalf("exit: %v\n%s", err, logs.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("agent did not stop")
	}
	if _, err := os.Stat(filepath.Join(dir, "agent.sock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket not removed on shutdown")
	}
}
