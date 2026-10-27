package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

// TestMain lets the test binary act as kernhaven-core when re-executed, so
// process-level behaviour (signals, exit codes) is tested on the real code.
func TestMain(m *testing.M) {
	if os.Getenv("KH_RUN_CORE") == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// writeConfig creates a private data dir and a config pointing at it.
func writeConfig(t *testing.T, port int, extra string) (cfgPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	dataDir = filepath.Join(dir, "data")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfgPath = filepath.Join(dir, "core.toml")
	body := fmt.Sprintf("[server]\nlisten = \"127.0.0.1:%d\"\nshutdown_timeout = \"5s\"\n[storage]\ndata_dir = %q\n%s", port, dataDir, extra)
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfgPath, dataDir
}

func TestVersionCommand(t *testing.T) {
	var out bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, io.Discard); code != exitOK {
		t.Fatalf("exit = %d", code)
	}
	var v map[string]string
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || v["version"] == "" {
		t.Fatalf("output %q err %v", out.String(), err)
	}
}

// AT-F00-01: invalid configuration exits with code 2 and a precise message.
func TestInvalidConfigExitCode(t *testing.T) {
	cfg, _ := writeConfig(t, freePort(t), "[log]\nlevel = \"loud\"\n")
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", cfg}, io.Discard, &stderr); code != exitConfig {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "log.level") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestPublicListenRejected(t *testing.T) {
	cfg, _ := writeConfig(t, freePort(t), "")
	body, _ := os.ReadFile(cfg)
	if err := os.WriteFile(cfg, bytes.Replace(body, []byte("127.0.0.1"), []byte("0.0.0.0"), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", cfg}, io.Discard, &stderr); code != exitConfig {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(stderr.String(), "not a loopback address") {
		t.Fatalf("stderr = %s", stderr.String())
	}
}

func TestMissingConfigAndBadFlags(t *testing.T) {
	cases := [][]string{
		{"-config", filepath.Join(t.TempDir(), "absent.toml")},
		{"-nope"},
		{"-config", "x", "extra"},
	}
	for _, args := range cases {
		if code := run(context.Background(), args, io.Discard, io.Discard); code != exitConfig {
			t.Errorf("%v: exit = %d, want %d", args, code, exitConfig)
		}
	}
}

func TestCorruptDatabaseExitCode(t *testing.T) {
	cfg, dataDir := writeConfig(t, freePort(t), "")
	if err := os.WriteFile(filepath.Join(dataDir, store.FileName), bytes.Repeat([]byte("garbage!"), 1000), 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"-config", cfg}, io.Discard, &stderr); code != exitDatabase {
		t.Fatalf("exit = %d, stderr = %s", code, stderr.String())
	}
}

func TestPortInUseExitCode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg, _ := writeConfig(t, ln.Addr().(*net.TCPAddr).Port, "")
	if code := run(context.Background(), []string{"-config", cfg}, io.Discard, io.Discard); code != exitRuntime {
		t.Fatalf("exit = %d", code)
	}
}

// AT-F00-03 + AT-F00-05: the real process serves health endpoints and stops
// cleanly on SIGTERM.
func TestProcessServesAndStopsOnSIGTERM(t *testing.T) {
	port := freePort(t)
	cfg, dataDir := writeConfig(t, port, "")

	cmd := exec.Command(os.Args[0], "-config", cfg)
	cmd.Env = append(os.Environ(), "KH_RUN_CORE=1")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })

	var logs bytes.Buffer
	logDone := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stderr)
		for sc.Scan() {
			logs.WriteString(sc.Text() + "\n")
		}
		close(logDone)
	}()

	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	deadline := time.Now().Add(10 * time.Second)
	for {
		resp, err := http.Get(base + "/api/v1/health/ready")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("core did not become ready: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
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
			t.Fatalf("exit after SIGTERM: %v\nlogs:\n%s", err, logs.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("core did not stop after SIGTERM")
	}
	for _, want := range []string{`"msg":"listening"`, `"msg":"shutting down"`, `"msg":"stopped"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log missing %s:\n%s", want, logs.String())
		}
	}

	// Database was closed cleanly: it reopens with integrity intact.
	db, err := store.Open(context.Background(), filepath.Join(dataDir, store.FileName))
	if err != nil {
		t.Fatalf("reopen after shutdown: %v", err)
	}
	db.Close()
}
