package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConfig writes body to a temp file and returns its path.
func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "core.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func privateDir(t *testing.T) string {
	t.Helper()
	d := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(d, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

// AT-F00-01
func TestLoadValidMinimalConfigUsesDefaults(t *testing.T) {
	dir := privateDir(t)
	cfg, err := Load(writeConfig(t, "[storage]\ndata_dir = \""+dir+"\"\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:8470" {
		t.Errorf("Listen = %q", cfg.Server.Listen)
	}
	if cfg.Server.ShutdownTimeout.Duration != 15*time.Second {
		t.Errorf("ShutdownTimeout = %s", cfg.Server.ShutdownTimeout)
	}
	if cfg.Server.MaxBodyBytes != 1<<20 {
		t.Errorf("MaxBodyBytes = %d", cfg.Server.MaxBodyBytes)
	}
	if cfg.Log.Level != "info" {
		t.Errorf("Level = %q", cfg.Log.Level)
	}
}

func TestLoadFullConfig(t *testing.T) {
	dir := privateDir(t)
	cfg, err := Load(writeConfig(t, `
[server]
listen = "[::1]:9000"
shutdown_timeout = "5s"
max_body_bytes = 4096
[storage]
data_dir = "`+dir+`"
[log]
level = "debug"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.Listen != "[::1]:9000" || cfg.Server.ShutdownTimeout.Duration != 5*time.Second ||
		cfg.Server.MaxBodyBytes != 4096 || cfg.Log.Level != "debug" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

// AT-F00-01: every invalid configuration is rejected with a precise error.
func TestLoadRejectsInvalidConfig(t *testing.T) {
	dir := privateDir(t)

	openDir := filepath.Join(t.TempDir(), "open")
	if err := os.Mkdir(openDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o755); err != nil { // defeat umask
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}

	storage := "[storage]\ndata_dir = \"" + dir + "\"\n"
	cases := []struct {
		name, body, wantErr string
	}{
		{"unknown top-level key", "debug = true\n" + storage, "unknown keys: debug"},
		{"unknown table key", storage + "debug = true\n", "unknown keys: storage.debug"},
		{"unknown nested key", storage + "[server]\nport = 1\n", "unknown keys: server.port"},
		{"syntax error", "[server\n", "read "},
		{"public listen", storage + "[server]\nlisten = \"0.0.0.0:8470\"\n", "not a loopback address"},
		{"lan listen", storage + "[server]\nlisten = \"192.168.1.10:8470\"\n", "not a loopback address"},
		{"hostname listen", storage + "[server]\nlisten = \"example.org:8470\"\n", "must be an IP literal or localhost"},
		{"empty host listen", storage + "[server]\nlisten = \":8470\"\n", "must be an IP literal or localhost"},
		{"missing port", storage + "[server]\nlisten = \"127.0.0.1\"\n", "is not host:port"},
		{"port zero", storage + "[server]\nlisten = \"127.0.0.1:0\"\n", "not in 1..65535"},
		{"port too large", storage + "[server]\nlisten = \"127.0.0.1:70000\"\n", "not in 1..65535"},
		{"bad duration", storage + "[server]\nshutdown_timeout = \"soon\"\n", "invalid duration"},
		{"duration too short", storage + "[server]\nshutdown_timeout = \"10ms\"\n", "server.shutdown_timeout"},
		{"duration too long", storage + "[server]\nshutdown_timeout = \"1h\"\n", "server.shutdown_timeout"},
		{"body too small", storage + "[server]\nmax_body_bytes = 10\n", "server.max_body_bytes"},
		{"body too large", storage + "[server]\nmax_body_bytes = 1073741824\n", "server.max_body_bytes"},
		{"relative data dir", "[storage]\ndata_dir = \"data\"\n", "must be an absolute path"},
		{"unclean data dir", "[storage]\ndata_dir = \"" + dir + "/../data\"\n", "must be a clean path"},
		{"missing data dir", "[storage]\ndata_dir = \"" + dir + "/missing\"\n", "no such file or directory"},
		{"data dir is file", "[storage]\ndata_dir = \"" + file + "\"\n", "is not a directory"},
		{"data dir is symlink", "[storage]\ndata_dir = \"" + link + "\"\n", "must not be a symlink"},
		{"data dir world readable", "[storage]\ndata_dir = \"" + openDir + "\"\n", "group and other permissions must be empty"},
		{"bad log level", storage + "[log]\nlevel = \"verbose\"\n", "log.level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err == nil || !strings.Contains(err.Error(), "no such file") {
		t.Fatalf("err = %v", err)
	}
}

func TestValidateReportsAllViolations(t *testing.T) {
	cfg := Default()
	cfg.Server.Listen = "0.0.0.0:1"
	cfg.Log.Level = "loud"
	cfg.Storage.DataDir = "relative"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"server.listen", "log.level", "storage.data_dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestLocalhostAndIPv6LoopbackAccepted(t *testing.T) {
	for _, addr := range []string{"localhost:8470", "127.0.0.2:8470", "[::1]:8470"} {
		if err := validateListen(addr); err != nil {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestPublicOriginValidation(t *testing.T) {
	ok := []string{"https://kernhaven.home.arpa", "https://192.168.1.5:8443", "http://localhost:8470", "http://127.0.0.1:8470", "http://[::1]:8470", "https://k.example/"}
	bad := []string{"", "kernhaven.local", "http://192.168.1.5:8470", "http://kernhaven.local", "ftp://x", "https://u:p@x", "https://x/path", "https://x?q=1", "https://x#f"}
	for _, o := range ok {
		if err := validateOrigin(o); err != nil {
			t.Errorf("%q rejected: %v", o, err)
		}
	}
	for _, o := range bad {
		if err := validateOrigin(o); err == nil {
			t.Errorf("%q accepted", o)
		}
	}
	if got := (Server{PublicOrigin: "https://k.example/"}).Origin(); got != "https://k.example" {
		t.Errorf("Origin() = %q", got)
	}
}

func TestAuthValidation(t *testing.T) {
	cfg := Default()
	cfg.Storage.DataDir = privateDir(t)
	if err := cfg.Validate(); err != nil {
		t.Fatalf("defaults invalid: %v", err)
	}
	cfg.Auth.SessionIdleTimeout.Duration = 2 * time.Hour
	cfg.Auth.SessionAbsoluteTimeout.Duration = time.Hour
	cfg.Auth.SetupTokenTTL.Duration = time.Minute
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"must not be shorter", "auth.setup_token_ttl"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestAgentSocketValidation(t *testing.T) {
	cfg := Default()
	cfg.Storage.DataDir = privateDir(t)
	for _, ok := range []string{"", "/run/kernhaven/agent.sock", "/run/user/1000/kh.sock"} {
		cfg.Agent.Socket = ok
		if err := cfg.Validate(); err != nil {
			t.Errorf("%q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"agent.sock", "/run/../tmp/a.sock"} {
		cfg.Agent.Socket = bad
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "agent.socket") {
			t.Errorf("%q accepted: %v", bad, err)
		}
	}
}
