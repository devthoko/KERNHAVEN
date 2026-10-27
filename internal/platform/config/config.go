// Package config loads and validates the Core configuration.
//
// Decoding is strict: unknown keys are errors. Validation enforces the
// security invariants from ADR-0010 (loopback-only listener, private data
// directory).
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
)

// DefaultPath is the configuration file used when none is given.
const DefaultPath = "/etc/kernhaven/core.toml"

// Bounds for numeric settings.
const (
	MinShutdownTimeout = 1 * time.Second
	MaxShutdownTimeout = 120 * time.Second
	MinMaxBodyBytes    = 1 << 10
	MaxMaxBodyBytes    = 64 << 20
)

// Config is the validated Core configuration.
type Config struct {
	Server     Server     `toml:"server"`
	Storage    Storage    `toml:"storage"`
	Log        Log        `toml:"log"`
	Auth       Auth       `toml:"auth"`
	Agent      Agent      `toml:"agent"`
	Containers Containers `toml:"containers"`
}

// Containers configures container management (M6).
type Containers struct {
	// AllowedBindRoots mirror the agent setting for policy previews; the
	// agent's own setting is authoritative.
	AllowedBindRoots []string `toml:"allowed_bind_roots"`
}

// Agent configures the connection to kernhaven-agent (M4).
type Agent struct {
	// Socket is the agent's unix socket; empty disables the agent.
	Socket string `toml:"socket"`
}

// Server configures the HTTP listener.
type Server struct {
	Listen          string   `toml:"listen"`
	ShutdownTimeout Duration `toml:"shutdown_timeout"`
	MaxBodyBytes    int64    `toml:"max_body_bytes"`
	// PublicOrigin is the browser-facing origin (scheme://host[:port]) used
	// for CSRF origin checks and the session cookie Secure flag.
	PublicOrigin string `toml:"public_origin"`
}

// Storage configures persistent state.
type Storage struct {
	DataDir string `toml:"data_dir"`
}

// Auth configures sessions and first-run setup.
type Auth struct {
	SessionIdleTimeout     Duration `toml:"session_idle_timeout"`
	SessionAbsoluteTimeout Duration `toml:"session_absolute_timeout"`
	SetupTokenTTL          Duration `toml:"setup_token_ttl"`
}

// Log configures logging.
type Log struct {
	Level string `toml:"level"`
}

// Duration is a time.Duration decoded from a Go duration string ("15s").
type Duration struct{ time.Duration }

// UnmarshalText implements encoding.TextUnmarshaler.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("invalid duration %q", string(b))
	}
	d.Duration = v
	return nil
}

// Default returns the configuration used for keys absent from the file.
func Default() Config {
	return Config{
		Server: Server{
			Listen:          "127.0.0.1:8470",
			ShutdownTimeout: Duration{15 * time.Second},
			MaxBodyBytes:    1 << 20,
			PublicOrigin:    "http://localhost:8470",
		},
		Storage: Storage{DataDir: "/var/lib/kernhaven"},
		Log:     Log{Level: "info"},
		Agent:   Agent{Socket: "/run/kernhaven/agent.sock"},
		Auth: Auth{
			SessionIdleTimeout:     Duration{30 * time.Minute},
			SessionAbsoluteTimeout: Duration{12 * time.Hour},
			SetupTokenTTL:          Duration{24 * time.Hour},
		},
	}
}

// Load reads, decodes and validates the configuration file at path.
func Load(path string) (Config, error) {
	cfg := Default()
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, k := range undecoded {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Validate checks all settings and returns every violation found.
func (c Config) Validate() error {
	var errs []error
	if err := validateListen(c.Server.Listen); err != nil {
		errs = append(errs, fmt.Errorf("server.listen: %w", err))
	}
	if d := c.Server.ShutdownTimeout.Duration; d < MinShutdownTimeout || d > MaxShutdownTimeout {
		errs = append(errs, fmt.Errorf("server.shutdown_timeout: %s is outside %s..%s", d, MinShutdownTimeout, MaxShutdownTimeout))
	}
	if n := c.Server.MaxBodyBytes; n < MinMaxBodyBytes || n > MaxMaxBodyBytes {
		errs = append(errs, fmt.Errorf("server.max_body_bytes: %d is outside %d..%d", n, MinMaxBodyBytes, MaxMaxBodyBytes))
	}
	if err := validateOrigin(c.Server.PublicOrigin); err != nil {
		errs = append(errs, fmt.Errorf("server.public_origin: %w", err))
	}
	errs = append(errs, c.Auth.validate()...)
	for _, r := range c.Containers.AllowedBindRoots {
		if !filepath.IsAbs(r) || filepath.Clean(r) != r || r == "/" {
			errs = append(errs, fmt.Errorf("containers.allowed_bind_roots: %q must be an absolute, clean directory other than /", r))
		}
	}
	if s := c.Agent.Socket; s != "" && (!filepath.IsAbs(s) || filepath.Clean(s) != s) {
		errs = append(errs, fmt.Errorf("agent.socket: %q must be an absolute, clean path or empty", s))
	}
	if err := validateDataDir(c.Storage.DataDir); err != nil {
		errs = append(errs, fmt.Errorf("storage.data_dir: %w", err))
	}
	switch c.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level: %q is not one of debug, info, warn, error", c.Log.Level))
	}
	return errors.Join(errs...)
}

// validateListen accepts only loopback addresses (ADR-0010, TH-05).
func validateListen(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q is not host:port", addr)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("port %q is not in 1..65535", port)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("host %q must be an IP literal or localhost", host)
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("host %q is not a loopback address; external access must go through the reverse proxy", host)
	}
	return nil
}

// validateDataDir requires an existing, private directory owned by the
// current user (TH-54).
func validateDataDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%q must be an absolute path", dir)
	}
	if filepath.Clean(dir) != dir {
		return fmt.Errorf("%q must be a clean path", dir)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%q: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%q must not be a symlink", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%q is not a directory", dir)
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("%q has mode %#o; group and other permissions must be empty (expected 0700)", dir, perm)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%q: cannot determine owner", dir)
	}
	if uid := os.Getuid(); int(st.Uid) != uid {
		return fmt.Errorf("%q is owned by uid %d, expected uid %d", dir, st.Uid, uid)
	}
	return nil
}

func (a Auth) validate() []error {
	var errs []error
	check := func(name string, d, lo, hi time.Duration) {
		if d < lo || d > hi {
			errs = append(errs, fmt.Errorf("auth.%s: %s is outside %s..%s", name, d, lo, hi))
		}
	}
	check("session_idle_timeout", a.SessionIdleTimeout.Duration, 5*time.Minute, 24*time.Hour)
	check("session_absolute_timeout", a.SessionAbsoluteTimeout.Duration, time.Hour, 720*time.Hour)
	check("setup_token_ttl", a.SetupTokenTTL.Duration, 10*time.Minute, 72*time.Hour)
	if a.SessionAbsoluteTimeout.Duration < a.SessionIdleTimeout.Duration {
		errs = append(errs, errors.New("auth.session_absolute_timeout must not be shorter than auth.session_idle_timeout"))
	}
	return errs
}

// validateOrigin accepts https origins, and http origins only for loopback
// hosts (local development without TLS).
func validateOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not an origin like https://host[:port]", origin)
	}
	if u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must contain only scheme, host and port", origin)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			return nil
		}
		return fmt.Errorf("%q uses http for a non-loopback host; use https", origin)
	default:
		return fmt.Errorf("%q must use https", origin)
	}
}

// Origin returns the normalized public origin (scheme://host[:port]).
func (s Server) Origin() string {
	u, err := url.Parse(s.PublicOrigin)
	if err != nil {
		return s.PublicOrigin
	}
	return u.Scheme + "://" + u.Host
}
