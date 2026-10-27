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
	Server  Server  `toml:"server"`
	Storage Storage `toml:"storage"`
	Log     Log     `toml:"log"`
}

// Server configures the HTTP listener.
type Server struct {
	Listen          string   `toml:"listen"`
	ShutdownTimeout Duration `toml:"shutdown_timeout"`
	MaxBodyBytes    int64    `toml:"max_body_bytes"`
}

// Storage configures persistent state.
type Storage struct {
	DataDir string `toml:"data_dir"`
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
		},
		Storage: Storage{DataDir: "/var/lib/kernhaven"},
		Log:     Log{Level: "info"},
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
