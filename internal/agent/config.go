package agent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// DefaultConfigPath is the agent configuration file.
const DefaultConfigPath = "/etc/kernhaven/agent.toml"

// Config is the validated agent configuration.
type Config struct {
	Socket         string   `toml:"socket"`
	AllowedUIDs    []uint32 `toml:"allowed_uids"`
	GrantPublicKey string   `toml:"grant_public_key"`
	DockerSocket   string   `toml:"docker_socket"`
	Log            struct {
		Level string `toml:"level"`
	} `toml:"log"`

	publicKey ed25519.PublicKey
}

// PublicKey returns the loaded grant verification key.
func (c Config) PublicKey() ed25519.PublicKey { return c.publicKey }

// LoadConfig reads and validates the agent configuration strictly.
func LoadConfig(path string) (Config, error) {
	cfg := Config{Socket: "/run/kernhaven/agent.sock", DockerSocket: "/run/docker.sock", GrantPublicKey: "/etc/kernhaven/agent-grant.pub"}
	cfg.Log.Level = "info"
	md, err := toml.DecodeFile(path, &cfg)
	if err != nil {
		return Config{}, fmt.Errorf("read %s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		keys := make([]string, len(u))
		for i, k := range u {
			keys[i] = k.String()
		}
		return Config{}, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	var errs []error
	for name, p := range map[string]string{"socket": cfg.Socket, "docker_socket": cfg.DockerSocket, "grant_public_key": cfg.GrantPublicKey} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			errs = append(errs, fmt.Errorf("%s: %q must be an absolute, clean path", name, p))
		}
	}
	if len(cfg.AllowedUIDs) == 0 {
		errs = append(errs, errors.New("allowed_uids: at least one UID (the Core service user) is required"))
	}
	switch cfg.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log.level: %q is not one of debug, info, warn, error", cfg.Log.Level))
	}
	if len(errs) == 0 {
		key, err := agentproto.ReadPublicKey(cfg.GrantPublicKey)
		if err != nil {
			errs = append(errs, fmt.Errorf("grant_public_key: %w", err))
		}
		cfg.publicKey = key
	}
	if err := errors.Join(errs...); err != nil {
		return Config{}, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}
