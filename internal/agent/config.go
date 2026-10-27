package agent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/devthoko/KERNHAVEN/internal/agent/storage"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// DefaultConfigPath is the agent configuration file.
const DefaultConfigPath = "/etc/kernhaven/agent.toml"

// Config is the validated agent configuration.
type Config struct {
	Socket         string   `toml:"socket"`
	AllowedUIDs    []uint32 `toml:"allowed_uids"`
	GrantPublicKey string   `toml:"grant_public_key"`
	DockerSocket   string   `toml:"docker_socket"`
	// AllowedBindRoots are host directories containers may bind-mount
	// without a policy exception (M6). Empty means none.
	AllowedBindRoots []string `toml:"allowed_bind_roots"`
	// HelperImage is the image for volume copies before app updates (ADR-0021).
	HelperImage string `toml:"helper_image"`
	// Role is "docker" (default) or "storage" (M9, runs as root, disks only).
	Role string `toml:"role"`
	// MountRoot is where data disks are mounted (M9).
	MountRoot string `toml:"mount_root"`
	// StorageIncludeLoop treats loop devices as disks. Only for tests.
	StorageIncludeLoop bool `toml:"storage_include_loop_devices"`
	Log                struct {
		Level string `toml:"level"`
	} `toml:"log"`

	publicKey ed25519.PublicKey
}

// PublicKey returns the loaded grant verification key.
func (c Config) PublicKey() ed25519.PublicKey { return c.publicKey }

// LoadConfig reads and validates the agent configuration strictly.
func LoadConfig(path string) (Config, error) {
	cfg := Config{Socket: "/run/kernhaven/agent.sock", DockerSocket: "/run/docker.sock", GrantPublicKey: "/etc/kernhaven/agent-grant.pub", HelperImage: DefaultHelperImage, MountRoot: storage.DefaultMountRoot, Role: "docker"}
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
	for _, r := range cfg.AllowedBindRoots {
		if !filepath.IsAbs(r) || filepath.Clean(r) != r || r == "/" {
			errs = append(errs, fmt.Errorf("allowed_bind_roots: %q must be an absolute, clean directory other than /", r))
		}
	}
	if cfg.Role != "docker" && cfg.Role != "storage" {
		errs = append(errs, fmt.Errorf("role: %q is not one of docker, storage", cfg.Role))
	}
	if !filepath.IsAbs(cfg.MountRoot) || filepath.Clean(cfg.MountRoot) != cfg.MountRoot || cfg.MountRoot == "/" {
		errs = append(errs, fmt.Errorf("mount_root: %q must be an absolute, clean directory other than /", cfg.MountRoot))
	}
	if !policy.ValidImageReference(cfg.HelperImage) {
		errs = append(errs, fmt.Errorf("helper_image: %q is not a valid image reference", cfg.HelperImage))
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
