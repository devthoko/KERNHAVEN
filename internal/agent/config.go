package agent

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/devthoko/KERNHAVEN/internal/agent/files"
	"github.com/devthoko/KERNHAVEN/internal/agent/storage"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/policy"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
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
	// Role is "docker" (default), "storage" (M9, disks and mounts) or "files"
	// (M10, file access below the mount root). Each runs as its own service.
	Role string `toml:"role"`
	// MountRoot is where data disks are mounted (M9).
	MountRoot string `toml:"mount_root"`
	// FileRoots are the file manager's roots (M10), all at or below MountRoot.
	FileRoots []files.Root `toml:"file_roots"`
	// StorageIncludeLoop treats loop devices as disks. Only for tests.
	StorageIncludeLoop bool `toml:"storage_include_loop_devices"`
	// Proxy role (M12, ADR-0025): Caddy's admin socket, the Core's loopback
	// address (the Kernhaven route and the sign-in gate) and Caddy's ports.
	CaddyAdminSocket string `toml:"caddy_admin_socket"`
	CoreAddress      string `toml:"core_address"`
	HTTPPort         int    `toml:"http_port"`
	HTTPSPort        int    `toml:"https_port"`
	Log              struct {
		Level string `toml:"level"`
	} `toml:"log"`

	publicKey ed25519.PublicKey
}

// ProxySettings returns the proxy role's settings.
func (c Config) ProxySettings() proxy.Settings {
	return proxy.Settings{AdminSocket: c.CaddyAdminSocket, CoreAddress: c.CoreAddress, HTTPPort: c.HTTPPort, HTTPSPort: c.HTTPSPort}
}

// PublicKey returns the loaded grant verification key.
func (c Config) PublicKey() ed25519.PublicKey { return c.publicKey }

// LoadConfig reads and validates the agent configuration strictly.
func LoadConfig(path string) (Config, error) {
	cfg := Config{Socket: "/run/kernhaven/agent.sock", DockerSocket: "/run/docker.sock", GrantPublicKey: "/etc/kernhaven/agent-grant.pub", HelperImage: DefaultHelperImage, MountRoot: storage.DefaultMountRoot, Role: "docker",
		CaddyAdminSocket: "/run/kernhaven-caddy/admin.sock", CoreAddress: "127.0.0.1:8470", HTTPPort: 80, HTTPSPort: 443}
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
	if _, err := files.New(cfg.FileRoots, cfg.MountRoot); err != nil {
		errs = append(errs, err)
	}
	switch cfg.Role {
	case "docker", "storage", "files":
	case "proxy":
		errs = append(errs, validProxy(cfg)...)
	default:
		errs = append(errs, fmt.Errorf("role: %q is not one of docker, storage, files, proxy", cfg.Role))
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

func validProxy(cfg Config) []error {
	var errs []error
	if p := cfg.CaddyAdminSocket; !filepath.IsAbs(p) || filepath.Clean(p) != p {
		errs = append(errs, fmt.Errorf("caddy_admin_socket: %q must be an absolute, clean path", p))
	}
	host, port, err := net.SplitHostPort(cfg.CoreAddress)
	ip, perr := netip.ParseAddr(host)
	n, nerr := strconv.Atoi(port)
	if err != nil || perr != nil || !ip.IsLoopback() || nerr != nil || n < 1 || n > 65535 {
		errs = append(errs, fmt.Errorf("core_address: %q must be a loopback IP address with a port", cfg.CoreAddress))
	}
	for name, p := range map[string]int{"http_port": cfg.HTTPPort, "https_port": cfg.HTTPSPort} {
		if p < 1 || p > 65535 {
			errs = append(errs, fmt.Errorf("%s: %d is not a port", name, p))
		}
	}
	if cfg.HTTPPort == cfg.HTTPSPort {
		errs = append(errs, errors.New("http_port and https_port must differ"))
	}
	return errs
}
