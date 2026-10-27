// Package policy validates container specifications and evaluates the
// container security policy (M6, TH-21, TH-30, TH-31). Core and agent both
// evaluate it; the agent's evaluation is authoritative.
package policy

import (
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Rule names.
const (
	RulePrivileged    = "privileged"
	RuleHostNetwork   = "host-network"
	RuleHostPID       = "host-pid"
	RuleHostIPC       = "host-ipc"
	RuleHostUTS       = "host-uts"
	RuleCapability    = "capability"
	RuleDevice        = "device"
	RuleSecurityOpt   = "security-opt"
	RuleBindMount     = "bind-mount"
	RuleDockerSocket  = "docker-socket"
	RuleSensitivePath = "sensitive-path"
)

// nonExemptible rules can never be approved.
var nonExemptible = map[string]bool{RuleDockerSocket: true, RuleSensitivePath: true}

// Exemptible reports whether an owner may approve an exception for rule.
func Exemptible(rule string) bool {
	switch rule {
	case RulePrivileged, RuleHostNetwork, RuleHostPID, RuleHostIPC, RuleHostUTS,
		RuleCapability, RuleDevice, RuleSecurityOpt, RuleBindMount:
		return true
	}
	return false
}

// Finding is one violation or warning.
type Finding struct {
	Rule       string `json:"rule"`
	Field      string `json:"field"`
	Message    string `json:"message"`
	Exemptible bool   `json:"exemptible"`
}

// Result is the outcome of an evaluation.
type Result struct {
	Violations []Finding `json:"violations"`
	Warnings   []Finding `json:"warnings"`
}

// Options configure evaluation.
type Options struct {
	// AllowedBindRoots are host directories below which bind mounts are
	// allowed without an exception. Empty means none.
	AllowedBindRoots []string
	// Resolve resolves symlinks of a host path (the agent passes
	// filepath.EvalSymlinks); nil uses the cleaned path as given.
	Resolve func(string) (string, error)
}

// sensitiveRoots may never be bind-mounted, nor anything below them.
var sensitiveRoots = []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/run", "/var/run", "/var/lib/docker", "/var/lib/kernhaven", "/var/lib/kernhaven-agent", "/etc/kernhaven"}

// ReservedLabelPrefix is set by Kernhaven only.
const ReservedLabelPrefix = "io.kernhaven."

var (
	nameRe      = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}$`)
	imageRe     = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?)*(?::[0-9]{1,5})?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)
	envNameRe   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
	labelKeyRe  = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,127}$`)
	userRe      = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31}(?::[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,31})?$`)
	capRe       = regexp.MustCompile(`^(CAP_)?[A-Z_]{2,32}$`)
	volumeRe    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	restartVals = map[string]bool{"": true, "no": true, "always": true, "unless-stopped": true, "on-failure": true}
)

// ValidImageReference reports whether ref is a well-formed image reference.
func ValidImageReference(ref string) bool { return len(ref) <= 255 && imageRe.MatchString(ref) }

// ValidName reports whether n is a valid container, volume or network name.
func ValidName(n string) bool { return nameRe.MatchString(n) }

// Validate checks the structure of a spec. It does not apply the security
// policy (see Evaluate).
func Validate(s agentproto.ContainerSpec) error {
	var errs []error
	bad := func(field, format string, a ...any) { errs = append(errs, fmt.Errorf(field+": "+format, a...)) }

	if !ValidName(s.Name) {
		bad("name", "must be 1-63 characters: letters, digits, _ . - (starting with a letter or digit)")
	}
	if !ValidImageReference(s.Image) {
		bad("image", "is not a valid image reference")
	}
	if len(s.Cmd) > 64 || len(s.Entrypoint) > 64 {
		bad("cmd", "at most 64 arguments")
	}
	for _, a := range append(append([]string{}, s.Cmd...), s.Entrypoint...) {
		if len(a) > 4096 || strings.ContainsRune(a, 0) {
			bad("cmd", "arguments must be at most 4096 bytes without NUL")
			break
		}
	}
	seenEnv := map[string]bool{}
	if len(s.Env) > 256 {
		bad("env", "at most 256 variables")
	}
	for _, e := range s.Env {
		if !envNameRe.MatchString(e.Name) {
			bad("env", "invalid variable name %q", e.Name)
		}
		if seenEnv[e.Name] {
			bad("env", "duplicate variable %q", e.Name)
		}
		seenEnv[e.Name] = true
		if len(e.Value) > 32768 || strings.ContainsRune(e.Value, 0) {
			bad("env", "value of %q too long or contains NUL", e.Name)
		}
	}
	if s.User != "" && !userRe.MatchString(s.User) {
		bad("user", "must be user[:group] (names or IDs)")
	}
	if s.WorkingDir != "" && !filepath.IsAbs(s.WorkingDir) {
		bad("working_dir", "must be absolute")
	}
	if len(s.Ports) > 64 {
		bad("ports", "at most 64 port bindings")
	}
	seenPort := map[string]bool{}
	for _, p := range s.Ports {
		if p.ContainerPort < 1 || p.ContainerPort > 65535 || p.HostPort < 0 || p.HostPort > 65535 {
			bad("ports", "ports must be 1..65535 (host port 0 = random)")
		}
		if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			bad("ports", "protocol must be tcp or udp")
		}
		if p.HostIP != "" && !validIP(p.HostIP) {
			bad("ports", "host_ip %q is not an IP address", p.HostIP)
		}
		key := fmt.Sprintf("%s/%d/%s", p.HostIP, p.HostPort, protocol(p))
		if p.HostPort != 0 && seenPort[key] {
			bad("ports", "host port %d/%s bound twice", p.HostPort, protocol(p))
		}
		seenPort[key] = true
	}
	if len(s.Mounts) > 32 {
		bad("mounts", "at most 32 mounts")
	}
	for _, m := range s.Mounts {
		if !filepath.IsAbs(m.Target) || filepath.Clean(m.Target) != m.Target || m.Target == "/" {
			bad("mounts", "target %q must be an absolute, clean path other than /", m.Target)
		}
		switch m.Type {
		case "volume":
			if !volumeRe.MatchString(m.Source) {
				bad("mounts", "volume name %q is invalid", m.Source)
			}
		case "bind":
			if !filepath.IsAbs(m.Source) {
				bad("mounts", "bind source %q must be an absolute host path", m.Source)
			}
		case "tmpfs":
			if m.Source != "" {
				bad("mounts", "tmpfs mounts take no source")
			}
		default:
			bad("mounts", "type must be volume, bind or tmpfs")
		}
	}
	switch s.NetworkMode {
	case "", "bridge", "none", "host":
	default:
		if !ValidName(s.NetworkMode) {
			bad("network_mode", "must be bridge, none, host or a network name")
		}
	}
	if !restartVals[s.RestartPolicy] {
		bad("restart_policy", "must be no, always, unless-stopped or on-failure")
	}
	if len(s.Labels) > 64 {
		bad("labels", "at most 64 labels")
	}
	for k, v := range s.Labels {
		if !labelKeyRe.MatchString(k) || len(v) > 1024 {
			bad("labels", "invalid label %q", k)
		}
		if strings.HasPrefix(k, ReservedLabelPrefix) {
			bad("labels", "label prefix %q is reserved", ReservedLabelPrefix)
		}
	}
	for _, c := range append(append([]string{}, s.CapAdd...), s.CapDrop...) {
		if c != "ALL" && !capRe.MatchString(c) {
			bad("capabilities", "invalid capability %q", c)
		}
	}
	for _, m := range []struct{ field, v string }{{"pid_mode", s.PidMode}, {"ipc_mode", s.IpcMode}, {"uts_mode", s.UTSMode}} {
		switch m.v {
		case "", "host", "private", "shareable":
		default:
			bad(m.field, "must be empty, host, private or shareable")
		}
	}
	for _, d := range s.Devices {
		if !filepath.IsAbs(d) {
			bad("devices", "device %q must be an absolute path", d)
		}
	}
	if s.MemoryBytes < 0 || (s.MemoryBytes > 0 && s.MemoryBytes < 6<<20) {
		bad("memory_bytes", "must be 0 (unlimited) or at least 6 MiB")
	}
	if s.NanoCPUs < 0 {
		bad("nano_cpus", "must not be negative")
	}
	return errors.Join(errs...)
}

func protocol(p agentproto.PortBinding) string {
	if p.Protocol == "" {
		return "tcp"
	}
	return p.Protocol
}

func validIP(s string) bool { return net.ParseIP(s) != nil }

func under(path, root string) bool {
	if root == "/" {
		return true
	}
	return path == root || strings.HasPrefix(path, root+"/")
}

// Evaluate applies the security policy to a structurally valid spec.
func Evaluate(s agentproto.ContainerSpec, o Options) Result {
	r := Result{Violations: []Finding{}, Warnings: []Finding{}}
	violation := func(rule, field, msg string) {
		r.Violations = append(r.Violations, Finding{Rule: rule, Field: field, Message: msg, Exemptible: Exemptible(rule)})
	}
	warn := func(rule, field, msg string) {
		r.Warnings = append(r.Warnings, Finding{Rule: rule, Field: field, Message: msg})
	}

	if s.Privileged {
		violation(RulePrivileged, "privileged", "privileged mode gives the container full access to the host")
	}
	if s.NetworkMode == "host" {
		violation(RuleHostNetwork, "network_mode", "the host network namespace exposes all host interfaces and local services")
	}
	if s.PidMode == "host" {
		violation(RuleHostPID, "pid_mode", "the host PID namespace lets the container see and signal host processes")
	}
	if s.IpcMode == "host" {
		violation(RuleHostIPC, "ipc_mode", "the host IPC namespace shares memory with host processes")
	}
	if s.UTSMode == "host" {
		violation(RuleHostUTS, "uts_mode", "the host UTS namespace allows changing the host name")
	}
	for _, c := range s.CapAdd {
		violation(RuleCapability, "cap_add", "added capability "+strings.TrimPrefix(c, "CAP_")+" widens what the container can do on the host")
	}
	for _, d := range s.Devices {
		violation(RuleDevice, "devices", "host device "+d+" is exposed to the container")
	}
	for _, opt := range s.SecurityOpt {
		o := strings.ToLower(strings.ReplaceAll(opt, " ", ""))
		if strings.Contains(o, "unconfined") || strings.Contains(o, "no-new-privileges=false") || strings.Contains(o, "no-new-privileges:false") || strings.HasPrefix(o, "label=disable") || strings.HasPrefix(o, "label:disable") {
			violation(RuleSecurityOpt, "security_opt", "security option "+opt+" disables a kernel protection")
		}
	}
	for _, m := range s.Mounts {
		if m.Type != "bind" {
			continue
		}
		p := filepath.Clean(m.Source)
		if o.Resolve != nil {
			if rp, err := o.Resolve(p); err == nil {
				p = rp
			}
		}
		switch {
		case filepath.Base(p) == "docker.sock" || strings.HasSuffix(p, "/docker.sock"):
			violation(RuleDockerSocket, "mounts", "mounting the Docker socket gives the container root on the host")
		case p == "/" || anyUnder(p, sensitiveRoots):
			violation(RuleSensitivePath, "mounts", "host path "+p+" is a protected system location")
		case !anyUnder(p, o.AllowedBindRoots):
			violation(RuleBindMount, "mounts", "host path "+p+" is outside the allowed bind-mount roots")
		}
	}

	if !strings.Contains(s.Image, "@sha256:") {
		warn("image-not-pinned", "image", "the image is not pinned by digest; updates may change it unnoticed")
	}
	for _, p := range s.Ports {
		if p.HostPort == 0 {
			continue
		}
		if p.HostIP == "" || p.HostIP == "0.0.0.0" || p.HostIP == "::" {
			warn("port-all-interfaces", "ports", fmt.Sprintf("port %d/%s is published on all interfaces", p.HostPort, protocol(p)))
		}
		if p.HostPort < 1024 {
			warn("privileged-port", "ports", fmt.Sprintf("host port %d is below 1024", p.HostPort))
		}
	}
	if s.User == "" || s.User == "root" || s.User == "0" || strings.HasPrefix(s.User, "0:") || strings.HasPrefix(s.User, "root:") {
		warn("runs-as-root", "user", "the container process runs as root inside the container (unless the image sets another user)")
	}
	if s.MemoryBytes == 0 {
		warn("no-memory-limit", "memory_bytes", "no memory limit; a runaway container can exhaust host memory")
	}
	if s.RestartPolicy == "always" {
		warn("restart-always", "restart_policy", "restart policy always also restarts containers you stopped after a daemon restart; consider unless-stopped")
	}
	return r
}

func anyUnder(p string, roots []string) bool {
	for _, r := range roots {
		if under(p, filepath.Clean(r)) {
			return true
		}
	}
	return false
}

// Decision is the outcome of Check.
type Decision struct {
	Result  Result
	Applied []string // exceptions that cover violations
}

// PolicyError lists violations not covered by valid exceptions.
type PolicyError struct {
	Uncovered []Finding
	Invalid   []string // exceptions that are not allowed or not needed
}

func (e *PolicyError) Error() string {
	var parts []string
	for _, f := range e.Uncovered {
		parts = append(parts, f.Rule+": "+f.Message)
	}
	for _, x := range e.Invalid {
		parts = append(parts, "exception "+x+" is not allowed or not needed")
	}
	return "container policy violation: " + strings.Join(parts, "; ")
}

// Check evaluates s and accepts it only if every violation is covered by an
// exception for an exemptible rule and no exception is superfluous.
func Check(s agentproto.ContainerSpec, exceptions []string, o Options) (Decision, error) {
	res := Evaluate(s, o)
	approved := map[string]bool{}
	pe := &PolicyError{}
	for _, x := range exceptions {
		if !Exemptible(x) || nonExemptible[x] {
			pe.Invalid = append(pe.Invalid, x)
			continue
		}
		approved[x] = true
	}
	violated := map[string]bool{}
	for _, v := range res.Violations {
		violated[v.Rule] = true
		if !approved[v.Rule] || !v.Exemptible {
			pe.Uncovered = append(pe.Uncovered, v)
		}
	}
	for x := range approved {
		if !violated[x] {
			pe.Invalid = append(pe.Invalid, x)
		}
	}
	if len(pe.Uncovered) > 0 || len(pe.Invalid) > 0 {
		sort.Strings(pe.Invalid)
		return Decision{Result: res}, pe
	}
	var applied []string
	for x := range approved {
		applied = append(applied, x)
	}
	sort.Strings(applied)
	return Decision{Result: res, Applied: applied}, nil
}
