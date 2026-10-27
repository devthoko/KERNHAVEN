package policy

import (
	"errors"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

func base() agentproto.ContainerSpec {
	return agentproto.ContainerSpec{
		Name: "web", Image: "nginx@sha256:" + strings.Repeat("a", 64), User: "101:101",
		MemoryBytes: 256 << 20, RestartPolicy: "unless-stopped",
		Ports:  []agentproto.PortBinding{{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80}},
		Mounts: []agentproto.MountSpec{{Type: "volume", Source: "web-data", Target: "/data"}},
	}
}

func rules(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.Rule)
	}
	return out
}

func TestSafeSpecHasNoFindings(t *testing.T) {
	s := base()
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	r := Evaluate(s, Options{})
	if len(r.Violations) != 0 || len(r.Warnings) != 0 {
		t.Fatalf("violations %v warnings %v", rules(r.Violations), rules(r.Warnings))
	}
	if d, err := Check(s, nil, Options{}); err != nil || len(d.Applied) != 0 {
		t.Fatalf("check: %v %v", d, err)
	}
}

// AT-F02-04: every dangerous setting is a violation.
func TestViolations(t *testing.T) {
	cases := map[string]struct {
		mod  func(*agentproto.ContainerSpec)
		rule string
	}{
		"privileged":   {func(s *agentproto.ContainerSpec) { s.Privileged = true }, RulePrivileged},
		"host network": {func(s *agentproto.ContainerSpec) { s.NetworkMode = "host" }, RuleHostNetwork},
		"host pid":     {func(s *agentproto.ContainerSpec) { s.PidMode = "host" }, RuleHostPID},
		"host ipc":     {func(s *agentproto.ContainerSpec) { s.IpcMode = "host" }, RuleHostIPC},
		"host uts":     {func(s *agentproto.ContainerSpec) { s.UTSMode = "host" }, RuleHostUTS},
		"cap add":      {func(s *agentproto.ContainerSpec) { s.CapAdd = []string{"SYS_ADMIN"} }, RuleCapability},
		"device":       {func(s *agentproto.ContainerSpec) { s.Devices = []string{"/dev/sda"} }, RuleDevice},
		"seccomp off":  {func(s *agentproto.ContainerSpec) { s.SecurityOpt = []string{"seccomp=unconfined"} }, RuleSecurityOpt},
		"apparmor off": {func(s *agentproto.ContainerSpec) { s.SecurityOpt = []string{"apparmor:unconfined"} }, RuleSecurityOpt},
		"nnp false":    {func(s *agentproto.ContainerSpec) { s.SecurityOpt = []string{"no-new-privileges=false"} }, RuleSecurityOpt},
		"selinux off":  {func(s *agentproto.ContainerSpec) { s.SecurityOpt = []string{"label=disable"} }, RuleSecurityOpt},
		"bind outside": {func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/srv/x", Target: "/x"}}
		}, RuleBindMount},
		"docker socket": {func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/var/run/docker.sock", Target: "/s"}}
		}, RuleDockerSocket},
		"rootless sock": {func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/home/u/docker.sock", Target: "/s"}}
		}, RuleDockerSocket},
		"host root": {func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/", Target: "/host"}}
		}, RuleSensitivePath},
		"etc": {func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/etc/shadow", Target: "/s"}}
		}, RuleSensitivePath},
		"dotdot": {func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/srv/../etc", Target: "/s"}}
		}, RuleSensitivePath},
		"kernhaven db": {func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/var/lib/kernhaven", Target: "/s"}}
		}, RuleSensitivePath},
	}
	for name, tc := range cases {
		s := base()
		tc.mod(&s)
		if err := Validate(s); err != nil {
			t.Fatalf("%s: spec invalid: %v", name, err)
		}
		r := Evaluate(s, Options{AllowedBindRoots: []string{"/srv/kernhaven"}})
		if got := rules(r.Violations); len(got) != 1 || got[0] != tc.rule {
			t.Errorf("%s: violations %v, want [%s]", name, got, tc.rule)
		}
		var pe *PolicyError
		if _, err := Check(s, nil, Options{AllowedBindRoots: []string{"/srv/kernhaven"}}); !errors.As(err, &pe) {
			t.Errorf("%s: Check accepted a violation", name)
		}
	}
}

func TestAllowedBindRootAndSymlinkResolution(t *testing.T) {
	s := base()
	s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/srv/kernhaven/media", Target: "/media", ReadOnly: true}}
	opts := Options{AllowedBindRoots: []string{"/srv/kernhaven"}}
	if r := Evaluate(s, opts); len(r.Violations) != 0 {
		t.Fatalf("allowed bind rejected: %v", r.Violations)
	}
	// A symlink under the allowed root pointing at /etc is caught.
	opts.Resolve = func(p string) (string, error) { return "/etc", nil }
	if r := Evaluate(s, opts); len(r.Violations) != 1 || r.Violations[0].Rule != RuleSensitivePath {
		t.Fatalf("symlink escape not caught: %v", r.Violations)
	}
	// Prefix tricks are not "below".
	s.Mounts[0].Source = "/srv/kernhaven-evil"
	if r := Evaluate(s, Options{AllowedBindRoots: []string{"/srv/kernhaven"}}); len(r.Violations) != 1 {
		t.Fatalf("prefix trick accepted: %v", r.Violations)
	}
}

// AT-F02-04: exceptions.
func TestExceptions(t *testing.T) {
	s := base()
	s.Privileged = true
	s.CapAdd = []string{"NET_ADMIN"}
	if _, err := Check(s, []string{RulePrivileged}, Options{}); err == nil {
		t.Fatal("partial exception accepted")
	}
	d, err := Check(s, []string{RuleCapability, RulePrivileged}, Options{})
	if err != nil || strings.Join(d.Applied, ",") != "capability,privileged" {
		t.Fatalf("approved exceptions: %v %v", d.Applied, err)
	}
	// Superfluous exceptions are rejected (no blanket approvals).
	if _, err := Check(base(), []string{RulePrivileged}, Options{}); err == nil {
		t.Fatal("unneeded exception accepted")
	}
	// Never-exemptible rules.
	s = base()
	s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "/run/docker.sock", Target: "/s"}}
	for _, ex := range [][]string{{RuleDockerSocket}, {RuleSensitivePath}, {RuleBindMount}, {"anything"}} {
		if _, err := Check(s, ex, Options{}); err == nil {
			t.Errorf("exception %v accepted for the Docker socket", ex)
		}
	}
	if Exemptible(RuleDockerSocket) || Exemptible(RuleSensitivePath) || !Exemptible(RulePrivileged) {
		t.Fatal("exemptibility wrong")
	}
}

func TestWarnings(t *testing.T) {
	s := base()
	s.Image = "nginx:1.27"
	s.User = ""
	s.MemoryBytes = 0
	s.RestartPolicy = "always"
	s.Ports = []agentproto.PortBinding{{HostPort: 80, ContainerPort: 80}}
	got := strings.Join(rules(Evaluate(s, Options{}).Warnings), ",")
	for _, w := range []string{"image-not-pinned", "port-all-interfaces", "privileged-port", "runs-as-root", "no-memory-limit", "restart-always"} {
		if !strings.Contains(got, w) {
			t.Errorf("missing warning %s in %s", w, got)
		}
	}
}

func TestValidateRejectsMalformedSpecs(t *testing.T) {
	cases := map[string]func(*agentproto.ContainerSpec){
		"name":        func(s *agentproto.ContainerSpec) { s.Name = "-bad" },
		"long name":   func(s *agentproto.ContainerSpec) { s.Name = strings.Repeat("a", 64) },
		"image":       func(s *agentproto.ContainerSpec) { s.Image = "UPPER/Case" },
		"image space": func(s *agentproto.ContainerSpec) { s.Image = "nginx latest" },
		"env name":    func(s *agentproto.ContainerSpec) { s.Env = []agentproto.EnvVar{{Name: "1BAD", Value: "x"}} },
		"env dup":     func(s *agentproto.ContainerSpec) { s.Env = []agentproto.EnvVar{{Name: "A"}, {Name: "A"}} },
		"env nul":     func(s *agentproto.ContainerSpec) { s.Env = []agentproto.EnvVar{{Name: "A", Value: "a\x00b"}} },
		"port range": func(s *agentproto.ContainerSpec) {
			s.Ports = []agentproto.PortBinding{{HostPort: 70000, ContainerPort: 80}}
		},
		"port proto": func(s *agentproto.ContainerSpec) {
			s.Ports = []agentproto.PortBinding{{HostPort: 1, ContainerPort: 80, Protocol: "sctp"}}
		},
		"port ip": func(s *agentproto.ContainerSpec) {
			s.Ports = []agentproto.PortBinding{{HostIP: "example.org", HostPort: 1, ContainerPort: 80}}
		},
		"port dup": func(s *agentproto.ContainerSpec) {
			s.Ports = []agentproto.PortBinding{{HostPort: 81, ContainerPort: 80}, {HostPort: 81, ContainerPort: 81}}
		},
		"mount target": func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "volume", Source: "v", Target: "data"}}
		},
		"mount root": func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "volume", Source: "v", Target: "/"}}
		},
		"mount type": func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "npipe", Source: "v", Target: "/d"}}
		},
		"bind relative": func(s *agentproto.ContainerSpec) {
			s.Mounts = []agentproto.MountSpec{{Type: "bind", Source: "data", Target: "/d"}}
		},
		"network": func(s *agentproto.ContainerSpec) { s.NetworkMode = "container:abc" },
		"restart": func(s *agentproto.ContainerSpec) { s.RestartPolicy = "sometimes" },
		"reserved lbl": func(s *agentproto.ContainerSpec) {
			s.Labels = map[string]string{"io.kernhaven.policy.exceptions": "privileged"}
		},
		"pid mode": func(s *agentproto.ContainerSpec) { s.PidMode = "container:x" },
		"memory":   func(s *agentproto.ContainerSpec) { s.MemoryBytes = 1024 },
		"user":     func(s *agentproto.ContainerSpec) { s.User = "root; rm -rf /" },
		"workdir":  func(s *agentproto.ContainerSpec) { s.WorkingDir = "app" },
	}
	for name, mod := range cases {
		s := base()
		mod(&s)
		if err := Validate(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestImageReferences(t *testing.T) {
	good := []string{"alpine", "alpine:3", "library/alpine:3.20", "ghcr.io/org/app:v1.2.3", "registry.local:5000/team/app@sha256:" + strings.Repeat("0", 64), "nginx:1.27-alpine"}
	bad := []string{"", "Alpine", "alpine:", "alpine::3", "-alpine", "alpine@sha256:abc", "a b", strings.Repeat("a", 256), "../x", "./x", "-host/x", "host./x"}
	for _, g := range good {
		if !ValidImageReference(g) {
			t.Errorf("%q rejected", g)
		}
	}
	for _, b := range bad {
		if ValidImageReference(b) {
			t.Errorf("%q accepted", b)
		}
	}
}
