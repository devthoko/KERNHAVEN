package compose

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

func (p *parser) service(pr kv, proj *Project) (Service, bool) {
	name := pr.key
	path := "services." + name
	if !serviceNameRe.MatchString(name) {
		p.fail(pr.kNode, path, "service names must be 1-30 characters: letters, digits, _ . -")
		return Service{}, false
	}
	attrs, ok := p.mapping(pr.val, path)
	if !ok {
		return Service{}, false
	}
	before := len(p.errs)
	svc := Service{Name: name, Line: pr.kNode.Line}
	s := &svc.Spec
	s.Name = ContainerName(p.stack, name)
	networkKey := ""
	networkSet := false
	for _, a := range attrs {
		ap := path + "." + a.key
		switch a.key {
		case "image":
			s.Image, _ = p.scalar(a.val, ap)
		case "command":
			s.Cmd, _ = p.command(a.val, ap)
		case "entrypoint":
			s.Entrypoint, _ = p.command(a.val, ap)
		case "environment":
			if env, ok := p.stringMap(a.val, ap, false); ok {
				keys := make([]string, 0, len(env))
				for k := range env {
					keys = append(keys, k)
				}
				sortStrings(keys)
				for _, k := range keys {
					s.Env = append(s.Env, agentproto.EnvVar{Name: k, Value: env[k]})
				}
			}
		case "user":
			s.User, _ = p.scalar(a.val, ap)
		case "working_dir":
			s.WorkingDir, _ = p.scalar(a.val, ap)
		case "ports":
			s.Ports = p.ports(a.val, ap)
		case "expose":
			// Documentation only; containers on the same network reach each other anyway.
		case "volumes":
			s.Mounts = append(s.Mounts, p.mounts(a.val, ap, proj)...)
		case "tmpfs":
			if paths, ok := p.stringsOrOne(a.val, ap); ok {
				for _, t := range paths {
					s.Mounts = append(s.Mounts, agentproto.MountSpec{Type: "tmpfs", Target: t})
				}
			}
		case "networks":
			networkKey, networkSet = p.serviceNetwork(a.val, ap, proj)
		case "network_mode":
			if networkKey != "" {
				p.fail(a.kNode, ap, "network_mode and networks cannot be combined")
			}
			if v, ok := p.scalar(a.val, ap); ok {
				switch v {
				case "host", "none", "bridge":
					s.NetworkMode = v
					networkSet = true
				default:
					p.fail(a.val, ap, "network_mode %q is not supported (host, none or bridge)", v)
				}
			}
		case "restart":
			if v, ok := p.scalar(a.val, ap); ok {
				switch v {
				case "no", "always", "unless-stopped", "on-failure":
					s.RestartPolicy = v
				default:
					p.fail(a.val, ap, "must be no, always, unless-stopped or on-failure")
				}
			}
		case "labels":
			if l, ok := p.stringMap(a.val, ap, false); ok {
				s.Labels = l
			}
		case "depends_on":
			svc.DependsOn = p.dependsOn(a.val, ap)
		case "healthcheck":
			s.Healthcheck = p.healthcheck(a.val, ap)
		case "privileged":
			s.Privileged, _ = p.boolean(a.val, ap)
		case "read_only":
			s.ReadOnlyRootfs, _ = p.boolean(a.val, ap)
		case "cap_add":
			s.CapAdd, _ = p.strings(a.val, ap)
		case "cap_drop":
			s.CapDrop, _ = p.strings(a.val, ap)
		case "security_opt":
			s.SecurityOpt, _ = p.strings(a.val, ap)
		case "devices":
			if devs, ok := p.strings(a.val, ap); ok {
				for _, d := range devs {
					host, ctr, _ := strings.Cut(d, ":")
					ctr, _, _ = strings.Cut(ctr, ":")
					if ctr != "" && ctr != host {
						p.fail(a.val, ap, "device %q must use the same path in the container", d)
						continue
					}
					s.Devices = append(s.Devices, host)
				}
			}
		case "pid":
			s.PidMode, _ = p.scalar(a.val, ap)
		case "ipc":
			s.IpcMode, _ = p.scalar(a.val, ap)
		case "mem_limit":
			s.MemoryBytes = p.bytes(a.val, ap)
		case "cpus":
			s.NanoCPUs = p.cpus(a.val, ap)
		case "deploy":
			p.deploy(a.val, ap, s)
		case "container_name":
			if v, ok := p.scalar(a.val, ap); ok && v != s.Name {
				p.fail(a.val, ap, "container names are managed by Kernhaven; it would be %q", s.Name)
			}
		case "build":
			p.fail(a.kNode, ap, "building images is not supported; use a published image")
		case "env_file":
			p.fail(a.kNode, ap, "env_file is not supported; use stack variables (they can be secret)")
		case "secrets", "configs":
			p.fail(a.kNode, ap, "%s are not supported; use secret stack variables", a.key)
		case "extends", "profiles":
			p.fail(a.kNode, ap, "%s is not supported", a.key)
		default:
			p.fail(a.kNode, ap, "service option %q is not supported", a.key)
		}
	}
	if s.Image == "" {
		p.fail(pr.kNode, path+".image", "an image is required")
	}
	if !networkSet || (networkKey != "" && s.NetworkMode == "") {
		if networkKey == "" {
			networkKey = "default"
		}
		if nw, ok := findNetwork(proj, networkKey); ok {
			s.NetworkMode = nw.Name
		}
	}
	return svc, len(p.errs) == before
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (p *parser) stringsOrOne(n *yaml.Node, path string) ([]string, bool) {
	if d := p.deref(n); d.Kind == yaml.ScalarNode {
		s, ok := p.scalar(d, path)
		return []string{s}, ok
	}
	return p.strings(n, path)
}

// command accepts a list or a string split like a shell would.
func (p *parser) command(n *yaml.Node, path string) ([]string, bool) {
	d := p.deref(n)
	if d.Kind == yaml.SequenceNode {
		return p.strings(d, path)
	}
	s, ok := p.scalar(d, path)
	if !ok {
		return nil, false
	}
	words, err := splitWords(s)
	if err != nil {
		p.fail(d, path, "%v", err)
		return nil, false
	}
	return words, true
}

// splitWords splits like a POSIX shell (quotes and backslashes), without expansion.
func splitWords(s string) ([]string, error) {
	var words []string
	var cur strings.Builder
	inWord, quote := false, rune(0)
	escaped := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
		case r == '\\' && quote != '\'':
			escaped, inWord = true, true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote, inWord = r, true
		case r == ' ' || r == '\t' || r == '\n':
			if inWord {
				words = append(words, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	if quote != 0 || escaped {
		return nil, fmt.Errorf("unterminated quote or escape")
	}
	if inWord {
		words = append(words, cur.String())
	}
	return words, nil
}

func (p *parser) ports(n *yaml.Node, path string) []agentproto.PortBinding {
	items, ok := p.sequence(n, path)
	if !ok {
		return nil
	}
	var out []agentproto.PortBinding
	for i, it := range items {
		ip := fmt.Sprintf("%s[%d]", path, i)
		d := p.deref(it)
		if d.Kind == yaml.MappingNode {
			attrs, ok := p.mapping(d, ip)
			if !ok {
				continue
			}
			var pb agentproto.PortBinding
			for _, a := range attrs {
				v, ok := p.scalar(a.val, ip+"."+a.key)
				if !ok {
					continue
				}
				switch a.key {
				case "target":
					pb.ContainerPort, _ = strconv.Atoi(v)
				case "published":
					pb.HostPort, _ = strconv.Atoi(v)
				case "host_ip":
					pb.HostIP = v
				case "protocol":
					pb.Protocol = v
				case "mode":
					if v != "host" && v != "ingress" {
						p.fail(a.val, ip+".mode", "must be host")
					}
				default:
					p.fail(a.kNode, ip+"."+a.key, "port option %q is not supported", a.key)
				}
			}
			if pb.ContainerPort == 0 {
				p.fail(d, ip, "target port is required")
				continue
			}
			out = append(out, pb)
			continue
		}
		v, ok := p.scalar(d, ip)
		if !ok {
			continue
		}
		pb, err := parsePort(v)
		if err != nil {
			p.fail(d, ip, "%v", err)
			continue
		}
		out = append(out, pb)
	}
	return out
}

// parsePort parses [ip:][host:]container[/proto]; IPv6 addresses in brackets.
func parsePort(v string) (agentproto.PortBinding, error) {
	var pb agentproto.PortBinding
	if base, proto, ok := strings.Cut(v, "/"); ok {
		v, pb.Protocol = base, proto
	}
	if strings.Contains(v, "-") {
		return pb, fmt.Errorf("port ranges are not supported")
	}
	if strings.HasPrefix(v, "[") {
		end := strings.Index(v, "]")
		if end < 0 {
			return pb, fmt.Errorf("invalid IPv6 address in %q", v)
		}
		pb.HostIP = v[1:end]
		v = strings.TrimPrefix(v[end+1:], ":")
	}
	parts := strings.Split(v, ":")
	nums := parts
	if len(parts) == 3 {
		pb.HostIP, nums = parts[0], parts[1:]
	}
	if len(nums) > 2 || len(nums) == 0 {
		return pb, fmt.Errorf("port %q must be [ip:][host:]container[/protocol]", v)
	}
	c, err := strconv.Atoi(nums[len(nums)-1])
	if err != nil {
		return pb, fmt.Errorf("invalid container port in %q", v)
	}
	pb.ContainerPort = c
	if len(nums) == 2 {
		h, err := strconv.Atoi(nums[0])
		if err != nil {
			return pb, fmt.Errorf("invalid host port in %q", v)
		}
		pb.HostPort = h
	}
	return pb, nil
}

func (p *parser) mounts(n *yaml.Node, path string, proj *Project) []agentproto.MountSpec {
	items, ok := p.sequence(n, path)
	if !ok {
		return nil
	}
	var out []agentproto.MountSpec
	for i, it := range items {
		ip := fmt.Sprintf("%s[%d]", path, i)
		d := p.deref(it)
		var m agentproto.MountSpec
		if d.Kind == yaml.MappingNode {
			attrs, ok := p.mapping(d, ip)
			if !ok {
				continue
			}
			for _, a := range attrs {
				switch a.key {
				case "type":
					m.Type, _ = p.scalar(a.val, ip+".type")
				case "source":
					m.Source, _ = p.scalar(a.val, ip+".source")
				case "target":
					m.Target, _ = p.scalar(a.val, ip+".target")
				case "read_only":
					m.ReadOnly, _ = p.boolean(a.val, ip+".read_only")
				default:
					p.fail(a.kNode, ip+"."+a.key, "mount option %q is not supported", a.key)
				}
			}
		} else {
			v, ok := p.scalar(d, ip)
			if !ok {
				continue
			}
			parts := strings.Split(v, ":")
			switch len(parts) {
			case 1:
				p.fail(d, ip, "anonymous volumes are not supported; use a named volume")
				continue
			case 2, 3:
				m.Source, m.Target = parts[0], parts[1]
				if len(parts) == 3 {
					switch parts[2] {
					case "ro":
						m.ReadOnly = true
					case "rw":
					default:
						p.fail(d, ip, "mode %q is not supported (ro or rw)", parts[2])
						continue
					}
				}
			default:
				p.fail(d, ip, "must be source:target[:ro]")
				continue
			}
			switch {
			case strings.HasPrefix(m.Source, "/"):
				m.Type = "bind"
			case strings.HasPrefix(m.Source, ".") || strings.HasPrefix(m.Source, "~"):
				p.fail(d, ip, "relative host paths are not supported; use an absolute path")
				continue
			default:
				m.Type = "volume"
			}
		}
		if m.Type == "volume" {
			v, ok := findVolume(proj, m.Source)
			if !ok {
				p.fail(d, ip, "volume %q is not declared under top-level volumes", m.Source)
				continue
			}
			m.Source = v.Name
		}
		out = append(out, m)
	}
	return out
}

func (p *parser) serviceNetwork(n *yaml.Node, path string, proj *Project) (string, bool) {
	d := p.deref(n)
	var keys []string
	switch d.Kind {
	case yaml.SequenceNode:
		keys, _ = p.strings(d, path)
	case yaml.MappingNode:
		pairs, ok := p.mapping(d, path)
		if !ok {
			return "", false
		}
		for _, pr := range pairs {
			v := p.deref(pr.val)
			if !(v.Kind == yaml.ScalarNode && (v.Tag == "!!null" || v.Value == "")) {
				p.fail(v, path+"."+pr.key, "network options (aliases, addresses) are not supported")
			}
			keys = append(keys, pr.key)
		}
	default:
		p.fail(d, path, "must be a list or mapping of network names")
		return "", false
	}
	if len(keys) != 1 {
		p.fail(d, path, "exactly one network per service is supported")
		return "", false
	}
	if _, ok := findNetwork(proj, keys[0]); !ok {
		p.fail(d, path, "network %q is not declared under top-level networks", keys[0])
		return "", false
	}
	return keys[0], true
}

func (p *parser) dependsOn(n *yaml.Node, path string) []string {
	d := p.deref(n)
	switch d.Kind {
	case yaml.SequenceNode:
		v, _ := p.strings(d, path)
		return v
	case yaml.MappingNode:
		pairs, ok := p.mapping(d, path)
		if !ok {
			return nil
		}
		var out []string
		for _, pr := range pairs {
			attrs, ok := p.mapping(pr.val, path+"."+pr.key)
			if !ok {
				continue
			}
			for _, a := range attrs {
				switch a.key {
				case "condition":
					if v, ok := p.scalar(a.val, path+"."+pr.key+".condition"); ok && v != "service_started" && v != "service_healthy" {
						p.fail(a.val, path+"."+pr.key+".condition", "must be service_started or service_healthy")
					}
				case "restart", "required":
				default:
					p.fail(a.kNode, path+"."+pr.key+"."+a.key, "option %q is not supported", a.key)
				}
			}
			out = append(out, pr.key)
		}
		return out
	}
	p.fail(d, path, "must be a list or mapping of service names")
	return nil
}

func (p *parser) healthcheck(n *yaml.Node, path string) *agentproto.Healthcheck {
	attrs, ok := p.mapping(n, path)
	if !ok {
		return nil
	}
	h := &agentproto.Healthcheck{}
	for _, a := range attrs {
		ap := path + "." + a.key
		switch a.key {
		case "test":
			d := p.deref(a.val)
			if d.Kind == yaml.SequenceNode {
				h.Test, _ = p.strings(d, ap)
			} else if s, ok := p.scalar(d, ap); ok {
				h.Test = []string{"CMD-SHELL", s}
			}
		case "interval":
			h.IntervalMS = p.duration(a.val, ap)
		case "timeout":
			h.TimeoutMS = p.duration(a.val, ap)
		case "start_period":
			h.StartPeriodMS = p.duration(a.val, ap)
		case "retries":
			if s, ok := p.scalar(a.val, ap); ok {
				r, err := strconv.Atoi(s)
				if err != nil || r < 0 || r > 100 {
					p.fail(a.val, ap, "must be 0..100")
				}
				h.Retries = r
			}
		case "disable":
			if b, _ := p.boolean(a.val, ap); b {
				h.Test = []string{"NONE"}
			}
		default:
			p.fail(a.kNode, ap, "healthcheck option %q is not supported", a.key)
		}
	}
	if len(h.Test) == 0 {
		p.fail(n, path+".test", "a test command is required")
		return nil
	}
	switch h.Test[0] {
	case "CMD", "CMD-SHELL", "NONE":
	default:
		h.Test = append([]string{"CMD"}, h.Test...)
	}
	return h
}

func (p *parser) duration(n *yaml.Node, path string) int64 {
	s, ok := p.scalar(n, path)
	if !ok {
		return 0
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d > 24*time.Hour {
		p.fail(n, path, "must be a duration like 30s or 1m30s")
		return 0
	}
	return d.Milliseconds()
}

// bytes parses Compose sizes (e.g. 512m, 1g, 1048576).
func (p *parser) bytes(n *yaml.Node, path string) int64 {
	s, ok := p.scalar(n, path)
	if !ok {
		return 0
	}
	v, err := ParseBytes(s)
	if err != nil {
		p.fail(n, path, "%v", err)
	}
	return v
}

// ParseBytes parses a Compose byte size.
func ParseBytes(s string) (int64, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	mult := int64(1)
	for _, u := range []struct {
		suffix string
		m      int64
	}{{"gb", 1 << 30}, {"mb", 1 << 20}, {"kb", 1 << 10}, {"g", 1 << 30}, {"m", 1 << 20}, {"k", 1 << 10}, {"b", 1}} {
		if strings.HasSuffix(s, u.suffix) {
			s, mult = strings.TrimSuffix(s, u.suffix), u.m
			break
		}
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 || f > 1<<50 {
		return 0, fmt.Errorf("invalid size; use e.g. 512m or 2g")
	}
	return int64(f * float64(mult)), nil
}

func (p *parser) cpus(n *yaml.Node, path string) int64 {
	s, ok := p.scalar(n, path)
	if !ok {
		return 0
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f <= 0 || f > 1024 {
		p.fail(n, path, "must be a positive number of CPUs, e.g. 0.5")
		return 0
	}
	return int64(f * 1e9)
}

func (p *parser) deploy(n *yaml.Node, path string, s *agentproto.ContainerSpec) {
	attrs, ok := p.mapping(n, path)
	if !ok {
		return
	}
	for _, a := range attrs {
		if a.key != "resources" {
			p.fail(a.kNode, path+"."+a.key, "deploy option %q is not supported (only resources.limits)", a.key)
			continue
		}
		res, ok := p.mapping(a.val, path+".resources")
		if !ok {
			continue
		}
		for _, r := range res {
			if r.key != "limits" {
				p.fail(r.kNode, path+".resources."+r.key, "only resources.limits is supported")
				continue
			}
			lim, ok := p.mapping(r.val, path+".resources.limits")
			if !ok {
				continue
			}
			for _, l := range lim {
				lp := path + ".resources.limits." + l.key
				switch l.key {
				case "memory":
					s.MemoryBytes = p.bytes(l.val, lp)
				case "cpus":
					s.NanoCPUs = p.cpus(l.val, lp)
				default:
					p.fail(l.kNode, lp, "limit %q is not supported", l.key)
				}
			}
		}
	}
}
