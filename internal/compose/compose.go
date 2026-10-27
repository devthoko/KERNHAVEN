// Package compose parses the supported subset of the Compose specification
// (ADR-0018) into policy-checkable container specs, with line-accurate errors.
package compose

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// MaxSize is the largest Compose document accepted.
const MaxSize = 256 << 10

// maxNodes bounds alias expansion (YAML "billion laughs").
const maxNodes = 100000

// Error is a problem at a position in the document.
type Error struct {
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e Error) String() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s: %s", e.Line, e.Path, e.Message)
	}
	return e.Path + ": " + e.Message
}

// Errors is a list of problems; it implements error.
type Errors []Error

func (e Errors) Error() string {
	parts := make([]string, len(e))
	for i, x := range e {
		parts[i] = x.String()
	}
	return strings.Join(parts, "; ")
}

// Project is a parsed stack.
type Project struct {
	Name     string
	Services []Service // in document order
	Volumes  []Volume
	Networks []Network
}

// Service is one service mapped to a container spec.
type Service struct {
	Name      string
	Line      int
	Spec      agentproto.ContainerSpec
	DependsOn []string
}

// Volume is a top-level volume; Name is the Docker name.
type Volume struct {
	Key      string
	Name     string
	External bool
	Labels   map[string]string
}

// Network is a top-level network; Name is the Docker name.
type Network struct {
	Key      string
	Name     string
	External bool
	Internal bool
	Labels   map[string]string
}

var (
	stackNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	serviceNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,29}$`)
	resourceKeyRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,29}$`)
)

// ValidStackName reports whether n is a valid stack name.
func ValidStackName(n string) bool { return stackNameRe.MatchString(n) }

// ContainerName returns the container name of a service.
func ContainerName(stack, service string) string { return stack + "-" + service }

// DefaultNetwork is the network every service joins unless configured otherwise.
func DefaultNetwork(stack string) string { return stack + "_default" }

type parser struct {
	stack string
	vars  map[string]string
	errs  Errors
	nodes int
}

func (p *parser) fail(n *yaml.Node, path, format string, a ...any) {
	e := Error{Path: path, Message: fmt.Sprintf(format, a...)}
	if n != nil {
		e.Line, e.Column = n.Line, n.Column
	}
	p.errs = append(p.errs, e)
}

var yamlLineRe = regexp.MustCompile(`line (\d+)`)

// Parse parses src for stack name with the given variables.
func Parse(src []byte, stack string, vars map[string]string) (*Project, Errors) {
	p := &parser{stack: stack, vars: vars}
	if !ValidStackName(stack) {
		p.fail(nil, "name", "stack name must be 1-31 characters: lowercase letters, digits and -")
		return nil, p.errs
	}
	if len(src) > MaxSize {
		p.fail(nil, "document", "larger than %d KiB", MaxSize>>10)
		return nil, p.errs
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		e := Error{Path: "document", Message: strings.TrimPrefix(err.Error(), "yaml: ")}
		if m := yamlLineRe.FindStringSubmatch(err.Error()); m != nil {
			e.Line, _ = strconv.Atoi(m[1])
		}
		return nil, Errors{e}
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		p.fail(nil, "document", "empty document")
		return nil, p.errs
	}
	root := p.deref(doc.Content[0])
	proj := p.project(root)
	if len(p.errs) > 0 {
		return nil, p.errs
	}
	return proj, nil
}

// deref follows aliases, counting expansions.
func (p *parser) deref(n *yaml.Node) *yaml.Node {
	for n != nil && n.Kind == yaml.AliasNode {
		p.nodes++
		n = n.Alias
	}
	p.nodes++
	return n
}

type kv struct {
	key   string
	kNode *yaml.Node
	val   *yaml.Node
}

// mapping returns the key/value pairs of a mapping with "<<" merges applied.
func (p *parser) mapping(n *yaml.Node, path string) ([]kv, bool) {
	n = p.deref(n)
	if p.nodes > maxNodes {
		p.fail(n, path, "document expands to too many nodes (alias bomb?)")
		return nil, false
	}
	if n == nil || n.Kind != yaml.MappingNode {
		p.fail(n, path, "must be a mapping")
		return nil, false
	}
	var out []kv
	seen := map[string]bool{}
	var merges []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "<<" && k.Tag == "!!merge" {
			mv := p.deref(v)
			if mv.Kind == yaml.SequenceNode {
				merges = append(merges, mv.Content...)
			} else {
				merges = append(merges, mv)
			}
			continue
		}
		if seen[k.Value] {
			p.fail(k, path, "duplicate key %q", k.Value)
			continue
		}
		seen[k.Value] = true
		out = append(out, kv{k.Value, k, v})
	}
	for _, m := range merges {
		pairs, ok := p.mapping(m, path+".<<")
		if !ok {
			return nil, false
		}
		for _, pr := range pairs {
			if !seen[pr.key] {
				seen[pr.key] = true
				out = append(out, pr)
			}
		}
	}
	return out, true
}

func (p *parser) sequence(n *yaml.Node, path string) ([]*yaml.Node, bool) {
	n = p.deref(n)
	if n == nil || n.Kind != yaml.SequenceNode {
		p.fail(n, path, "must be a list")
		return nil, false
	}
	return n.Content, true
}

// scalar returns an interpolated scalar value.
func (p *parser) scalar(n *yaml.Node, path string) (string, bool) {
	n = p.deref(n)
	if n == nil || n.Kind != yaml.ScalarNode {
		p.fail(n, path, "must be a single value")
		return "", false
	}
	v, err := interpolate(n.Value, p.vars)
	if err != nil {
		p.fail(n, path, "%v", err)
		return "", false
	}
	return v, true
}

func (p *parser) boolean(n *yaml.Node, path string) (bool, bool) {
	s, ok := p.scalar(n, path)
	if !ok {
		return false, false
	}
	switch strings.ToLower(s) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	}
	p.fail(n, path, "must be true or false")
	return false, false
}

func (p *parser) strings(n *yaml.Node, path string) ([]string, bool) {
	items, ok := p.sequence(n, path)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(items))
	for i, it := range items {
		s, ok := p.scalar(it, fmt.Sprintf("%s[%d]", path, i))
		if !ok {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// stringMap accepts a mapping or a list of "key=value".
func (p *parser) stringMap(n *yaml.Node, path string, allowBareKey bool) (map[string]string, bool) {
	out := map[string]string{}
	d := p.deref(n)
	switch d.Kind {
	case yaml.MappingNode:
		pairs, ok := p.mapping(d, path)
		if !ok {
			return nil, false
		}
		for _, pr := range pairs {
			v := p.deref(pr.val)
			if v.Kind == yaml.ScalarNode && v.Tag == "!!null" {
				p.fail(v, path+"."+pr.key, "a value is required (values from the host environment are not supported)")
				continue
			}
			s, ok := p.scalar(v, path+"."+pr.key)
			if ok {
				out[pr.key] = s
			}
		}
	case yaml.SequenceNode:
		for i, it := range d.Content {
			s, ok := p.scalar(it, fmt.Sprintf("%s[%d]", path, i))
			if !ok {
				continue
			}
			k, v, found := strings.Cut(s, "=")
			if !found && !allowBareKey {
				p.fail(it, fmt.Sprintf("%s[%d]", path, i), "must be KEY=value (values from the host environment are not supported)")
				continue
			}
			out[k] = v
		}
	default:
		p.fail(d, path, "must be a mapping or a list of KEY=value")
		return nil, false
	}
	return out, true
}

func (p *parser) project(root *yaml.Node) *Project {
	pairs, ok := p.mapping(root, "document")
	if !ok {
		return nil
	}
	proj := &Project{Name: p.stack}
	var services, volumes, networks *yaml.Node
	for _, pr := range pairs {
		switch {
		case pr.key == "services":
			services = pr.val
		case pr.key == "volumes":
			volumes = pr.val
		case pr.key == "networks":
			networks = pr.val
		case pr.key == "name", pr.key == "version", strings.HasPrefix(pr.key, "x-"):
		default:
			p.fail(pr.kNode, pr.key, "top-level key %q is not supported (supported: services, volumes, networks, name, x-*)", pr.key)
		}
	}
	if services == nil {
		p.fail(root, "services", "at least one service is required")
		return nil
	}
	if volumes != nil {
		proj.Volumes = p.volumes(volumes)
	}
	nets := []Network{{Key: "default", Name: DefaultNetwork(p.stack)}}
	if networks != nil {
		nets = append(nets, p.networks(networks)...)
	}
	proj.Networks = nets
	svcPairs, ok := p.mapping(services, "services")
	if !ok {
		return nil
	}
	if len(svcPairs) == 0 {
		p.fail(services, "services", "at least one service is required")
	}
	if len(svcPairs) > 32 {
		p.fail(services, "services", "at most 32 services per stack")
	}
	for _, pr := range svcPairs {
		if svc, ok := p.service(pr, proj); ok {
			proj.Services = append(proj.Services, svc)
		}
	}
	p.checkDependencies(proj)
	return proj
}

func (p *parser) volumes(n *yaml.Node) []Volume {
	pairs, ok := p.mapping(n, "volumes")
	if !ok {
		return nil
	}
	var out []Volume
	for _, pr := range pairs {
		path := "volumes." + pr.key
		if !resourceKeyRe.MatchString(pr.key) {
			p.fail(pr.kNode, path, "invalid volume name")
			continue
		}
		v := Volume{Key: pr.key, Name: p.stack + "_" + pr.key, Labels: map[string]string{}}
		d := p.deref(pr.val)
		if d.Kind == yaml.MappingNode {
			attrs, ok := p.mapping(d, path)
			if !ok {
				continue
			}
			for _, a := range attrs {
				switch a.key {
				case "external":
					v.External, _ = p.boolean(a.val, path+".external")
				case "name":
					if s, ok := p.scalar(a.val, path+".name"); ok {
						v.Name = s
					}
				case "labels":
					if l, ok := p.stringMap(a.val, path+".labels", false); ok {
						v.Labels = l
					}
				default:
					p.fail(a.kNode, path+"."+a.key, "volume option %q is not supported", a.key)
				}
			}
		} else if !(d.Kind == yaml.ScalarNode && (d.Tag == "!!null" || d.Value == "")) {
			p.fail(d, path, "must be empty or a mapping")
		}
		if v.Name != p.stack+"_"+pr.key && !v.External {
			p.fail(pr.kNode, path+".name", "custom names are only allowed for external volumes")
		}
		out = append(out, v)
	}
	return out
}

func (p *parser) networks(n *yaml.Node) []Network {
	pairs, ok := p.mapping(n, "networks")
	if !ok {
		return nil
	}
	var out []Network
	for _, pr := range pairs {
		path := "networks." + pr.key
		if pr.key == "default" {
			p.fail(pr.kNode, path, "the default network is managed by Kernhaven")
			continue
		}
		if !resourceKeyRe.MatchString(pr.key) {
			p.fail(pr.kNode, path, "invalid network name")
			continue
		}
		nw := Network{Key: pr.key, Name: p.stack + "_" + pr.key, Labels: map[string]string{}}
		d := p.deref(pr.val)
		if d.Kind == yaml.MappingNode {
			attrs, ok := p.mapping(d, path)
			if !ok {
				continue
			}
			for _, a := range attrs {
				switch a.key {
				case "external":
					nw.External, _ = p.boolean(a.val, path+".external")
				case "internal":
					nw.Internal, _ = p.boolean(a.val, path+".internal")
				case "name":
					if s, ok := p.scalar(a.val, path+".name"); ok {
						nw.Name = s
					}
				case "driver":
					if s, ok := p.scalar(a.val, path+".driver"); ok && s != "bridge" {
						p.fail(a.val, path+".driver", "only the bridge driver is supported")
					}
				case "labels":
					if l, ok := p.stringMap(a.val, path+".labels", false); ok {
						nw.Labels = l
					}
				default:
					p.fail(a.kNode, path+"."+a.key, "network option %q is not supported", a.key)
				}
			}
		} else if !(d.Kind == yaml.ScalarNode && (d.Tag == "!!null" || d.Value == "")) {
			p.fail(d, path, "must be empty or a mapping")
		}
		if nw.Name != p.stack+"_"+pr.key && !nw.External {
			p.fail(pr.kNode, path+".name", "custom names are only allowed for external networks")
		}
		out = append(out, nw)
	}
	return out
}

func findVolume(proj *Project, key string) (Volume, bool) {
	for _, v := range proj.Volumes {
		if v.Key == key {
			return v, true
		}
	}
	return Volume{}, false
}

func findNetwork(proj *Project, key string) (Network, bool) {
	for _, n := range proj.Networks {
		if n.Key == key {
			return n, true
		}
	}
	return Network{}, false
}

func (p *parser) checkDependencies(proj *Project) {
	names := map[string]Service{}
	for _, s := range proj.Services {
		names[s.Name] = s
	}
	for _, s := range proj.Services {
		for _, d := range s.DependsOn {
			if _, ok := names[d]; !ok {
				p.fail(nil, "services."+s.Name+".depends_on", "unknown service %q", d)
			}
		}
	}
	if len(p.errs) == 0 {
		if _, err := Order(proj); err != nil {
			p.fail(nil, "services", "%v", err)
		}
	}
}

// Order returns the services in dependency order (dependencies first;
// otherwise document order).
func Order(proj *Project) ([]Service, error) {
	index := map[string]int{}
	for i, s := range proj.Services {
		index[s.Name] = i
	}
	const (
		unvisited = iota
		visiting
		done
	)
	state := make([]int, len(proj.Services))
	var out []Service
	var visit func(i int, chain []string) error
	visit = func(i int, chain []string) error {
		switch state[i] {
		case done:
			return nil
		case visiting:
			return fmt.Errorf("dependency cycle: %s", strings.Join(append(chain, proj.Services[i].Name), " → "))
		}
		state[i] = visiting
		deps := append([]string(nil), proj.Services[i].DependsOn...)
		sort.Strings(deps)
		for _, d := range deps {
			j, ok := index[d]
			if !ok {
				return fmt.Errorf("unknown service %q", d)
			}
			if err := visit(j, append(chain, proj.Services[i].Name)); err != nil {
				return err
			}
		}
		state[i] = done
		out = append(out, proj.Services[i])
		return nil
	}
	for i := range proj.Services {
		if err := visit(i, nil); err != nil {
			return nil, err
		}
	}
	return out, nil
}
