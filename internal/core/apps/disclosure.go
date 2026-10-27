package apps

import (
	"fmt"
	"sort"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/catalog"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// ServiceDisclosure lists what one service of an app may do.
type ServiceDisclosure struct {
	Service      string              `json:"service"`
	Image        string              `json:"image"`
	ImagePinned  bool                `json:"image_pinned"`
	User         string              `json:"user"`
	Ports        []string            `json:"ports"`
	BindMounts   []string            `json:"bind_mounts"`
	Volumes      []string            `json:"volumes"`
	Capabilities []string            `json:"capabilities"`
	Devices      []string            `json:"devices"`
	Privileged   bool                `json:"privileged"`
	HostNetwork  bool                `json:"host_network"`
	Violations   []policy.Finding    `json:"violations"`
	Warnings     []policy.Finding    `json:"warnings"`
	Exceptions   []catalog.Exception `json:"exceptions"`
}

// Disclosure is computed by Kernhaven from the Compose file, not taken from
// the catalog's description (AT-F04-04).
type Disclosure struct {
	Services []ServiceDisclosure `json:"services"`
	// Installable is false when a violation has no declared exception or the
	// Compose file does not render with the given values.
	Installable bool `json:"installable"`
	// NeedsApproval is true when declared exceptions are needed on this host;
	// only owners can approve them.
	NeedsApproval bool     `json:"needs_approval"`
	Problems      []string `json:"problems"`
}

// Exceptions returns the declared exceptions that are needed on this host.
func (d Disclosure) Exceptions() []catalog.Exception {
	var out []catalog.Exception
	for _, s := range d.Services {
		out = append(out, s.Exceptions...)
	}
	return out
}

func (s *Service) disclose(name string, app catalog.App, values map[string]string) Disclosure {
	d := Disclosure{Services: []ServiceDisclosure{}, Problems: []string{}, Installable: true}
	proj, err := s.stacks.Project(name, app.Compose, values)
	if err != nil {
		d.Installable = false
		d.Problems = append(d.Problems, err.Error())
		return d
	}
	declared := map[string]catalog.Exception{}
	for _, e := range app.Exceptions {
		declared[e.Service+"/"+e.Rule] = e
	}
	for _, svc := range proj.Services {
		sp := svc.Spec
		sd := ServiceDisclosure{Service: svc.Name, Image: sp.Image, ImagePinned: strings.Contains(sp.Image, "@sha256:"), User: sp.User,
			Ports: []string{}, BindMounts: []string{}, Volumes: []string{}, Capabilities: orEmpty(sp.CapAdd), Devices: orEmpty(sp.Devices),
			Privileged: sp.Privileged, HostNetwork: sp.NetworkMode == "host", Exceptions: []catalog.Exception{}}
		for _, p := range sp.Ports {
			host := p.HostIP
			if host == "" {
				host = "all interfaces"
			}
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}
			sd.Ports = append(sd.Ports, fmt.Sprintf("%s:%d → %d/%s", host, p.HostPort, p.ContainerPort, proto))
		}
		for _, m := range sp.Mounts {
			ro := ""
			if m.ReadOnly {
				ro = " (read-only)"
			}
			switch m.Type {
			case "bind":
				sd.BindMounts = append(sd.BindMounts, m.Source+" → "+m.Target+ro)
			case "volume":
				sd.Volumes = append(sd.Volumes, m.Source+" → "+m.Target+ro)
			}
		}
		res := policy.Evaluate(sp, policy.Options{AllowedBindRoots: s.stacks.BindRoots()})
		sd.Violations, sd.Warnings = orFindings(res.Violations), orFindings(res.Warnings)
		needed := map[string]bool{}
		for _, v := range res.Violations {
			e, ok := declared[svc.Name+"/"+v.Rule]
			switch {
			case ok && v.Exemptible:
				if !needed[v.Rule] {
					needed[v.Rule] = true
					sd.Exceptions = append(sd.Exceptions, e)
				}
			case !v.Exemptible:
				d.Installable = false
				d.Problems = append(d.Problems, fmt.Sprintf("service %s: %s (never allowed)", svc.Name, v.Message))
			default:
				d.Installable = false
				d.Problems = append(d.Problems, fmt.Sprintf("service %s: %s (the catalog declares no exception)", svc.Name, v.Message))
			}
		}
		sort.Slice(sd.Exceptions, func(i, j int) bool { return sd.Exceptions[i].Rule < sd.Exceptions[j].Rule })
		if len(sd.Exceptions) > 0 {
			d.NeedsApproval = true
		}
		d.Services = append(d.Services, sd)
	}
	return d
}

func orFindings(f []policy.Finding) []policy.Finding {
	if f == nil {
		return []policy.Finding{}
	}
	return f
}
