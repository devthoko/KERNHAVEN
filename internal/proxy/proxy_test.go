package proxy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

var settings = Settings{AdminSocket: "/run/kernhaven-caddy/admin.sock", CoreAddress: "127.0.0.1:8470", HTTPPort: 80, HTTPSPort: 443}

func TestValidHost(t *testing.T) {
	for _, h := range []string{"nas", "jellyfin.home.arpa", "a-b.c1.example", "192.168.1.20", "x.localhost"} {
		if err := ValidHost(h); err != nil {
			t.Errorf("%q: %v", h, err)
		}
	}
	for _, h := range []string{"", "Nas.lan", "*.lan", "-a.lan", "a-.lan", "a..lan", "a.lan.", "1.2.3", "192.168.001.1", "300.1.1.1",
		"::1", "a_b.lan", "a b", "a/b", "a.lan:443", strings.Repeat("a", 64) + ".lan", strings.Repeat("a.", 127) + "lan"} {
		if err := ValidHost(h); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
	if ValidKernhavenHost("::1") != nil || ValidKernhavenHost("::ffff:1.2.3.4") == nil {
		t.Error("kernhaven host: IPv6 handling")
	}
}

func TestValidPathPrefix(t *testing.T) {
	for _, p := range []string{"", "/jellyfin", "/a/b.c/d~e_f-g"} {
		if err := ValidPathPrefix(p); err != nil {
			t.Errorf("%q: %v", p, err)
		}
	}
	for _, p := range []string{"/", "jellyfin", "/a/", "//a", "/a//b", "/a/../b", "/./a", "/a b", "/a?b", "/a%2e", "/.kernhaven", "/x/.kernhaven-y", "/" + strings.Repeat("a", 128)} {
		if err := ValidPathPrefix(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestNormalizeCIDR(t *testing.T) {
	for in, want := range map[string]string{"192.168.1.7": "192.168.1.7/32", " 10.1.2.3/8 ": "10.0.0.0/8", "fd00::1/64": "fd00::/64", "::1": "::1/128"} {
		if got, err := NormalizeCIDR(in); err != nil || got != want {
			t.Errorf("%q → %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "10.0.0.0/33", "lan", "10.0.0.0/8,192.168.0.0/16"} {
		if _, err := NormalizeCIDR(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := agentproto.ProxyRoute{ID: 1, Host: "app.lan", UpstreamPort: 8080}
	cases := map[string]agentproto.ProxyApply{
		"bad kernhaven host": {KernhavenHost: "*.lan"},
		"kernhaven host":     {KernhavenHost: "app.lan", Routes: []agentproto.ProxyRoute{ok}},
		"core port":          {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "a.lan", UpstreamPort: 8470}}},
		"https port":         {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "a.lan", UpstreamPort: 443}}},
		"privileged port":    {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "a.lan", UpstreamPort: 22}}},
		"port too high":      {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "a.lan", UpstreamPort: 70000}}},
		"duplicate":          {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{ok, {ID: 2, Host: "app.lan", UpstreamPort: 8081}}},
		"duplicate id":       {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{ok, {ID: 1, Host: "b.lan", UpstreamPort: 8081}}},
		"zero id":            {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{Host: "a.lan", UpstreamPort: 8080}}},
		"strip without path": {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "a.lan", UpstreamPort: 8080, StripPrefix: true}}},
		"cidr not canonical": {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "a.lan", UpstreamPort: 8080, AllowCIDRs: []string{"10.1.2.3/8"}}}},
		"too many cidrs":     {KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "a.lan", UpstreamPort: 8080, AllowCIDRs: make([]string, 33)}}},
	}
	for name, a := range cases {
		_, err := Build(a, settings)
		var ie *InvalidError
		if !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Build(agentproto.ProxyApply{KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{ok, {ID: 2, Host: "app.lan", PathPrefix: "/x", UpstreamPort: 8081}}}, settings); err != nil {
		t.Fatal(err)
	}
}

// find walks the decoded configuration and returns every object with key == value.
func find(v any, key, value string) []map[string]any {
	var out []map[string]any
	switch x := v.(type) {
	case map[string]any:
		if s, ok := x[key].(string); ok && s == value {
			out = append(out, x)
		}
		for _, c := range x {
			out = append(out, find(c, key, value)...)
		}
	case []any:
		for _, c := range x {
			out = append(out, find(c, key, value)...)
		}
	}
	return out
}

func TestBuild(t *testing.T) {
	a := agentproto.ProxyApply{KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{
		{ID: 1, Host: "media.lan", UpstreamPort: 8096},
		{ID: 2, Host: "media.lan", PathPrefix: "/books", StripPrefix: true, UpstreamPort: 8083, SSO: true, LANOnly: true, AllowCIDRs: []string{"192.168.1.0/24"}},
	}}
	raw, err := Build(a, settings)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`"admin":{"config":{"persist":true},"listen":"unix//run/kernhaven-caddy/admin.sock","origins":["kernhaven-proxy"]}`,
		`"install_trust":false`,
		`"issuers":[{"module":"internal"}]`,
		`"listen":[":443"]`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, forbiddenHandler := range []string{"file_server", "acme", "exec"} {
		if strings.Contains(s, forbiddenHandler) {
			t.Errorf("configuration contains %s", forbiddenHandler)
		}
	}
	routes := cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["kernhaven"].(map[string]any)["routes"].([]any)
	if len(routes) != 4 {
		t.Fatalf("routes: %d", len(routes))
	}
	// Kernhaven first, its internal endpoints blocked; longer prefix before the root route; 404 last.
	first, _ := json.Marshal(routes[0])
	if !strings.Contains(string(first), `"host":["kh.lan"]`) || !strings.Contains(string(first), `"path":["/api/v1/proxy-internal/*"]`) {
		t.Errorf("kernhaven route %s", first)
	}
	second, _ := json.Marshal(routes[1])
	if !strings.Contains(string(second), `"path":["/books","/books/*"]`) {
		t.Errorf("prefix route not before root route: %s", second)
	}
	if !strings.Contains(string(second), `"strip_path_prefix":"/books"`) || !strings.Contains(string(second), `"dial":"127.0.0.1:8083"`) {
		t.Errorf("prefix route %s", second)
	}
	// Every app route deletes the identity header before anything else.
	for _, r := range routes[1:3] {
		inner := r.(map[string]any)["handle"].([]any)[0].(map[string]any)["routes"].([]any)
		b, _ := json.Marshal(inner[0])
		if string(b) != `{"handle":[{"handler":"headers","request":{"delete":["X-Kernhaven-User"]}}]}` {
			t.Errorf("first handler %s", b)
		}
	}
	// LAN-only and allow-list deny routes, gate callback and forward auth on route 2 only.
	if n := len(find(cfg, "status_code", "403")); n != 2 {
		t.Errorf("403 handlers: %d", n)
	}
	if n := len(find(cfg, "uri", AuthPath)); n != 1 {
		t.Errorf("forward auth: %d", n)
	}
	if !strings.Contains(string(second), `"path":["/books/.kernhaven/gate"]`) || !strings.Contains(string(second), `"X-Kernhaven-Route":["2"]`) {
		t.Errorf("gate %s", second)
	}
	// Upstreams are loopback only.
	for _, d := range find(cfg, "dial", "") {
		t.Errorf("empty dial %v", d)
	}
	h1, err := Hash(raw)
	if err != nil {
		t.Fatal(err)
	}
	pretty, _ := json.MarshalIndent(cfg, "", "  ")
	if h2, _ := Hash(pretty); h1 != h2 {
		t.Error("hash depends on formatting")
	}
	again, _ := Build(a, settings)
	if string(again) != string(raw) {
		t.Error("build is not deterministic")
	}
}
