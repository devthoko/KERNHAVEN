// Package proxy validates reverse proxy routes and builds the complete Caddy
// configuration from them (M12, ADR-0025). The Core uses the validation; the
// proxy service uses both, so Caddy only ever receives configurations of the
// shape built here, whatever the Core sends.
package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/mail"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Limits and fixed names shared by the Core, the proxy service and Caddy.
const (
	MaxRoutes       = 200
	MaxAllowCIDRs   = 32
	MaxPathPrefix   = 128
	MinUpstreamPort = 1024
	MaxUpstreamPort = 65535

	// GatePath (below the route's prefix) is where the browser returns with
	// a one-time code; Caddy forwards it to the Core's callback.
	GatePath = "/.kernhaven/gate"
	// InternalPrefix holds the endpoints only Caddy may call.
	InternalPrefix = "/api/v1/proxy-internal/"
	AuthPath       = InternalPrefix + "auth"
	CallbackPath   = InternalPrefix + "callback"

	// UserHeader carries the signed-in user to gated apps; RouteHeader tells
	// the Core which route Caddy is asking about.
	UserHeader  = "X-Kernhaven-User"
	RouteHeader = "X-Kernhaven-Route"

	// AdminHost is the only Host header Caddy's admin API accepts.
	AdminHost = "kernhaven-proxy"
)

// LANRanges are the client networks a "LAN only" route accepts.
var LANRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

// InvalidError reports a route or setting that is not allowed.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{fmt.Sprintf(format, a...)} }

var (
	labelRE   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	segmentRE = regexp.MustCompile(`^[A-Za-z0-9._~-]+$`)
	digitsRE  = regexp.MustCompile(`^[0-9]+$`)
)

// ValidHost accepts lower-case DNS names and IPv4 addresses in canonical form.
func ValidHost(h string) error {
	if h == "" || len(h) > 253 {
		return invalid("host must be 1 to 253 characters")
	}
	labels := strings.Split(h, ".")
	if digitsRE.MatchString(labels[len(labels)-1]) {
		if a, err := netip.ParseAddr(h); err != nil || !a.Is4() || a.String() != h {
			return invalid("host %q is neither a host name nor an IPv4 address", h)
		}
		return nil
	}
	for _, l := range labels {
		if !labelRE.MatchString(l) {
			return invalid("host %q is not a valid lower-case host name (letters, digits and hyphens per label, no wildcards)", h)
		}
	}
	return nil
}

// ValidKernhavenHost also accepts IPv6 addresses (the Core's own origin).
func ValidKernhavenHost(h string) error {
	if a, err := netip.ParseAddr(h); err == nil && a.Is6() && a.String() == h && !a.Is4In6() {
		return nil
	}
	return ValidHost(h)
}

// ValidPathPrefix accepts "" or "/segment[/segment…]".
func ValidPathPrefix(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > MaxPathPrefix || !strings.HasPrefix(p, "/") {
		return invalid("path prefix must start with / and have at most %d characters", MaxPathPrefix)
	}
	for _, seg := range strings.Split(p[1:], "/") {
		switch {
		case !segmentRE.MatchString(seg):
			return invalid("path prefix %q: segments may contain letters, digits and . _ ~ - only, without empty segments or a trailing slash", p)
		case seg == "." || seg == "..":
			return invalid("path prefix %q must not contain . or .. segments", p)
		case strings.HasPrefix(seg, ".kernhaven"):
			return invalid("path prefix %q: .kernhaven is reserved", p)
		}
	}
	return nil
}

// NormalizeCIDR turns an address or prefix into its canonical prefix form.
func NormalizeCIDR(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return "", invalid("%q is not an IP address or CIDR range", s)
		}
		return netip.PrefixFrom(a, a.BitLen()).String(), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return "", invalid("%q is not an IP address or CIDR range", s)
	}
	return p.Masked().String(), nil
}

// ValidateRoute checks the rules that do not depend on the proxy service's
// settings. Hosts and CIDRs must already be normalized.
func ValidateRoute(r agentproto.ProxyRoute) error {
	if r.ID <= 0 {
		return invalid("route id must be positive")
	}
	if err := ValidHost(r.Host); err != nil {
		return err
	}
	if err := ValidPathPrefix(r.PathPrefix); err != nil {
		return err
	}
	if r.StripPrefix && r.PathPrefix == "" {
		return invalid("strip prefix needs a path prefix")
	}
	if r.UpstreamPort < MinUpstreamPort || r.UpstreamPort > MaxUpstreamPort {
		return invalid("upstream port must be %d to %d", MinUpstreamPort, MaxUpstreamPort)
	}
	if len(r.AllowCIDRs) > MaxAllowCIDRs {
		return invalid("at most %d allowed networks", MaxAllowCIDRs)
	}
	for _, c := range r.AllowCIDRs {
		n, err := NormalizeCIDR(c)
		if err != nil {
			return err
		}
		if n != c {
			return invalid("allowed network %q is not in canonical form (%s)", c, n)
		}
	}
	return nil
}

// Settings are the proxy service's fixed parameters (proxy.toml).
type Settings struct {
	AdminSocket string // absolute path of Caddy's admin socket
	CoreAddress string // loopback host:port of the Core
	HTTPPort    int
	HTTPSPort   int
	// ACMECA replaces Let's Encrypt's directories and ACMECARoot is a PEM
	// file Caddy trusts for it — only for tests against Pebble (M13).
	ACMECA     string
	ACMECARoot string
}

// ACMEDirectories are the CAs the Core may choose (ADR-0026).
var ACMEDirectories = map[string]string{
	agentproto.ACMEProduction: "https://acme-v02.api.letsencrypt.org/directory",
	agentproto.ACMEStaging:    "https://acme-staging-v02.api.letsencrypt.org/directory",
}

// ACMEDirectory returns the directory URL for ca.
func (s Settings) ACMEDirectory(ca string) string {
	if s.ACMECA != "" {
		return s.ACMECA
	}
	return ACMEDirectories[ca]
}

// ValidEmail is a plain check of an ACME contact address.
func ValidEmail(e string) bool {
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e && a.Name == "" && len(e) <= 254 && strings.Count(e, "@") == 1
}

// CorePort returns the port of the Core address.
func (s Settings) CorePort() int {
	_, p, _ := net.SplitHostPort(s.CoreAddress)
	n, _ := strconv.Atoi(p)
	return n
}

// Validate checks a complete route set against the settings.
func Validate(a agentproto.ProxyApply, s Settings) error {
	_, err := validate(a, s)
	return err
}

func validate(a agentproto.ProxyApply, s Settings) (map[int64]KeyPair, error) {
	if err := validateRoutes(a, s); err != nil {
		return nil, err
	}
	return validateTLS(a)
}

// validateTLS checks the TLS part (M13): known hosts, one entry per host,
// ACME only for public DNS names, certificates that parse, match their key
// and cover their host.
func validateTLS(a agentproto.ProxyApply) (map[int64]KeyPair, error) {
	hosts := map[string]bool{a.KernhavenHost: true}
	lan := map[string]bool{}
	for _, r := range a.Routes {
		hosts[r.Host] = true
		lan[r.Host] = lan[r.Host] || r.LANOnly
	}
	if len(a.Certificates) > MaxCertificates {
		return nil, invalid("at most %d certificates", MaxCertificates)
	}
	certs := map[int64]KeyPair{}
	for _, c := range a.Certificates {
		if c.ID <= 0 || certs[c.ID].Leaf != nil {
			return nil, invalid("certificate ids must be positive and unique")
		}
		kp, err := ParseKeyPair(c.CertificatePEM, c.KeyPEM)
		if err != nil {
			return nil, invalid("certificate %d: %v", c.ID, err)
		}
		certs[c.ID] = kp
	}
	if a.ACME != nil {
		if !ValidEmail(a.ACME.Email) {
			return nil, invalid("ACME e-mail %q is not valid", a.ACME.Email)
		}
		if _, ok := ACMEDirectories[a.ACME.CA]; !ok {
			return nil, invalid("ACME CA must be production or staging")
		}
	}
	seen := map[string]bool{}
	for _, t := range a.TLSHosts {
		if !hosts[t.Host] {
			return nil, invalid("TLS settings for %q, which has no route", t.Host)
		}
		if seen[t.Host] {
			return nil, invalid("duplicate TLS settings for %q", t.Host)
		}
		seen[t.Host] = true
		switch t.Mode {
		case agentproto.TLSInternal:
		case agentproto.TLSACME:
			if _, err := netip.ParseAddr(t.Host); err == nil || t.Host == "localhost" || strings.HasSuffix(t.Host, ".localhost") {
				return nil, invalid("%s: ACME needs a public host name", t.Host)
			}
			if lan[t.Host] {
				return nil, invalid("%s has a LAN-only route; HTTP-01 needs the host to be reachable from the internet (use DNS-01 or the internal CA)", t.Host)
			}
			if a.ACME == nil {
				return nil, invalid("%s: ACME settings are missing", t.Host)
			}
		case agentproto.TLSLoaded:
			kp, ok := certs[t.CertificateID]
			if !ok {
				return nil, invalid("%s: certificate %d is missing", t.Host, t.CertificateID)
			}
			if !Covers(kp.Leaf, t.Host) {
				return nil, invalid("%s: certificate %d does not cover this host", t.Host, t.CertificateID)
			}
		default:
			return nil, invalid("%s: unknown TLS mode %q", t.Host, t.Mode)
		}
	}
	return certs, nil
}

func validateRoutes(a agentproto.ProxyApply, s Settings) error {
	if err := ValidKernhavenHost(a.KernhavenHost); err != nil {
		return invalid("kernhaven host: %v", err)
	}
	if len(a.Routes) > MaxRoutes {
		return invalid("at most %d routes", MaxRoutes)
	}
	ids := map[int64]bool{}
	keys := map[string]bool{}
	for _, r := range a.Routes {
		if err := ValidateRoute(r); err != nil {
			return err
		}
		if r.Host == a.KernhavenHost {
			return invalid("host %q is the Kernhaven host", r.Host)
		}
		if r.UpstreamPort == s.CorePort() || r.UpstreamPort == s.HTTPPort || r.UpstreamPort == s.HTTPSPort {
			return invalid("upstream port %d belongs to Kernhaven or Caddy", r.UpstreamPort)
		}
		key := r.Host + r.PathPrefix
		if ids[r.ID] || keys[key] {
			return invalid("duplicate route %d (%s)", r.ID, key)
		}
		ids[r.ID], keys[key] = true, true
	}
	return nil
}

// obj is a JSON object; json.Marshal sorts its keys, so the output is canonical.
type obj = map[string]any

// Build validates a and returns the complete Caddy JSON configuration.
func Build(a agentproto.ProxyApply, s Settings) ([]byte, error) {
	if _, err := validate(a, s); err != nil {
		return nil, err
	}
	core := []any{obj{"dial": s.CoreAddress}}
	routes := []any{obj{
		"match": []any{obj{"host": []any{a.KernhavenHost}}},
		"handle": []any{obj{"handler": "subroute", "routes": []any{
			obj{"match": []any{obj{"path": []any{InternalPrefix + "*"}}}, "handle": []any{notFound()}, "terminal": true},
			obj{"handle": []any{obj{"handler": "reverse_proxy", "upstreams": core}}},
		}}},
		"terminal": true,
	}}
	sorted := append([]agentproto.ProxyRoute(nil), a.Routes...)
	sort.Slice(sorted, func(i, j int) bool {
		x, y := sorted[i], sorted[j]
		if len(x.PathPrefix) != len(y.PathPrefix) {
			return len(x.PathPrefix) > len(y.PathPrefix)
		}
		return x.Host+x.PathPrefix < y.Host+y.PathPrefix
	})
	for _, r := range sorted {
		routes = append(routes, route(r, core))
	}
	routes = append(routes, obj{"handle": []any{notFound()}})
	server := obj{"listen": []any{":" + strconv.Itoa(s.HTTPSPort)}, "routes": routes}
	tlsApp := obj{}
	var acmeHosts, certHosts, connPolicies, loaded []any
	used := map[int64]bool{}
	for _, t := range sortedTLS(a.TLSHosts) {
		switch t.Mode {
		case agentproto.TLSACME:
			acmeHosts = append(acmeHosts, t.Host)
		case agentproto.TLSLoaded:
			certHosts = append(certHosts, t.Host)
			tag := "kh-cert-" + strconv.FormatInt(t.CertificateID, 10)
			// Exactly this certificate for this host, whatever else is cached.
			connPolicies = append(connPolicies, obj{"match": obj{"sni": []any{t.Host}}, "certificate_selection": obj{"any_tag": []any{tag}}})
			if !used[t.CertificateID] {
				used[t.CertificateID] = true
				for _, c := range a.Certificates {
					if c.ID == t.CertificateID {
						loaded = append(loaded, obj{"certificate": c.CertificatePEM, "key": c.KeyPEM, "tags": []any{tag}})
					}
				}
			}
		}
	}
	if len(certHosts) > 0 {
		server["automatic_https"] = obj{"skip_certificates": certHosts}
		server["tls_connection_policies"] = append(connPolicies, obj{})
		tlsApp["certificates"] = obj{"load_pem": loaded}
	}
	// The local CA for every host without another issuer; never installed
	// into the host's trust store.
	policies := []any{obj{"issuers": []any{obj{"module": "internal"}}}}
	if len(acmeHosts) > 0 {
		issuer := obj{"module": "acme", "ca": s.ACMEDirectory(a.ACME.CA), "email": a.ACME.Email}
		if s.ACMECARoot != "" {
			issuer["trusted_roots_pem_files"] = []any{s.ACMECARoot}
		}
		policies = append([]any{obj{"subjects": acmeHosts, "issuers": []any{issuer}}}, policies...)
	}
	tlsApp["automation"] = obj{"policies": policies}
	cfg := obj{
		// The admin API stays on the unix socket whatever is loaded.
		"admin": obj{"listen": "unix/" + s.AdminSocket, "origins": []any{AdminHost}, "config": obj{"persist": true}},
		"apps": obj{
			"http": obj{
				"http_port":  s.HTTPPort,
				"https_port": s.HTTPSPort,
				"servers":    obj{"kernhaven": server},
			},
			"tls": tlsApp,
			"pki": obj{"certificate_authorities": obj{"local": obj{"install_trust": false}}},
		},
	}
	return json.Marshal(cfg)
}

func sortedTLS(in []agentproto.TLSHost) []agentproto.TLSHost {
	out := append([]agentproto.TLSHost(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

func notFound() obj {
	return obj{"handler": "static_response", "status_code": "404", "body": "Not found"}
}

func forbidden(ranges []string) obj {
	rs := make([]any, len(ranges))
	for i, r := range ranges {
		rs[i] = r
	}
	return obj{
		"match":    []any{obj{"not": []any{obj{"remote_ip": obj{"ranges": rs}}}}},
		"handle":   []any{obj{"handler": "static_response", "status_code": "403", "body": "Forbidden"}},
		"terminal": true,
	}
}

func route(r agentproto.ProxyRoute, core []any) obj {
	id := strconv.FormatInt(r.ID, 10)
	match := obj{"host": []any{r.Host}}
	if r.PathPrefix != "" {
		match["path"] = []any{r.PathPrefix, r.PathPrefix + "/*"}
	}
	// Client-supplied identity headers never reach an app (TH-41).
	inner := []any{obj{"handle": []any{obj{"handler": "headers", "request": obj{"delete": []any{UserHeader}}}}}}
	if r.LANOnly {
		inner = append(inner, forbidden(LANRanges))
	}
	if len(r.AllowCIDRs) > 0 {
		inner = append(inner, forbidden(r.AllowCIDRs))
	}
	if r.SSO {
		inner = append(inner,
			obj{
				"match": []any{obj{"path": []any{r.PathPrefix + GatePath}}},
				"handle": []any{
					obj{"handler": "rewrite", "uri": CallbackPath + "?{http.request.uri.query}"},
					obj{"handler": "reverse_proxy", "upstreams": core, "headers": obj{"request": obj{"set": obj{RouteHeader: []any{id}}}}},
				},
				"terminal": true,
			},
			// forward_auth as Caddy 2.6.2 adapts it.
			obj{"handle": []any{obj{
				"handler":   "reverse_proxy",
				"upstreams": core,
				"rewrite":   obj{"method": "GET", "uri": AuthPath},
				"headers": obj{"request": obj{"set": obj{
					"X-Forwarded-Method": []any{"{http.request.method}"},
					"X-Forwarded-Uri":    []any{"{http.request.uri}"},
					RouteHeader:          []any{id},
				}}},
				"handle_response": []any{obj{
					"match": obj{"status_code": []any{2}},
					"routes": []any{obj{"handle": []any{obj{"handler": "headers", "request": obj{"set": obj{
						UserHeader: []any{"{http.reverse_proxy.header." + UserHeader + "}"},
					}}}}}},
				}},
			}}},
		)
	}
	last := []any{}
	if r.StripPrefix {
		last = append(last, obj{"handler": "rewrite", "strip_path_prefix": r.PathPrefix})
	}
	last = append(last, obj{"handler": "reverse_proxy", "upstreams": []any{obj{"dial": "127.0.0.1:" + strconv.Itoa(r.UpstreamPort)}}})
	inner = append(inner, obj{"handle": last})
	return obj{"match": []any{match}, "handle": []any{obj{"handler": "subroute", "routes": inner}}, "terminal": true}
}

// Hash returns the SHA-256 of the canonical form of a JSON configuration, so
// a configuration read back from Caddy compares equal to the one built.
func Hash(cfg []byte) (string, error) {
	var v any
	if err := json.Unmarshal(cfg, &v); err != nil {
		return "", err
	}
	canon, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), nil
}
