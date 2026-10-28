package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/certs"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/proxy/certtest"
)

// fakeIssuer stands in for ACME DNS-01 (the real flow runs against Pebble in
// the acme_integration test).
type fakeIssuer struct {
	t     *testing.T
	ca    *certtest.CA
	now   func() time.Time
	mu    sync.Mutex
	err   error
	hosts []string
}

func (f *fakeIssuer) Issue(_ context.Context, host string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts = append(f.hosts, host)
	if f.err != nil {
		return "", "", f.err
	}
	now := f.now()
	cert, key := f.ca.Issue(f.t, certtest.Leaf{Names: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour)})
	return cert + f.ca.PEM, key, nil
}

type tlsBody struct {
	Hosts        []certs.HostTLS
	Certificates []certs.Certificate
	Settings     certs.Settings
	RootSHA256   string `json:"root_sha256"`
}

func hostOf(t *testing.T, b tlsBody, host string) certs.HostTLS {
	t.Helper()
	for _, h := range b.Hosts {
		if h.Host.Host == host {
			return h
		}
	}
	t.Fatalf("host %s missing in %+v", host, b.Hosts)
	return certs.HostTLS{}
}

func getTLS(c *client) tlsBody {
	var b tlsBody
	c.do("GET", "/api/v1/tls", nil).expect(200).json(&b)
	return b
}

// AT-F12-01..03 in the Core: modes per host, uploads, DNS-01 issuance and
// renewal, everything applied to Caddy before it is stored.
func TestTLS(t *testing.T) {
	issuer := &fakeIssuer{t: t, ca: certtest.NewCA(t, "Fake ACME CA", nil)}
	own := certtest.NewCA(t, "Own Root", nil)
	h, fake, _ := withProxyOpts(t, false, nil, func(o *Options) { o.TLS.Issuer = issuer })
	issuer.now = h.clock.Now
	owner := h.setupOwner()
	h.startJobs()
	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer1", authz.Viewer)
	op, viewer := h.loginAs("operator1"), h.loginAs("viewer1")
	for _, r := range []map[string]any{
		{"host": "media.lan", "upstream_port": 8096, "lan_only": true},
		{"host": "public.example.org", "upstream_port": 8097},
		{"host": "home.example.org", "upstream_port": 8098, "lan_only": true},
		{"host": "192.168.1.9", "upstream_port": 8099},
	} {
		owner.do("POST", "/api/v1/network/routes", r).expect(201)
	}

	// Reading and the root download.
	viewer.do("GET", "/api/v1/tls", nil).expect(403)
	b := getTLS(op)
	if len(b.Hosts) != 5 || !hostOf(t, b, "kernhaven.test").Kernhaven || hostOf(t, b, "media.lan").Effective != certs.ModeInternal || len(b.RootSHA256) != 64 {
		t.Fatalf("overview %+v", b)
	}
	r := viewer.do("GET", "/api/v1/tls/root.crt", nil).expect(200)
	if !strings.HasPrefix(r.Body.String(), "-----BEGIN CERTIFICATE-----") || !strings.Contains(r.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("root download %v %q", r.Header(), r.Body.String()[:40])
	}
	op.do("PUT", "/api/v1/tls/hosts/media.lan", map[string]any{"mode": "internal"}).expect(403)

	// AT-F12-03: uploads are validated; the key never leaves the Core except to the proxy.
	now := h.clock.Now()
	certPEM, keyPEM := own.Issue(t, certtest.Leaf{Names: []string{"media.lan", "*.media.lan"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour)})
	_, otherKey := own.Issue(t, certtest.Leaf{Names: []string{"media.lan"}, NotBefore: now.Add(-time.Hour)})
	for name, body := range map[string]map[string]string{
		"key mismatch":  {"certificate_pem": certPEM + own.PEM, "key_pem": otherKey},
		"no chain root": {"certificate_pem": certPEM, "key_pem": keyPEM},
		"not PEM":       {"certificate_pem": "hello", "key_pem": keyPEM},
	} {
		if r := owner.do("POST", "/api/v1/tls/certificates", body); r.Code != 422 {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	var up certs.Certificate
	r = owner.do("POST", "/api/v1/tls/certificates", map[string]string{"certificate_pem": certPEM + own.PEM, "key_pem": keyPEM}).expect(201)
	r.json(&up)
	if strings.Contains(r.Body.String(), "PRIVATE KEY") || up.Source != "upload" || len(up.SHA256) != 64 || up.Names[0] != "media.lan" {
		t.Fatalf("upload %s", r.Body)
	}
	var stored []byte
	if err := h.db.QueryRow(`SELECT key FROM tls_certificates WHERE id = ?`, up.ID).Scan(&stored); err != nil || strings.Contains(string(stored), "PRIVATE") {
		t.Fatalf("key stored in clear: %v", err)
	}
	if auditCount(t, h, "tls.certificate_upload", "failure") != 3 || auditCount(t, h, "tls.certificate_upload", "success") != 1 {
		t.Fatal("uploads not audited")
	}

	// Assigning: only to hosts it covers; Caddy gets exactly this certificate.
	owner.do("PUT", "/api/v1/tls/hosts/public.example.org", map[string]any{"mode": "custom", "certificate_id": up.ID}).expect(422)
	owner.do("PUT", "/api/v1/tls/hosts/media.lan", map[string]any{"mode": "custom", "certificate_id": up.ID}).expect(200)
	cfg, _ := fake.state()
	if !strings.Contains(cfg, `"match":{"sni":["media.lan"]}`) || !strings.Contains(cfg, `"tags":["kh-cert-`+itoa(up.ID)+`"]`) || !strings.Contains(cfg, "BEGIN PRIVATE KEY") {
		t.Fatalf("custom certificate not in caddy config")
	}
	if hostOf(t, getTLS(owner), "media.lan").Effective != certs.ModeCustom {
		t.Fatal("not effective")
	}
	owner.do("DELETE", "/api/v1/tls/certificates/"+itoa(up.ID), nil).expect(409)

	// Caddy refuses: nothing changes.
	fake.set("loading config: tls: certificate rejected")
	if r := owner.do("PUT", "/api/v1/tls/hosts/media.lan", map[string]any{"mode": "internal"}); r.Code != 422 || r.errorCode() != "proxy_rejected" {
		t.Fatalf("refused change: %d %s", r.Code, r.Body)
	}
	fake.set("")
	if hostOf(t, getTLS(owner), "media.lan").Mode != certs.ModeCustom {
		t.Fatal("mode changed although Caddy refused")
	}

	// AT-F12-01, HTTP-01: needs the agreement, a public name and no LAN-only route.
	owner.do("PUT", "/api/v1/tls/hosts/public.example.org", map[string]any{"mode": "acme"}).expect(422)
	for name, body := range map[string]map[string]any{
		"bad email":  {"email": "Admin <a@b.c>", "agree_tos": true},
		"foreign CA": {"email": "a@example.org", "ca": "https://evil.example/dir", "agree_tos": true},
		"provider":   {"email": "a@example.org", "agree_tos": true, "dns_provider": "route53"},
	} {
		if r := owner.do("PUT", "/api/v1/tls/settings", body); r.Code != 422 {
			t.Errorf("%s: %d", name, r.Code)
		}
	}
	var st certs.Settings
	r = owner.do("PUT", "/api/v1/tls/settings", map[string]any{"email": "admin@example.org", "agree_tos": true, "ca": "staging",
		"dns_provider": "cloudflare", "cloudflare_token": "cf-secret-token"}).expect(200)
	r.json(&st)
	if st.AgreedAt.IsZero() || !st.DNSConfigured || strings.Contains(r.Body.String(), "cf-secret-token") {
		t.Fatalf("settings %s", r.Body)
	}
	if err := h.db.QueryRow(`SELECT dns_credentials FROM tls_settings`).Scan(&stored); err != nil || strings.Contains(string(stored), "cf-secret") {
		t.Fatalf("token stored in clear: %v", err)
	}
	owner.do("PUT", "/api/v1/tls/hosts/home.example.org", map[string]any{"mode": "acme"}).expect(422) // LAN-only
	owner.do("PUT", "/api/v1/tls/hosts/192.168.1.9", map[string]any{"mode": "acme"}).expect(422)
	owner.do("PUT", "/api/v1/tls/hosts/public.example.org", map[string]any{"mode": "acme"}).expect(200)
	if cfg, _ := fake.state(); !strings.Contains(cfg, `"subjects":["public.example.org"]`) || !strings.Contains(cfg, "acme-staging-v02.api.letsencrypt.org") {
		t.Fatalf("acme issuer missing: %s", cfg)
	}
	owner.do("PUT", "/api/v1/tls/settings", map[string]any{"email": "", "agree_tos": false}).expect(422) // hosts use ACME

	// AT-F12-01, DNS-01: a LAN-only host with a public name gets its certificate from the Core.
	var res struct {
		Host  certs.HostTLS
		JobID int64 `json:"job_id"`
	}
	owner.do("PUT", "/api/v1/tls/hosts/home.example.org", map[string]any{"mode": "dns"}).expect(200).json(&res)
	if res.JobID == 0 || res.Host.Effective != certs.ModeInternal {
		t.Fatalf("dns mode %+v", res)
	}
	h.waitJob(res.JobID, jobs.Succeeded)
	b = getTLS(owner)
	home := hostOf(t, b, "home.example.org")
	if home.Effective != certs.ModeDNS || home.CertificateID == 0 {
		t.Fatalf("dns host %+v", home)
	}
	if cfg, _ := fake.state(); !strings.Contains(cfg, `"match":{"sni":["home.example.org"]}`) {
		t.Fatal("DNS-01 certificate not in caddy config")
	}
	owner.do("PUT", "/api/v1/tls/hosts/media.lan", map[string]any{"mode": "dns"}).expect(422) // not a public name

	// A failing CA is recorded on the host and audited.
	issuer.mu.Lock()
	issuer.err = errors.New("acme: urn:ietf:params:acme:error:dns: NXDOMAIN")
	issuer.mu.Unlock()
	owner.do("POST", "/api/v1/tls/hosts/home.example.org/renew", nil).expect(202)
	deadline := time.Now().Add(10 * time.Second)
	for hostOf(t, getTLS(owner), "home.example.org").Error == "" {
		if time.Now().After(deadline) {
			t.Fatal("failure not recorded")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if hostOf(t, getTLS(owner), "home.example.org").CertificateID != home.CertificateID || auditCount(t, h, "tls.issue", "failure") < 1 {
		t.Fatal("failed renewal replaced the certificate or was not audited")
	}
	owner.do("POST", "/api/v1/tls/hosts/media.lan/renew", nil).expect(422)

	// Changing modes, uploads and settings needs step-up (AT-F09-04).
	h.clock.Advance(11 * time.Minute)
	for _, c := range []struct{ method, path string }{{"PUT", "/api/v1/tls/settings"}, {"PUT", "/api/v1/tls/hosts/media.lan"}, {"POST", "/api/v1/tls/certificates"}, {"DELETE", "/api/v1/tls/certificates/" + itoa(up.ID)}} {
		if r := owner.do(c.method, c.path, map[string]any{}); r.errorCode() != "step_up_required" && r.Code != 400 {
			t.Errorf("%s %s: %d %s", c.method, c.path, r.Code, r.Body)
		}
	}

	// Deleting the last route of a host drops its TLS settings from Caddy.
	var rb routesBody
	owner = h.loginAs("owner")
	owner.do("GET", "/api/v1/network/routes", nil).expect(200).json(&rb)
	for _, x := range rb.Routes {
		if x.Host == "public.example.org" {
			owner.do("DELETE", "/api/v1/network/routes/"+itoa(x.ID), nil).expect(204)
		}
	}
	if cfg, _ := fake.state(); strings.Contains(cfg, "public.example.org") {
		t.Fatal("deleted host still in caddy config")
	}
}

// Renewal 30 days before expiry replaces the DNS-01 certificate.
func TestTLSRenewal(t *testing.T) {
	issuer := &fakeIssuer{t: t, ca: certtest.NewCA(t, "Fake ACME CA", nil)}
	h, _, _ := withProxyOpts(t, false, nil, func(o *Options) { o.TLS.Issuer = issuer })
	issuer.now = h.clock.Now
	owner := h.setupOwner()
	h.startJobs()
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "home.example.org", "upstream_port": 8098}).expect(201)
	owner.do("PUT", "/api/v1/tls/settings", map[string]any{"email": "admin@example.org", "agree_tos": true, "dns_provider": "cloudflare", "cloudflare_token": "t"}).expect(200)
	var res struct {
		JobID int64 `json:"job_id"`
	}
	owner.do("PUT", "/api/v1/tls/hosts/home.example.org", map[string]any{"mode": "dns"}).expect(200).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	first := hostOf(t, getTLS(owner), "home.example.org").CertificateID

	ctx := context.Background()
	if n, err := h.app.Certs.EnqueueRenewals(ctx); err != nil || n != 0 {
		t.Fatalf("fresh certificate renewed: %d %v", n, err)
	}
	h.clock.Advance(61 * 24 * time.Hour) // 90-day certificate: 29 days left
	n, err := h.app.Certs.EnqueueRenewals(ctx)
	if err != nil || n != 1 {
		t.Fatalf("renewals %d %v", n, err)
	}
	h.app.Runner.Wake()
	deadline := time.Now().Add(10 * time.Second)
	var id int64
	for {
		_ = h.db.QueryRow(`SELECT certificate_id FROM tls_hosts WHERE host = 'home.example.org'`).Scan(&id)
		if id != first || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	var left int
	_ = h.db.QueryRow(`SELECT count(*) FROM tls_certificates`).Scan(&left)
	if id == first || left != 1 {
		t.Fatalf("not renewed: %d → %d, %d certificates", first, id, left)
	}
}
