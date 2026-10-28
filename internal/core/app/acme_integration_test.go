//go:build acme_integration

package app

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/core/certs"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/proxy/certtest"
)

// pebbleDNS writes the challenge into Pebble's mock DNS.
type pebbleDNS struct{ p *certtest.Pebble }

func (d pebbleDNS) Present(_ context.Context, fqdn, value string) error {
	return d.p.SetTXT(fqdn, value)
}
func (d pebbleDNS) CleanUp(_ context.Context, fqdn, _ string) error { return d.p.ClearTXT(fqdn) }

// AT-F12-01: DNS-01 with the real ACME client against Pebble, through the
// API, the issuance job and the proxy configuration.
func TestDNS01AgainstPebble(t *testing.T) {
	dir := t.TempDir()
	pb := certtest.StartPebble(t, dir, 1, 2) // DNS-01 only: no HTTP validation ports needed
	h, fake, _ := withProxyOpts(t, false, func(c *config.Config) {
		c.TLS.ACMEDirectoryForTests = pb.Directory
		c.TLS.ACMERootForTests = pb.TLSRootFile
		c.TLS.DNSPropagation = config.Duration{}
	}, func(o *Options) {
		o.TLS.Providers = func(name, creds string) (certs.DNSProvider, error) {
			if name != "cloudflare" || creds != "token" {
				t.Errorf("provider %q %q", name, creds)
			}
			return pebbleDNS{pb}, nil
		}
	})
	owner := h.setupOwner()
	h.startJobs()
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "nas.example.org", "upstream_port": 8098, "lan_only": true}).expect(201)
	owner.do("PUT", "/api/v1/tls/settings", map[string]any{"email": "admin@example.org", "agree_tos": true, "dns_provider": "cloudflare", "cloudflare_token": "token"}).expect(200)
	var res struct {
		JobID int64 `json:"job_id"`
	}
	owner.do("PUT", "/api/v1/tls/hosts/nas.example.org", map[string]any{"mode": "dns"}).expect(200).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	b := getTLS(owner)
	host := hostOf(t, b, "nas.example.org")
	if host.Effective != certs.ModeDNS {
		t.Fatalf("host %+v", host)
	}
	var chain string
	if err := h.db.QueryRow(`SELECT chain_pem FROM tls_certificates WHERE id = ?`, host.CertificateID).Scan(&chain); err != nil {
		t.Fatal(err)
	}
	blk, rest := pem.Decode([]byte(chain))
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	inter := x509.NewCertPool()
	inter.AppendCertsFromPEM(rest)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "nas.example.org", Roots: pb.Issuing, Intermediates: inter}); err != nil {
		t.Fatalf("not issued by Pebble: %v", err)
	}
	if cfg, _ := fake.state(); !containsAll(cfg, `"match":{"sni":["nas.example.org"]}`, "kh-cert-") {
		t.Fatal("certificate not applied")
	}
}

func containsAll(s string, subs ...string) bool {
	for _, x := range subs {
		if !strings.Contains(s, x) {
			return false
		}
	}
	return true
}
