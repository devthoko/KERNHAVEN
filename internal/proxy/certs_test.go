package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/proxy/certtest"
)

func isInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

func TestParseKeyPair(t *testing.T) {
	ca := certtest.NewCA(t, "Root", nil)
	cert, key := ca.Issue(t, certtest.Leaf{Names: []string{"app.lan"}})
	other, otherKey := ca.Issue(t, certtest.Leaf{Names: []string{"other.lan"}})
	kp, err := ParseKeyPair(cert+ca.PEM, key)
	if err != nil || len(kp.Chain) != 2 || !Covers(kp.Leaf, "app.lan") || Covers(kp.Leaf, "other.lan") {
		t.Fatalf("valid pair: %v", err)
	}
	if info := kp.Info(); info.Names[0] != "app.lan" || len(info.SHA256) != 64 || !strings.Contains(info.Issuer, "Root") {
		t.Fatalf("info %+v", info)
	}
	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	weakPEM := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}))
	for name, c := range map[string][2]string{
		"key of another certificate": {cert, otherKey},
		"empty certificate":          {"", key},
		"key in certificate file":    {cert + key, key},
		"trailing junk":              {cert + "junk", key},
		"two keys":                   {cert, key + otherKey},
		"encrypted key":              {cert, string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{0}}))},
		"weak RSA key":               {cert, weakPEM},
		"oversized":                  {strings.Repeat("a", MaxPEMBytes+1), key},
		"too long chain":             {cert + strings.Repeat(ca.PEM, MaxChainCerts), key},
	} {
		if _, err := ParseKeyPair(c[0], c[1]); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	_ = other
	wild, wkey := ca.Issue(t, certtest.Leaf{Names: []string{"*.home.arpa"}})
	kp, err = ParseKeyPair(wild, wkey)
	if err != nil || !Covers(kp.Leaf, "nas.home.arpa") || Covers(kp.Leaf, "a.b.home.arpa") || Covers(kp.Leaf, "home.arpa") {
		t.Fatalf("wildcard coverage: %v", err)
	}
}

func TestValidateUpload(t *testing.T) {
	now := time.Now()
	root := certtest.NewCA(t, "Own Root", nil)
	inter := certtest.NewCA(t, "Own Intermediate", root)
	cert, key := inter.Issue(t, certtest.Leaf{Names: []string{"app.lan"}})
	empty := x509.NewCertPool()

	// An own CA: leaf, intermediate and root uploaded together.
	if _, err := ValidateUpload(cert+inter.PEM+root.PEM, key, now, empty); err != nil {
		t.Fatalf("own CA chain: %v", err)
	}
	// A root the system trusts (here: given as trusted pool) needs only the intermediate.
	trusted := x509.NewCertPool()
	trusted.AddCert(root.Cert)
	if _, err := ValidateUpload(cert+inter.PEM, key, now, trusted); err != nil {
		t.Fatalf("public chain: %v", err)
	}
	expired, ekey := inter.Issue(t, certtest.Leaf{Names: []string{"app.lan"}, NotBefore: now.Add(-48 * time.Hour), NotAfter: now.Add(time.Hour)})
	future, fkey := inter.Issue(t, certtest.Leaf{Names: []string{"app.lan"}, NotBefore: now.Add(time.Hour)})
	caLeaf, cakey := inter.Issue(t, certtest.Leaf{Names: []string{"app.lan"}, IsCA: true})
	client, ckey := inter.Issue(t, certtest.Leaf{Names: []string{"app.lan"}, ExtUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	noName, nkey := inter.Issue(t, certtest.Leaf{})
	stranger := certtest.NewCA(t, "Stranger", nil)
	foreign, fokey := stranger.Issue(t, certtest.Leaf{Names: []string{"app.lan"}})
	for name, c := range map[string][2]string{
		"missing intermediate":   {cert + root.PEM, key},
		"untrusted root":         {cert + inter.PEM, key},
		"expires within a day":   {expired + inter.PEM + root.PEM, ekey},
		"not yet valid":          {future + inter.PEM + root.PEM, fkey},
		"CA as leaf":             {caLeaf + inter.PEM + root.PEM, cakey},
		"client certificate":     {client + inter.PEM + root.PEM, ckey},
		"no names":               {noName + inter.PEM + root.PEM, nkey},
		"chain of another CA":    {foreign + inter.PEM + root.PEM, fokey},
		"self-signed leaf alone": {root.PEM, ""},
	} {
		if _, err := ValidateUpload(c[0], c[1], now, empty); !isInvalid(err) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
}

func TestBuildTLS(t *testing.T) {
	ca := certtest.NewCA(t, "Root", nil)
	cert, key := ca.Issue(t, certtest.Leaf{Names: []string{"files.lan", "*.media.lan"}})
	routes := []agentproto.ProxyRoute{
		{ID: 1, Host: "public.example.org", UpstreamPort: 8080},
		{ID: 2, Host: "files.lan", UpstreamPort: 8081, LANOnly: true},
		{ID: 3, Host: "tv.media.lan", UpstreamPort: 8082},
		{ID: 4, Host: "nas.lan", UpstreamPort: 8083, LANOnly: true},
		{ID: 5, Host: "192.168.1.9", UpstreamPort: 8084},
	}
	acme := &agentproto.ACMESettings{Email: "admin@example.org", CA: agentproto.ACMEStaging}
	certs := []agentproto.TLSCertificate{{ID: 7, CertificatePEM: cert + ca.PEM, KeyPEM: key}}
	a := agentproto.ProxyApply{KernhavenHost: "kh.lan", Routes: routes, ACME: acme, Certificates: certs, TLSHosts: []agentproto.TLSHost{
		{Host: "public.example.org", Mode: agentproto.TLSACME},
		{Host: "files.lan", Mode: agentproto.TLSLoaded, CertificateID: 7},
		{Host: "tv.media.lan", Mode: agentproto.TLSLoaded, CertificateID: 7},
		{Host: "nas.lan", Mode: agentproto.TLSInternal},
	}}
	raw, err := Build(a, settings)
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{
		`{"issuers":[{"ca":"https://acme-staging-v02.api.letsencrypt.org/directory","email":"admin@example.org","module":"acme"}],"subjects":["public.example.org"]}`,
		`"automatic_https":{"skip_certificates":["files.lan","tv.media.lan"]}`,
		`{"certificate_selection":{"any_tag":["kh-cert-7"]},"match":{"sni":["files.lan"]}}`,
		`{"certificate_selection":{"any_tag":["kh-cert-7"]},"match":{"sni":["tv.media.lan"]}},{}]`,
		`"tags":["kh-cert-7"]`,
		`{"issuers":[{"module":"internal"}]}`,
		`"install_trust":false`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Count(s, `"load_pem":[{`) != 1 || strings.Count(s, "BEGIN PRIVATE KEY") != 1 {
		t.Error("certificate not loaded exactly once")
	}
	// Tests may point Caddy at Pebble; the Core cannot.
	test := settings
	test.ACMECA, test.ACMECARoot = "https://127.0.0.1:14000/dir", "/tmp/pebble.pem"
	raw, _ = Build(a, test)
	if !strings.Contains(string(raw), `"ca":"https://127.0.0.1:14000/dir"`) || !strings.Contains(string(raw), `"trusted_roots_pem_files":["/tmp/pebble.pem"]`) {
		t.Errorf("override %s", raw)
	}

	bad := func(name string, mod func(*agentproto.ProxyApply)) {
		t.Helper()
		b := a
		b.TLSHosts = append([]agentproto.TLSHost(nil), a.TLSHosts...)
		mod(&b)
		if _, err := Build(b, settings); !isInvalid(err) {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad("unknown host", func(b *agentproto.ProxyApply) {
		b.TLSHosts = append(b.TLSHosts, agentproto.TLSHost{Host: "x.lan", Mode: "internal"})
	})
	bad("duplicate host", func(b *agentproto.ProxyApply) {
		b.TLSHosts = append(b.TLSHosts, agentproto.TLSHost{Host: "nas.lan", Mode: "internal"})
	})
	bad("acme on LAN-only", func(b *agentproto.ProxyApply) { b.TLSHosts[3].Mode = agentproto.TLSACME })
	bad("acme on IP", func(b *agentproto.ProxyApply) {
		b.TLSHosts = append(b.TLSHosts, agentproto.TLSHost{Host: "192.168.1.9", Mode: agentproto.TLSACME})
	})
	bad("acme without settings", func(b *agentproto.ProxyApply) { b.ACME = nil })
	bad("bad email", func(b *agentproto.ProxyApply) {
		b.ACME = &agentproto.ACMESettings{Email: "Admin <a@b.c>", CA: "staging"}
	})
	bad("foreign CA", func(b *agentproto.ProxyApply) {
		b.ACME = &agentproto.ACMESettings{Email: "a@b.c", CA: "https://evil.example/directory"}
	})
	bad("certificate not covering host", func(b *agentproto.ProxyApply) {
		b.TLSHosts[3] = agentproto.TLSHost{Host: "nas.lan", Mode: agentproto.TLSLoaded, CertificateID: 7}
	})
	bad("missing certificate", func(b *agentproto.ProxyApply) { b.TLSHosts[1].CertificateID = 8 })
	bad("key mismatch", func(b *agentproto.ProxyApply) {
		_, other := ca.Issue(t, certtest.Leaf{Names: []string{"files.lan"}})
		b.Certificates = []agentproto.TLSCertificate{{ID: 7, CertificatePEM: cert, KeyPEM: other}}
	})
	bad("unknown mode", func(b *agentproto.ProxyApply) { b.TLSHosts[3].Mode = "letsencrypt" })
}
