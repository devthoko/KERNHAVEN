//go:build proxy_integration

package network

// These tests run a real Caddy (KH_CADDY=/path/to/caddy, 2.6.2 or newer)
// with a private admin socket and high ports, and check that the generated
// configuration behaves as designed (AT-F11-01..03).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
	"github.com/devthoko/KERNHAVEN/internal/proxy/certtest"
)

func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

type caddyProc struct {
	t   *testing.T
	dir string
	cmd *exec.Cmd
}

func startCaddy(t *testing.T, dir string) *caddyProc {
	t.Helper()
	bin := os.Getenv("KH_CADDY")
	if bin == "" {
		t.Skip("KH_CADDY not set")
	}
	boot := filepath.Join(dir, "boot.json")
	sock := filepath.Join(dir, "admin.sock")
	_ = os.WriteFile(boot, []byte(fmt.Sprintf(`{"admin":{"listen":"unix/%s","origins":[%q]}}`, sock, proxy.AdminHost)), 0o600)
	cmd := exec.Command(bin, "run", "--config", boot, "--resume")
	cmd.Env = []string{"HOME=" + dir, "XDG_DATA_HOME=" + filepath.Join(dir, "data"), "XDG_CONFIG_HOME=" + filepath.Join(dir, "config")}
	log, _ := os.OpenFile(filepath.Join(dir, "caddy.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	c := &caddyProc{t: t, dir: dir, cmd: cmd}
	t.Cleanup(c.stop)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			return c
		}
		time.Sleep(50 * time.Millisecond)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "caddy.log"))
	t.Fatalf("caddy did not start: %s", b)
	return nil
}

func (c *caddyProc) stop() {
	if c.cmd.ProcessState == nil {
		_ = c.cmd.Process.Signal(os.Interrupt)
		_ = c.cmd.Wait()
	}
}

// client sends every request to Caddy's port on 127.0.0.1, trusting only
// Caddy's internal root, and does not follow redirects.
func client(t *testing.T, dir string, port int) *http.Client {
	t.Helper()
	root := filepath.Join(dir, "data", "caddy", "pki", "authorities", "local", "root.crt")
	var pem []byte
	for i := 0; i < 100; i++ {
		if b, err := os.ReadFile(root); err == nil {
			pem = b
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("no internal root at %s", root)
	}
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool},
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				_, p, _ := net.SplitHostPort(addr)
				if p == "443" || p == fmt.Sprint(port) {
					p = fmt.Sprint(port)
				}
				return d.DialContext(ctx, "tcp", "127.0.0.1:"+p)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func waitTLS(t *testing.T, c *http.Client, url string) {
	t.Helper()
	var err error
	for i := 0; i < 100; i++ {
		var res *http.Response
		if res, err = c.Get(url + "/"); err == nil {
			res.Body.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("no certificate for %s: %v", url, err)
}

type reply struct {
	status int
	body   string
	header http.Header
}

func get(t *testing.T, c *http.Client, url string, hdr ...string) reply {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return reply{res.StatusCode, string(b), res.Header}
}

func TestCaddyRoutes(t *testing.T) {
	dir := t.TempDir()
	caddy := startCaddy(t, dir)

	backend := func(name string) int {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "%s path=%s user=%s", name, r.URL.Path, r.Header.Get(proxy.UserHeader))
		}))
		t.Cleanup(srv.Close)
		return srv.Listener.Addr().(*net.TCPAddr).Port
	}
	one, two := backend("one"), backend("two")
	// The fake Core answers forward auth and the gate callback.
	core := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case proxy.AuthPath:
			if c, err := r.Cookie("kh_gate_2"); err == nil && c.Value == "good" {
				w.Header().Set(proxy.UserHeader, "alice")
				return
			}
			http.Redirect(w, r, "https://kh.test/gate?route="+r.Header.Get(proxy.RouteHeader)+"&uri="+r.Header.Get("X-Forwarded-Uri"), http.StatusFound)
		case proxy.CallbackPath:
			fmt.Fprintf(w, "callback route=%s query=%s host=%s", r.Header.Get(proxy.RouteHeader), r.URL.RawQuery, r.Host)
		default:
			fmt.Fprintf(w, "core %s", r.URL.Path)
		}
	}))
	t.Cleanup(core.Close)

	httpsPort, httpPort := freePort(t), freePort(t)
	set := proxy.Settings{AdminSocket: filepath.Join(dir, "admin.sock"), CoreAddress: core.Listener.Addr().String(), HTTPPort: httpPort, HTTPSPort: httpsPort}
	s := New(set)
	ctx := context.Background()
	applied, err := s.Apply(ctx, agentproto.ProxyApply{KernhavenHost: "kh.test", Routes: []agentproto.ProxyRoute{
		{ID: 1, Host: "app.test", UpstreamPort: one},
		{ID: 2, Host: "app.test", PathPrefix: "/books", StripPrefix: true, UpstreamPort: two, SSO: true},
		{ID: 3, Host: "lan.test", UpstreamPort: one, LANOnly: true},
		{ID: 4, Host: "deny.test", UpstreamPort: one, AllowCIDRs: []string{"10.0.0.0/8"}},
		{ID: 5, Host: "both.test", UpstreamPort: one, LANOnly: true, AllowCIDRs: []string{"127.0.0.1/32"}},
	}})
	if err != nil {
		b, _ := os.ReadFile(filepath.Join(dir, "caddy.log"))
		t.Fatalf("apply: %v\n%s", err, b)
	}
	c := client(t, dir, httpsPort)
	base := func(host string) string { return fmt.Sprintf("https://%s:%d", host, httpsPort) }
	// Certificates of the internal CA are issued in the background after a load.
	for _, h := range []string{"app.test", "lan.test", "deny.test", "both.test", "kh.test"} {
		waitTLS(t, c, base(h))
	}

	// Host routing; a spoofed identity header is removed (TH-41).
	if r := get(t, c, base("app.test")+"/x", proxy.UserHeader, "mallory"); r.status != 200 || r.body != "one path=/x user=" {
		t.Errorf("app.test: %+v", r)
	}
	// The gated prefix route: without a cookie → redirect from the Core, with the original URI.
	if r := get(t, c, base("app.test")+"/books/a?b=1"); r.status != 302 || r.header.Get("Location") != "https://kh.test/gate?route=2&uri=/books/a?b=1" {
		t.Errorf("gate redirect: %+v", r)
	}
	// With the cookie: prefix stripped, identity from the Core, spoofed header replaced.
	if r := get(t, c, base("app.test")+"/books/a", "Cookie", "kh_gate_2=good", proxy.UserHeader, "mallory"); r.status != 200 || r.body != "two path=/a user=alice" {
		t.Errorf("gated: %+v", r)
	}
	if r := get(t, c, base("app.test")+"/books/a", "Cookie", "kh_gate_2=bad"); r.status != 302 {
		t.Errorf("bad cookie: %+v", r)
	}
	// The callback reaches the Core with the route and the original host.
	if r := get(t, c, base("app.test")+"/books/.kernhaven/gate?code=abc&rd=%2Fbooks"); r.status != 200 ||
		r.body != fmt.Sprintf("callback route=2 query=code=abc&rd=%%2Fbooks host=app.test:%d", httpsPort) {
		t.Errorf("callback: %+v", r)
	}
	// Kernhaven host: the UI is proxied, internal endpoints are not reachable.
	if r := get(t, c, base("kh.test")+"/dashboard"); r.status != 200 || r.body != "core /dashboard" {
		t.Errorf("kernhaven: %+v", r)
	}
	for _, p := range []string{proxy.AuthPath, proxy.CallbackPath, "/api/v1/proxy-internal/x"} {
		if r := get(t, c, base("kh.test")+p); r.status != 404 {
			t.Errorf("%s via kernhaven host: %+v", p, r)
		}
	}
	// Access control: 127.0.0.1 is LAN; it is not in 10.0.0.0/8; both conditions must hold.
	if r := get(t, c, base("lan.test")+"/"); r.status != 200 {
		t.Errorf("lan only from loopback: %+v", r)
	}
	if r := get(t, c, base("deny.test")+"/"); r.status != 403 || strings.Contains(r.body, "one") {
		t.Errorf("allow-list: %+v", r)
	}
	if r := get(t, c, base("both.test")+"/"); r.status != 200 {
		t.Errorf("lan + allow-list: %+v", r)
	}
	// Plain HTTP redirects to HTTPS.
	if r := get(t, c, fmt.Sprintf("http://app.test:%d/x", httpPort)); r.status != 308 || !strings.HasPrefix(r.header.Get("Location"), "https://app.test") {
		t.Errorf("http redirect: %+v", r)
	}
	if st, err := s.Status(ctx); err != nil || st.Hash != applied.Hash {
		t.Fatalf("status %+v %v, applied %s", st, err, applied.Hash)
	}

	// AT-F11-03: a configuration Caddy cannot start (port in use) is refused and the running one stays.
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	bad := set
	bad.HTTPSPort = busy.Addr().(*net.TCPAddr).Port
	_, err = New(bad).Apply(ctx, agentproto.ProxyApply{KernhavenHost: "kh.test", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "app.test", UpstreamPort: two}}})
	var re *RejectedError
	if !errors.As(err, &re) || !strings.Contains(re.Msg, "address already in use") {
		t.Fatalf("busy port: %v", err)
	}
	if st, _ := s.Status(ctx); st.Hash != applied.Hash {
		t.Fatal("configuration changed after a failed load")
	}
	if r := get(t, c, base("app.test")+"/x"); r.status != 200 || r.body != "one path=/x user=" {
		t.Errorf("after failed load: %+v", r)
	}

	// After a restart Caddy resumes the last configuration.
	caddy.stop()
	startCaddy(t, dir)
	waitTLS(t, c, base("app.test"))
	if st, err := s.Status(ctx); err != nil || st.Hash != applied.Hash {
		t.Fatalf("after restart: %+v %v", st, err)
	}
	if r := get(t, c, base("app.test")+"/x"); r.status != 200 {
		t.Errorf("after restart: %+v", r)
	}
}

// served returns the leaf Caddy presents for host, verified against roots.
func served(t *testing.T, port int, host string, roots *x509.CertPool) (*x509.Certificate, error) {
	t.Helper()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", fmt.Sprintf("127.0.0.1:%d", port), &tls.Config{ServerName: host, RootCAs: roots})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0], nil
}

func waitServed(t *testing.T, port int, host string, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	var err error
	for i := 0; i < 300; i++ {
		var c *x509.Certificate
		if c, err = served(t, port, host, roots); err == nil {
			return c
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s: %v", host, err)
	return nil
}

// AT-F12-01..03 at the Caddy level: an ACME certificate through HTTP-01,
// exactly the uploaded certificate for its host, the local CA's root.
func TestCaddyTLS(t *testing.T) {
	dir := t.TempDir()
	t.Cleanup(func() {
		if t.Failed() {
			for _, f := range []string{"caddy.log", "pebble.log", "pebble-challtestsrv.log"} {
				b, _ := os.ReadFile(filepath.Join(dir, f))
				if len(b) > 6000 {
					b = b[len(b)-6000:]
				}
				t.Logf("--- %s\n%s", f, b)
			}
		}
	})
	httpsPort, httpPort := freePort(t), freePort(t)
	pb := certtest.StartPebble(t, dir, httpPort, httpsPort)
	directory, tlsRoot, issuing := pb.Directory, pb.TLSRootFile, pb.Issuing
	startCaddy(t, dir)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "backend") }))
	defer backend.Close()
	port := backend.Listener.Addr().(*net.TCPAddr).Port

	own := certtest.NewCA(t, "Own Root", nil)
	cert, key := own.Issue(t, certtest.Leaf{Names: []string{"custom.test"}})
	s := New(proxy.Settings{AdminSocket: filepath.Join(dir, "admin.sock"), CoreAddress: "127.0.0.1:9", HTTPPort: httpPort, HTTPSPort: httpsPort,
		ACMECA: directory, ACMECARoot: tlsRoot})
	ctx := context.Background()
	_, err := s.Apply(ctx, agentproto.ProxyApply{KernhavenHost: "kh.test",
		Routes:       []agentproto.ProxyRoute{{ID: 1, Host: "acme.test", UpstreamPort: port}, {ID: 2, Host: "custom.test", UpstreamPort: port}},
		ACME:         &agentproto.ACMESettings{Email: "admin@example.org", CA: agentproto.ACMEStaging},
		Certificates: []agentproto.TLSCertificate{{ID: 3, CertificatePEM: cert + own.PEM, KeyPEM: key}},
		TLSHosts: []agentproto.TLSHost{
			{Host: "acme.test", Mode: agentproto.TLSACME},
			{Host: "custom.test", Mode: agentproto.TLSLoaded, CertificateID: 3},
		}})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	// AT-F12-01: Caddy obtained acme.test from the ACME CA through HTTP-01/TLS-ALPN-01.
	leaf := waitServed(t, httpsPort, "acme.test", issuing)
	if !strings.Contains(leaf.Issuer.CommonName, "Pebble") {
		t.Fatalf("acme.test issued by %s", leaf.Issuer)
	}
	// AT-F12-03: exactly the uploaded certificate for its host.
	ownPool := x509.NewCertPool()
	ownPool.AddCert(own.Cert)
	leaf = waitServed(t, httpsPort, "custom.test", ownPool)
	if leaf.Subject.CommonName != "leaf" || leaf.Issuer.CommonName != "Own Root" {
		t.Fatalf("custom.test served %s from %s", leaf.Subject, leaf.Issuer)
	}
	// AT-F12-02: the Kernhaven host uses the local CA, whose root the proxy service hands out.
	ca, err := s.CA(ctx)
	if err != nil || len(ca.SHA256) != 64 {
		t.Fatalf("ca: %+v %v", ca, err)
	}
	local := x509.NewCertPool()
	if !local.AppendCertsFromPEM([]byte(ca.RootPEM)) {
		t.Fatal("root not PEM")
	}
	if leaf = waitServed(t, httpsPort, "kh.test", local); !strings.Contains(leaf.Issuer.CommonName, "Caddy Local Authority") {
		t.Fatalf("kh.test issued by %s", leaf.Issuer)
	}
	if _, err := served(t, httpsPort, "custom.test", local); err == nil {
		t.Fatal("custom.test served with a local CA certificate")
	}
}
