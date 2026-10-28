package certtest

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Pebble is a running Pebble ACME test server with its mock DNS.
type Pebble struct {
	Directory   string         // ACME directory URL
	TLSRootFile string         // PEM of the CA that signed Pebble's own TLS certificate
	TLSRoots    *x509.CertPool // the same as a pool
	Issuing     *x509.CertPool // Pebble's issuing root
	mgmt        string
}

func freePort(t testing.TB) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// StartPebble runs Pebble (KH_PEBBLE) with pebble-challtestsrv
// (KH_CHALLTESTSRV) as its DNS, which answers every name with 127.0.0.1.
// HTTP-01 and TLS-ALPN-01 are validated on httpPort and tlsPort.
func StartPebble(t testing.TB, dir string, httpPort, tlsPort int) *Pebble {
	t.Helper()
	bin, chall := os.Getenv("KH_PEBBLE"), os.Getenv("KH_CHALLTESTSRV")
	if bin == "" || chall == "" {
		t.Skip("KH_PEBBLE and KH_CHALLTESTSRV not set")
	}
	ca := NewCA(t, "Pebble TLS test root", nil)
	cert, key := ca.Issue(t, Leaf{Names: []string{"127.0.0.1", "localhost"}})
	p := &Pebble{TLSRootFile: filepath.Join(dir, "pebble-tls-root.pem"), TLSRoots: x509.NewCertPool()}
	p.TLSRoots.AddCert(ca.Cert)
	_ = os.WriteFile(p.TLSRootFile, []byte(ca.PEM), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "pebble-cert.pem"), []byte(cert), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "pebble-key.pem"), []byte(key), 0o600)
	dnsPort, mgmt, listen, pmgmt := freePort(t), freePort(t), freePort(t), freePort(t)
	p.mgmt = fmt.Sprintf("http://127.0.0.1:%d", mgmt)
	start := func(name string, env []string, args ...string) {
		cmd := exec.Command(name, args...)
		cmd.Env = append(os.Environ(), env...)
		log, _ := os.Create(filepath.Join(dir, filepath.Base(name)+".log"))
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	}
	start(chall, nil, "-defaultIPv4", "127.0.0.1", "-defaultIPv6", "", "-dnsserver", fmt.Sprintf("127.0.0.1:%d", dnsPort),
		"-management", fmt.Sprintf("127.0.0.1:%d", mgmt), "-http01", "", "-https01", "", "-tlsalpn01", "", "-doh", "")
	cfg := fmt.Sprintf(`{"pebble":{"listenAddress":"127.0.0.1:%d","managementListenAddress":"127.0.0.1:%d","certificate":%q,"privateKey":%q,"httpPort":%d,"tlsPort":%d,"ocspResponderURL":"","externalAccountBindingRequired":false}}`,
		listen, pmgmt, filepath.Join(dir, "pebble-cert.pem"), filepath.Join(dir, "pebble-key.pem"), httpPort, tlsPort)
	_ = os.WriteFile(filepath.Join(dir, "pebble.json"), []byte(cfg), 0o600)
	start(bin, []string{"PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0"}, "-config", filepath.Join(dir, "pebble.json"), "-dnsserver", fmt.Sprintf("127.0.0.1:%d", dnsPort))
	p.Directory = fmt.Sprintf("https://127.0.0.1:%d/dir", listen)

	c := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: p.TLSRoots}}}
	var pem []byte
	for i := 0; i < 100; i++ {
		if res, err := c.Get(fmt.Sprintf("https://127.0.0.1:%d/roots/0", pmgmt)); err == nil {
			pem, _ = io.ReadAll(res.Body)
			res.Body.Close()
			if res.StatusCode == 200 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	p.Issuing = x509.NewCertPool()
	if !p.Issuing.AppendCertsFromPEM(pem) {
		b, _ := os.ReadFile(filepath.Join(dir, "pebble.log"))
		t.Fatalf("no Pebble root: %s", b)
	}
	return p
}

// SetTXT and ClearTXT change the mock DNS (for DNS-01).
func (p *Pebble) SetTXT(fqdn, value string) error {
	return p.post("/set-txt", map[string]string{"host": fqdn + ".", "value": value})
}

// ClearTXT removes the TXT records of fqdn.
func (p *Pebble) ClearTXT(fqdn string) error {
	return p.post("/clear-txt", map[string]string{"host": fqdn + "."})
}

func (p *Pebble) post(path string, body any) error {
	b, _ := json.Marshal(body)
	res, err := http.Post(p.mgmt+path, "application/json", bytes.NewReader(b))
	if err != nil {
		return err
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		return fmt.Errorf("challtestsrv %s: HTTP %d", path, res.StatusCode)
	}
	return nil
}
