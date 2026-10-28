//go:build proxy_service

package network

// These tests talk to the real kernhaven-proxy and kernhaven-caddy services,
// started by systemd with deploy/systemd/kernhaven-{proxy,caddy}.service on a
// disposable CI runner (ports 80 and 443).
//
//	KH_PROXY_KEYDIR   directory for the Core grant key (agent-grant.pub is read by the service)
//	KH_PROXY_SOCKET   the proxy service's socket
//	KH_CADDY_ROOT     Caddy's internal root certificate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
	"github.com/devthoko/KERNHAVEN/internal/proxy/certtest"
)

func mustEnv(t *testing.T, k string) string {
	t.Helper()
	v := os.Getenv(k)
	if v == "" {
		t.Skipf("%s not set", k)
	}
	return v
}

// TestM12WriteKey creates the Core's grant key before the service starts.
func TestM12WriteKey(t *testing.T) {
	if _, err := agentclient.LoadOrCreateKey(mustEnv(t, "KH_PROXY_KEYDIR")); err != nil {
		t.Fatal(err)
	}
}

func TestM12ProxyService(t *testing.T) {
	key, err := agentclient.LoadOrCreateKey(mustEnv(t, "KH_PROXY_KEYDIR"))
	if err != nil {
		t.Fatal(err)
	}
	cl := agentclient.New(mustEnv(t, "KH_PROXY_SOCKET"), key)
	do := func(op string, params, out any) error {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		return cl.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: "it", RequestID: "it"}, out)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "backend %s user=%s", r.URL.Path, r.Header.Get(proxy.UserHeader))
	}))
	defer backend.Close()
	port := backend.Listener.Addr().(*net.TCPAddr).Port

	// Only the proxy role's operations exist.
	if err := do(agentproto.OpContainersList, agentproto.ContainersList{}, nil); err == nil {
		t.Fatal("containers.list in the proxy role")
	}
	var applied agentproto.ProxyApplied
	if err := do(agentproto.OpProxyApply, agentproto.ProxyApply{KernhavenHost: "kh.test", Routes: []agentproto.ProxyRoute{
		{ID: 1, Host: "app.test", UpstreamPort: port},
		{ID: 2, Host: "deny.test", UpstreamPort: port, AllowCIDRs: []string{"10.0.0.0/8"}},
	}}, &applied); err != nil {
		t.Fatalf("apply through the real units: %v", err)
	}
	// Validation happens in the service whatever the caller sends.
	if err := do(agentproto.OpProxyApply, agentproto.ProxyApply{KernhavenHost: "kh.test", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "x.test", UpstreamPort: 22}}}, nil); err == nil {
		t.Fatal("privileged upstream port accepted")
	}

	// Caddy serves the routes on 443 with its internal CA.
	pool := x509.NewCertPool()
	var pem []byte
	for i := 0; i < 100 && !pool.AppendCertsFromPEM(pem); i++ {
		time.Sleep(100 * time.Millisecond)
		pem, _ = os.ReadFile(mustEnv(t, "KH_CADDY_ROOT"))
	}
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:443")
		},
	}}
	get := func(host string) (int, string) {
		var lastErr error
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/hello", nil)
			req.Header.Set(proxy.UserHeader, "mallory")
			res, err := c.Do(req)
			if err == nil {
				b, _ := io.ReadAll(res.Body)
				res.Body.Close()
				return res.StatusCode, string(b)
			}
			lastErr = err
			time.Sleep(200 * time.Millisecond)
		}
		t.Fatalf("GET %s: %v", host, lastErr)
		return 0, ""
	}
	if code, body := get("app.test"); code != 200 || body != "backend /hello user=" {
		t.Fatalf("app.test: %d %q", code, body)
	}
	if code, _ := get("deny.test"); code != 403 {
		t.Fatalf("deny.test: %d", code)
	}
	var st agentproto.ProxyStatus
	if err := do(agentproto.OpProxyStatus, nil, &st); err != nil || !st.Reachable || st.Hash != applied.Hash {
		t.Fatalf("status %+v %v", st, err)
	}
	// The overview works inside the unit's sandbox and sees Caddy's port.
	var ov agentproto.NetworkOverview
	if err := do(agentproto.OpNetworkOverview, nil, &ov); err != nil || len(ov.Interfaces) == 0 {
		t.Fatalf("overview %+v %v", ov, err)
	}
	found := false
	for _, l := range ov.Listening {
		found = found || l.Port == 443 && l.Protocol[:3] == "tcp"
	}
	if !found {
		t.Fatalf("443 not among %+v", ov.Listening)
	}

	// M13: the local CA's root through the unit's sandbox, and an own certificate for app.test.
	var ca agentproto.ProxyCA
	if err := do(agentproto.OpProxyCA, nil, &ca); err != nil || len(ca.SHA256) != 64 {
		t.Fatalf("root: %+v %v", ca, err)
	}
	own := certtest.NewCA(t, "Own Root", nil)
	cert, certKey := own.Issue(t, certtest.Leaf{Names: []string{"app.test"}})
	if err := do(agentproto.OpProxyApply, agentproto.ProxyApply{KernhavenHost: "kh.test",
		Routes:       []agentproto.ProxyRoute{{ID: 1, Host: "app.test", UpstreamPort: port}},
		Certificates: []agentproto.TLSCertificate{{ID: 9, CertificatePEM: cert + own.PEM, KeyPEM: certKey}},
		TLSHosts:     []agentproto.TLSHost{{Host: "app.test", Mode: agentproto.TLSLoaded, CertificateID: 9}},
	}, nil); err != nil {
		t.Fatalf("apply with certificate: %v", err)
	}
	ownPool := x509.NewCertPool()
	ownPool.AddCert(own.Cert)
	var conn *tls.Conn
	for i := 0; i < 50; i++ {
		if conn, err = tls.Dial("tcp", "127.0.0.1:443", &tls.Config{ServerName: "app.test", RootCAs: ownPool}); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("own certificate not served: %v", err)
	}
	conn.Close()
}
