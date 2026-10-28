package network

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
)

// fakeCaddy imitates the admin API: /load stores the body unless fail is set,
// /config/ returns what is stored.
type fakeCaddy struct {
	mu     sync.Mutex
	config []byte
	fail   string
	hosts  []string
}

func (f *fakeCaddy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hosts = append(f.hosts, r.Host)
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/load":
		if f.fail != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"`+f.fail+`"}`)
			return
		}
		f.config, _ = io.ReadAll(r.Body)
	case r.Method == http.MethodGet && r.URL.Path == "/config/":
		if f.config == nil {
			_, _ = io.WriteString(w, "null\n")
			return
		}
		_, _ = w.Write(f.config)
	default:
		http.NotFound(w, r)
	}
}

func startFake(t *testing.T) (*fakeCaddy, proxy.Settings) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeCaddy{}
	srv := &http.Server{Handler: f}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f, proxy.Settings{AdminSocket: sock, CoreAddress: "127.0.0.1:8470", HTTPPort: 80, HTTPSPort: 443}
}

var apply = agentproto.ProxyApply{KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "app.lan", UpstreamPort: 8080}}}

func TestApply(t *testing.T) {
	f, set := startFake(t)
	s := New(set)
	ctx := context.Background()
	st, err := s.Status(ctx)
	if err != nil || !st.Reachable || st.Hash != "" {
		t.Fatalf("empty caddy: %+v %v", st, err)
	}
	res, err := s.Apply(ctx, apply)
	if err != nil || res.Routes != 1 || res.Hash == "" || res.HTTPSPort != 443 {
		t.Fatalf("apply: %+v %v", res, err)
	}
	if st, _ := s.Status(ctx); st.Hash != res.Hash {
		t.Fatalf("status hash %q, applied %q", st.Hash, res.Hash)
	}
	if !strings.Contains(string(f.config), `"dial":"127.0.0.1:8080"`) {
		t.Fatalf("loaded %s", f.config)
	}
	for _, h := range f.hosts {
		if h != proxy.AdminHost {
			t.Fatalf("host header %q", h)
		}
	}

	// Caddy refuses: the error carries its message, the old configuration stays.
	f.fail = "loading config: listen tcp :443: bind: address already in use"
	before := string(f.config)
	_, err = s.Apply(ctx, agentproto.ProxyApply{KernhavenHost: "kh.lan"})
	var re *RejectedError
	if !errors.As(err, &re) || !strings.Contains(re.Msg, "address already in use") || string(f.config) != before {
		t.Fatalf("rejected: %v", err)
	}
	f.fail = ""

	// Invalid routes never reach Caddy.
	_, err = s.Apply(ctx, agentproto.ProxyApply{KernhavenHost: "kh.lan", Routes: []agentproto.ProxyRoute{{ID: 1, Host: "app.lan", UpstreamPort: 8470}}})
	var ie *proxy.InvalidError
	if !errors.As(err, &ie) || string(f.config) != before {
		t.Fatalf("invalid: %v", err)
	}
}

func TestUnavailable(t *testing.T) {
	s := New(proxy.Settings{AdminSocket: filepath.Join(t.TempDir(), "missing.sock"), CoreAddress: "127.0.0.1:8470", HTTPPort: 80, HTTPSPort: 443})
	if _, err := s.Apply(context.Background(), apply); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("apply: %v", err)
	}
	if st, err := s.Status(context.Background()); err != nil || st.Reachable {
		t.Fatalf("status: %+v %v", st, err)
	}
}

func TestParseProcNet(t *testing.T) {
	tcp := `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:2116 00000000:0000 0A 00000000:00000000 00:00000000 00000000   998        0 1 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 2 1 0000000000000000 100 0 0 10 0
   2: 0100007F:2116 0100007F:C350 01 00000000:00000000 00:00000000 00000000   998        0 3 1 0000000000000000 20 4 30 10 -1
`
	got, err := parseProcNet(strings.NewReader(tcp), "tcp")
	if err != nil || len(got) != 2 || got[0] != (agentproto.ListeningSocket{Protocol: "tcp", Address: "127.0.0.1", Port: 8470}) ||
		got[1] != (agentproto.ListeningSocket{Protocol: "tcp", Address: "0.0.0.0", Port: 22}) {
		t.Fatalf("tcp %+v %v", got, err)
	}
	tcp6 := `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000001000000:01BB 00000000000000000000000000000000:0000 0A
   1: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A
`
	got, err = parseProcNet(strings.NewReader(tcp6), "tcp6")
	if err != nil || len(got) != 2 || got[0].Address != "::1" || got[0].Port != 443 || got[1].Address != "127.0.0.1" || got[1].Port != 80 {
		t.Fatalf("tcp6 %+v %v", got, err)
	}
	udp := `  sl  local_address rem_address   st
   0: 3500007F:0035 00000000:0000 07
   1: 0100007F:A000 0100007F:0035 01
   2: 0100007F:A001 0100007F:0035 07
`
	got, err = parseProcNet(strings.NewReader(udp), "udp")
	if err != nil || len(got) != 1 || got[0].Address != "127.0.0.53" || got[0].Port != 53 {
		t.Fatalf("udp %+v %v", got, err)
	}
	if _, err := parseProcNet(strings.NewReader("h\n 0: zz:0016 00000000:0000 0A\n"), "tcp"); err == nil {
		t.Fatal("bad address accepted")
	}
}

func TestOverview(t *testing.T) {
	ov, err := New(proxy.Settings{}).Overview(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	lo := false
	for _, i := range ov.Interfaces {
		lo = lo || i.Loopback
	}
	if !lo {
		t.Fatalf("no loopback interface in %+v", ov.Interfaces)
	}
	// The test's own listener shows up.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	ov, _ = New(proxy.Settings{}).Overview(context.Background())
	for _, l := range ov.Listening {
		if l.Port == port && l.Address == "127.0.0.1" && l.Protocol == "tcp" {
			return
		}
	}
	t.Fatalf("listener %d not found", port)
}
