package app

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	agentnetwork "github.com/devthoko/KERNHAVEN/internal/agent/network"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
	"github.com/devthoko/KERNHAVEN/internal/proxy/certtest"
)

// fakeCaddy stands in for Caddy's admin API: it keeps the last loaded
// configuration and refuses loads while fail is set (the real Caddy is
// exercised by internal/agent/network's integration test).
type fakeCaddy struct {
	mu     sync.Mutex
	config []byte
	loads  int
	fail   string
	root   string // PEM of the local CA's root (M13)
}

func (f *fakeCaddy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/load":
		f.loads++
		if f.fail != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"`+f.fail+`"}`)
			return
		}
		f.config, _ = io.ReadAll(r.Body)
	case r.URL.Path == "/pki/ca/local":
		b, _ := json.Marshal(map[string]string{"id": "local", "root_certificate": f.root})
		_, _ = w.Write(b)
	case r.URL.Path == "/config/":
		if f.config == nil {
			_, _ = io.WriteString(w, "null")
			return
		}
		_, _ = w.Write(f.config)
	}
}

func (f *fakeCaddy) set(fail string) { f.mu.Lock(); f.fail = fail; f.mu.Unlock() }

func (f *fakeCaddy) state() (string, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return string(f.config), f.loads
}

func serveAgent(t *testing.T, h *harness, sock string, d agent.Docker, opts agent.Options) {
	t.Helper()
	pub, err := agentproto.ReadPublicKey(filepath.Join(h.dataDir, "agent-grant.pub"))
	if err != nil {
		t.Fatal(err)
	}
	srv := agent.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, d, opts)
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// withProxy starts a Core with a proxy service (the real agent role) in front
// of a fake Caddy; docker additionally starts the Docker agent.
func withProxy(t *testing.T, docker bool) (*harness, *fakeCaddy, *memDocker) {
	t.Helper()
	return withProxyOpts(t, docker, nil, nil)
}

// withProxyOpts also adjusts the configuration and options (M13).
func withProxyOpts(t *testing.T, docker bool, adjust func(*config.Config), adjustOpts func(*Options)) (*harness, *fakeCaddy, *memDocker) {
	t.Helper()
	dir := t.TempDir()
	proxySock, dockerSock, adminSock := filepath.Join(dir, "proxy.sock"), filepath.Join(dir, "agent.sock"), filepath.Join(dir, "admin.sock")
	h := newHarnessFull(t, func(c *config.Config) {
		c.Agent.ProxySocket = proxySock
		if docker {
			c.Agent.Socket = dockerSock
		}
		if adjust != nil {
			adjust(c)
		}
	}, adjustOpts)
	fake := &fakeCaddy{root: certtest.NewCA(t, "Caddy Local Authority - Test Root", nil).PEM}
	ln, err := net.Listen("unix", adminSock)
	if err != nil {
		t.Fatal(err)
	}
	hs := &http.Server{Handler: fake}
	go func() { _ = hs.Serve(ln) }()
	t.Cleanup(func() { _ = hs.Close() })
	serveAgent(t, h, proxySock, nil, agent.Options{Proxy: agentnetwork.New(proxy.Settings{AdminSocket: adminSock, CoreAddress: "127.0.0.1:8470", HTTPPort: 80, HTTPSPort: 443})})
	var md *memDocker
	if docker {
		md = newMemDocker()
		serveAgent(t, h, dockerSock, md, agent.Options{})
	}
	return h, fake, md
}

type routesBody struct {
	Routes []network.Route
	Proxy  network.State
}

// AT-F11-01, AT-F11-03: routes are validated, applied as a whole and stored
// only when Caddy accepted them; permissions and step-up.
func TestNetworkRoutes(t *testing.T) {
	h, fake, _ := withProxy(t, false)
	owner := h.setupOwner()
	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer1", authz.Viewer)
	op, viewer := h.loginAs("operator1"), h.loginAs("viewer1")

	viewer.do("GET", "/api/v1/network/routes", nil).expect(403)
	op.do("GET", "/api/v1/network/routes", nil).expect(200)
	op.do("POST", "/api/v1/network/routes", map[string]any{"host": "a.lan", "upstream_port": 8096}).expect(403)

	var media network.Route
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": " Media.LAN ", "upstream_port": 8096,
		"allow_cidrs": []string{"192.168.1.7", " 10.1.2.3/8", "192.168.1.7/32"}}).expect(201).json(&media)
	if media.Host != "media.lan" || media.URL != "https://media.lan/" || strings.Join(media.AllowCIDRs, ",") != "192.168.1.7/32,10.0.0.0/8" || media.SSOMinRole != authz.Viewer {
		t.Fatalf("route %+v", media)
	}
	cfg, loads := fake.state()
	if !strings.Contains(cfg, `"dial":"127.0.0.1:8096"`) || !strings.Contains(cfg, `"host":["kernhaven.test"]`) || !strings.Contains(cfg, `"dial":"127.0.0.1:8470"`) {
		t.Fatalf("caddy config %s", cfg)
	}

	// Invalid input never reaches Caddy.
	for name, body := range map[string]map[string]any{
		"kernhaven host": {"host": "kernhaven.test", "upstream_port": 9000},
		"core port":      {"host": "x.lan", "upstream_port": 8470},
		"low port":       {"host": "x.lan", "upstream_port": 80},
		"wildcard":       {"host": "*.lan", "upstream_port": 9000},
		"traversal":      {"host": "x.lan", "path_prefix": "/a/../b", "upstream_port": 9000},
		"strip only":     {"host": "x.lan", "strip_prefix": true, "upstream_port": 9000},
		"role":           {"host": "x.lan", "upstream_port": 9000, "sso": true, "sso_min_role": "root"},
		"cidr":           {"host": "x.lan", "upstream_port": 9000, "allow_cidrs": []string{"lan"}},
	} {
		if r := owner.do("POST", "/api/v1/network/routes", body); r.Code != 422 || r.errorCode() != "validation_failed" {
			t.Errorf("%s: %d %s", name, r.Code, r.Body)
		}
	}
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "media.lan", "upstream_port": 9000}).expect(409)
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "x.lan", "upstream_port": 9000, "unknown": 1}).expect(400)
	if _, n := fake.state(); n != loads {
		t.Fatalf("invalid input reached Caddy: %d loads", n-loads)
	}

	var books network.Route
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "media.lan", "path_prefix": "/books", "strip_prefix": true, "upstream_port": 8083,
		"sso": true, "sso_min_role": "admin"}).expect(201).json(&books)
	owner.do("PUT", "/api/v1/network/routes/"+itoa(media.ID), map[string]any{"host": "media.lan", "upstream_port": 8096, "lan_only": true}).expect(200)
	if cfg, _ := fake.state(); !strings.Contains(cfg, `"fc00::/7"`) || !strings.Contains(cfg, `"strip_path_prefix":"/books"`) || strings.Contains(cfg, "192.168.1.7/32") {
		t.Fatalf("after update %s", cfg)
	}

	// Caddy refuses: nothing is stored, the error is shown, audited and kept as state.
	fake.set("loading config: listen tcp :443: bind: address already in use")
	before, _ := fake.state()
	r := owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "new.lan", "upstream_port": 9000})
	if r.Code != 422 || r.errorCode() != "proxy_rejected" || !strings.Contains(r.Body.String(), "address already in use") {
		t.Fatalf("refused create: %d %s", r.Code, r.Body)
	}
	owner.do("DELETE", "/api/v1/network/routes/"+itoa(books.ID), nil).expect(422)
	owner.do("PUT", "/api/v1/network/routes/"+itoa(media.ID), map[string]any{"host": "media.lan", "upstream_port": 9999}).expect(422)
	var rb routesBody
	owner.do("GET", "/api/v1/network/routes", nil).expect(200).json(&rb)
	if len(rb.Routes) != 2 || rb.Routes[0].UpstreamPort != 8096 || rb.Routes[1].UpstreamPort != 8083 || !strings.Contains(rb.Proxy.Error, "address already in use") ||
		strings.HasPrefix(rb.Proxy.Error, "agent:") {
		t.Fatalf("after refusal %+v", rb)
	}
	if after, _ := fake.state(); after != before {
		t.Fatal("caddy configuration changed")
	}
	if n := auditCount(t, h, "network.route_create", "failure"); n != 1 {
		t.Fatalf("failed create audited %d times", n)
	}
	fake.set("")

	owner.do("DELETE", "/api/v1/network/routes/"+itoa(books.ID), nil).expect(204)
	owner.do("DELETE", "/api/v1/network/routes/"+itoa(books.ID), nil).expect(404)
	rb = routesBody{}
	owner.do("GET", "/api/v1/network/routes", nil).expect(200).json(&rb)
	if len(rb.Routes) != 1 || !rb.Proxy.Reachable || !rb.Proxy.InSync || rb.Proxy.Error != "" {
		t.Fatalf("after delete %+v", rb)
	}

	// Publishing or changing a route needs a recent strong authentication (AT-F09-04).
	h.clock.Advance(11 * time.Minute)
	for _, c := range []struct {
		method, path string
		body         any
	}{
		{"POST", "/api/v1/network/routes", map[string]any{"host": "y.lan", "upstream_port": 9000}},
		{"PUT", "/api/v1/network/routes/" + itoa(media.ID), map[string]any{"host": "media.lan", "upstream_port": 8096}},
		{"DELETE", "/api/v1/network/routes/" + itoa(media.ID), nil},
	} {
		if r := owner.do(c.method, c.path, c.body); r.Code != 403 || r.errorCode() != "step_up_required" {
			t.Errorf("%s without step-up: %d", c.method, r.Code)
		}
	}
	owner.do("POST", "/api/v1/network/apply", nil).expect(200)
	if auditCount(t, h, "network.route_create", "success") != 2 || auditCount(t, h, "network.route_update", "success") != 1 ||
		auditCount(t, h, "network.route_delete", "success") != 1 || auditCount(t, h, "network.apply", "success") != 1 {
		t.Fatal("route changes not audited")
	}

	// Caddy lost its configuration (restart without state): reconcile applies the routes again.
	fake.mu.Lock()
	fake.config = nil
	fake.mu.Unlock()
	if applied, err := h.app.Network.Reconcile(context.Background()); err != nil || !applied {
		t.Fatalf("reconcile: %v %v", applied, err)
	}
	if cfg, _ := fake.state(); !strings.Contains(cfg, `"dial":"127.0.0.1:8096"`) {
		t.Fatalf("not restored: %s", cfg)
	}
	if applied, err := h.app.Network.Reconcile(context.Background()); err != nil || applied {
		t.Fatalf("second reconcile: %v %v", applied, err)
	}

	// The overview comes from the proxy service.
	var ov agentproto.NetworkOverview
	op.do("GET", "/api/v1/network/overview", nil).expect(200).json(&ov)
	if len(ov.Interfaces) == 0 {
		t.Fatalf("overview %+v", ov)
	}
	viewer.do("GET", "/api/v1/network/overview", nil).expect(403)
}

func TestNetworkWithoutProxy(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	if r := owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "a.lan", "upstream_port": 9000}); r.Code != 503 || r.errorCode() != "proxy_unavailable" {
		t.Fatalf("create: %d %s", r.Code, r.Body)
	}
	var rb routesBody
	owner.do("GET", "/api/v1/network/routes", nil).expect(200).json(&rb)
	if rb.Proxy.Configured || len(rb.Routes) != 0 {
		t.Fatalf("%+v", rb)
	}
	owner.do("GET", "/api/v1/network/overview", nil).expect(503)
}

// caddyRequest sends what Caddy sends for a gated route.
func caddyRequest(h *harness, path, host string, route int64, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Host = host
	req.RemoteAddr = "127.0.0.1:50000"
	req.Header.Set(proxy.RouteHeader, itoa(route))
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Uri", "/x?y=1")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.app.Handler.ServeHTTP(rec, req)
	return rec
}

func gateCookie(t *testing.T, rec *httptest.ResponseRecorder, id int64) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == network.CookieName(id) {
			return c
		}
	}
	t.Fatalf("no gate cookie: %d %v", rec.Code, rec.Header())
	return nil
}

// AT-F11-02: the Kernhaven sign-in gate.
func TestProxyGate(t *testing.T) {
	h, _, _ := withProxy(t, false)
	owner := h.setupOwner()
	opID := h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer1", authz.Viewer)
	op, viewer := h.loginAs("operator1"), h.loginAs("viewer1")
	var app, docs, open network.Route
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "app.lan", "upstream_port": 9000, "sso": true, "sso_min_role": "operator"}).expect(201).json(&app)
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "app.lan", "path_prefix": "/docs", "upstream_port": 9001, "sso": true}).expect(201).json(&docs)
	owner.do("POST", "/api/v1/network/routes", map[string]any{"host": "open.lan", "upstream_port": 9002}).expect(201).json(&open)

	// Without a gate cookie Caddy is told to send the browser to the gate page.
	rec := caddyRequest(h, proxy.AuthPath, "app.lan", app.ID)
	want := "https://kernhaven.test/gate?" + url.Values{"rd": {"https://app.lan/x?y=1"}, "route": {itoa(app.ID)}}.Encode()
	if rec.Code != 302 || rec.Header().Get("Location") != want || rec.Header().Get(proxy.UserHeader) != "" {
		t.Fatalf("no cookie: %d %v", rec.Code, rec.Header())
	}
	// Routes named for another host, unknown or ungated routes are refused.
	for name, r := range map[string]*httptest.ResponseRecorder{
		"other host":   caddyRequest(h, proxy.AuthPath, "open.lan", app.ID),
		"unknown":      caddyRequest(h, proxy.AuthPath, "app.lan", 999),
		"not gated":    caddyRequest(h, proxy.AuthPath, "open.lan", open.ID),
		"callback":     caddyRequest(h, proxy.CallbackPath+"?code=x", "open.lan", open.ID),
		"no route hdr": caddyRequest(h, proxy.AuthPath, "app.lan", 0),
	} {
		if r.Code != 403 {
			t.Errorf("%s: %d", name, r.Code)
		}
	}

	// The gate page: role check and no open redirects.
	gate := func(c *client, id int64, rd string) response {
		return c.do("POST", "/api/v1/proxy/gate", map[string]any{"route_id": id, "rd": rd})
	}
	for _, rd := range []string{"https://evil.example/x", "https://app.lan.evil.example/", "http://app.lan/x", "https://u@app.lan/", "javascript:alert(1)",
		"https://app.lan:444/x", "//app.lan/x", "/x", "https://app.lan\\@evil.example/"} {
		if r := gate(owner, app.ID, rd); r.Code != 422 {
			t.Errorf("rd %q: %d", rd, r.Code)
		}
	}
	gate(owner, docs.ID, "https://app.lan/other").expect(422)
	gate(owner, docs.ID, "https://app.lan/docsx").expect(422)
	gate(owner, docs.ID, "https://app.lan/docs/a").expect(200)
	gate(owner, open.ID, "https://open.lan/").expect(404)
	if r := gate(viewer, app.ID, "https://app.lan/"); r.Code != 403 {
		t.Fatalf("viewer below the route's role: %d", r.Code)
	}
	if auditCount(t, h, "proxy.gate", "denied") != 1 {
		t.Fatal("denied gate not audited")
	}

	// Gate → callback on the app's host → cookie → access.
	signIn := func(c *client) *http.Cookie {
		var g struct{ Redirect string }
		gate(c, app.ID, "https://app.lan/x?y=1").expect(200).json(&g)
		u, err := url.Parse(g.Redirect)
		if err != nil || u.Host != "app.lan" || u.Path != proxy.GatePath || u.Query().Get("rd") != "/x?y=1" {
			t.Fatalf("redirect %q", g.Redirect)
		}
		rec := caddyRequest(h, proxy.CallbackPath+"?"+u.RawQuery, "app.lan", app.ID)
		if rec.Code != 302 || rec.Header().Get("Location") != "/x?y=1" {
			t.Fatalf("callback %d %v %s", rec.Code, rec.Header(), rec.Body)
		}
		ck := gateCookie(t, rec, app.ID)
		if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" {
			t.Fatalf("cookie %+v", ck)
		}
		// The code works once.
		if rec := caddyRequest(h, proxy.CallbackPath+"?"+u.RawQuery, "app.lan", app.ID); rec.Code != 400 {
			t.Fatalf("code replay: %d", rec.Code)
		}
		return &http.Cookie{Name: ck.Name, Value: ck.Value}
	}
	ownerCookie := signIn(owner)
	rec = caddyRequest(h, proxy.AuthPath, "app.lan", app.ID, ownerCookie)
	if rec.Code != 200 || rec.Header().Get(proxy.UserHeader) != "owner" {
		t.Fatalf("with cookie: %d %v", rec.Code, rec.Header())
	}
	// The cookie belongs to its route only.
	if rec := caddyRequest(h, proxy.AuthPath, "app.lan", docs.ID, &http.Cookie{Name: network.CookieName(docs.ID), Value: ownerCookie.Value}); rec.Code != 302 {
		t.Fatalf("cookie of another route: %d", rec.Code)
	}

	// Codes are bound to their route and expire after 60 s.
	var g struct{ Redirect string }
	gate(owner, app.ID, "https://app.lan/").expect(200).json(&g)
	u, _ := url.Parse(g.Redirect)
	if rec := caddyRequest(h, proxy.CallbackPath+"?"+u.RawQuery, "app.lan", docs.ID); rec.Code != 400 {
		t.Fatalf("code on another route: %d", rec.Code)
	}
	gate(owner, app.ID, "https://app.lan/").expect(200).json(&g)
	u, _ = url.Parse(g.Redirect)
	h.clock.Advance(61 * time.Second)
	if rec := caddyRequest(h, proxy.CallbackPath+"?"+u.RawQuery, "app.lan", app.ID); rec.Code != 400 {
		t.Fatalf("expired code: %d", rec.Code)
	}
	// A foreign return path in the callback falls back to the route.
	gate(owner, app.ID, "https://app.lan/").expect(200).json(&g)
	u, _ = url.Parse(g.Redirect)
	q := u.Query()
	q.Set("rd", "//evil.example/")
	if rec := caddyRequest(h, proxy.CallbackPath+"?"+q.Encode(), "app.lan", app.ID); rec.Code != 302 || rec.Header().Get("Location") != "/" {
		t.Fatalf("foreign rd: %d %v", rec.Code, rec.Header())
	}

	// A role change ends the operator's sessions and with them the app access.
	opCookie := signIn(op)
	if rec := caddyRequest(h, proxy.AuthPath, "app.lan", app.ID, opCookie); rec.Code != 200 || rec.Header().Get(proxy.UserHeader) != "operator1" {
		t.Fatalf("operator: %d", rec.Code)
	}
	// Raising the route's minimum role locks the operator out at once.
	appIn := map[string]any{"host": "app.lan", "upstream_port": 9000, "sso": true, "sso_min_role": "admin"}
	owner.do("PUT", "/api/v1/network/routes/"+itoa(app.ID), appIn).expect(200)
	if rec := caddyRequest(h, proxy.AuthPath, "app.lan", app.ID, opCookie); rec.Code != 302 {
		t.Fatalf("operator after raising the role: %d", rec.Code)
	}
	appIn["sso_min_role"] = "operator"
	owner.do("PUT", "/api/v1/network/routes/"+itoa(app.ID), appIn).expect(200)
	if rec := caddyRequest(h, proxy.AuthPath, "app.lan", app.ID, opCookie); rec.Code != 200 {
		t.Fatalf("operator after lowering the role: %d", rec.Code)
	}
	owner.do("PATCH", "/api/v1/users/"+itoa(opID), map[string]any{"role": "viewer"}).expect(200)
	if rec := caddyRequest(h, proxy.AuthPath, "app.lan", app.ID, opCookie); rec.Code != 302 {
		t.Fatalf("after role change: %d", rec.Code)
	}
	// Signing out of Kernhaven ends it too.
	owner.do("POST", "/api/v1/auth/logout", nil).expect(204)
	if rec := caddyRequest(h, proxy.AuthPath, "app.lan", app.ID, ownerCookie); rec.Code != 302 {
		t.Fatalf("after logout: %d", rec.Code)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM proxy_gate_sessions`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("gate sessions left: %d %v", n, err)
	}
	// An expired Kernhaven session does not open the app.
	owner = h.loginAs("owner")
	ownerCookie = signIn(owner)
	h.clock.Advance(31 * time.Minute)
	if rec := caddyRequest(h, proxy.AuthPath, "app.lan", app.ID, ownerCookie); rec.Code != 302 {
		t.Fatalf("after idle timeout: %d", rec.Code)
	}
	if auditCount(t, h, "proxy.gate", "success") < 5 {
		t.Fatal("gate not audited")
	}
}

// AT-F05-01: installing an app with a web address creates its route.
func TestAppRoute(t *testing.T) {
	h, fake, _ := withProxy(t, true)
	owner := h.setupOwner()
	h.startJobs()
	_, src := storeWithNotes(t, h, owner)

	// An invalid address is refused before anything is installed.
	if r := owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes", "route": map[string]any{"host": "kernhaven.test"}}); r.Code != 422 {
		t.Fatalf("kernhaven host: %d", r.Code)
	}
	owner.do("GET", "/api/v1/apps/notes", nil).expect(404)

	var res struct {
		JobID      int64 `json:"job_id"`
		Route      network.Route
		RouteError string `json:"route_error"`
	}
	r := owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes", "route": map[string]any{"host": "notes.lan", "lan_only": true}})
	r.expect(202).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	if res.RouteError != "" || res.Route.UpstreamPort != 18080 || res.Route.App != "notes" || !res.Route.LANOnly || res.Route.URL != "https://notes.lan/" {
		t.Fatalf("install route %+v", res)
	}
	var app struct{ URL string }
	owner.do("GET", "/api/v1/apps/notes", nil).expect(200).json(&app)
	if app.URL != "https://notes.lan/" {
		t.Fatalf("app url %q", app.URL)
	}
	// A new web port moves the app's routes.
	if err := h.app.Network.MoveAppRoutes(context.Background(), network.Actor{Name: "test"}, "notes", 18081); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := fake.state(); !strings.Contains(cfg, `"dial":"127.0.0.1:18081"`) {
		t.Fatalf("not moved: %s", cfg)
	}
	// Removing the app removes its route.
	var rm appJob
	owner.do("POST", "/api/v1/apps/notes/remove", map[string]any{}).expect(202).json(&rm)
	h.waitJob(rm.JobID, jobs.Succeeded)
	var rb routesBody
	owner.do("GET", "/api/v1/network/routes", nil).expect(200).json(&rb)
	if len(rb.Routes) != 0 {
		t.Fatalf("route left: %+v", rb.Routes)
	}
	// If Caddy refuses, the app is installed anyway and the error reported.
	fake.set("listen tcp :443: bind: address already in use")
	r = owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes", "route": map[string]any{"host": "notes.lan"}})
	r.expect(202).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	if !strings.Contains(res.RouteError, "address already in use") {
		t.Fatalf("route error %q", res.RouteError)
	}
	// Installing with a web address needs step-up.
	fake.set("")
	h.clock.Advance(11 * time.Minute)
	if r := owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes", "name": "notes2", "route": map[string]any{"host": "n2.lan"}}); r.errorCode() != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.Code, r.Body)
	}
}
