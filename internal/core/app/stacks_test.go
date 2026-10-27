package app

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
)

const stackV1 = `services:
  web:
    image: nginx:1.27
    user: "101"
    mem_limit: 128m
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
      MODE: ${MODE:-prod}
    volumes: [data:/data]
    depends_on: [db]
  db:
    image: postgres:16
    user: "999"
    mem_limit: 256m
volumes:
  data:
`

const secretValue = "Sup3r-S3cret-Passw0rd-for-test"

type stackEval struct {
	Valid      bool
	Deployable bool
	Errors     []struct {
		Line    int
		Message string
	}
	Services []struct {
		Service    string
		Violations []struct{ Rule string }
	}
}

type stackDetail struct {
	Stack     stacks.Stack
	Latest    stacks.Revision
	Variables []stacks.Variable
	Services  []stacks.ServiceState
}

func createStack(t *testing.T, c *client) {
	t.Helper()
	c.do("POST", "/api/v1/stacks", map[string]any{
		"name": "shop", "compose": stackV1, "comment": "initial",
		"variables": []map[string]any{{"name": "DB_PASSWORD", "value": secretValue, "secret": true}},
	}).expect(201)
}

// AT-F03-02, AT-F03-03: validation with line numbers and per-service policy.
func TestStackValidation(t *testing.T) {
	h, _ := withAgent(t)
	owner := h.setupOwner()
	var ev stackEval
	owner.do("POST", "/api/v1/stacks/validate", map[string]any{"name": "shop", "compose": "services:\n  web:\n    image: x\n    build: .\n"}).expect(200).json(&ev)
	if ev.Valid || len(ev.Errors) != 1 || ev.Errors[0].Line != 4 || !strings.Contains(ev.Errors[0].Message, "building images") {
		t.Fatalf("evaluation %+v", ev)
	}
	priv := "services:\n  vpn:\n    image: wireguard:1\n    cap_add: [NET_ADMIN]\n"
	owner.do("POST", "/api/v1/stacks/validate", map[string]any{"name": "vpn", "compose": priv}).expect(200).json(&ev)
	if !ev.Valid || ev.Deployable || len(ev.Services) != 1 || ev.Services[0].Violations[0].Rule != "capability" {
		t.Fatalf("policy evaluation %+v", ev)
	}
	exc := []map[string]string{{"service": "vpn", "rule": "capability", "reason": "WireGuard needs NET_ADMIN"}}
	owner.do("POST", "/api/v1/stacks/validate", map[string]any{"name": "vpn", "compose": priv, "exceptions": exc}).expect(200).json(&ev)
	if !ev.Deployable {
		t.Fatal("exception not applied in validation")
	}
	// Creating requires deployability; only owners approve.
	h.createUser(owner, "adele", authz.Admin)
	admin := h.loginAs("adele")
	if r := admin.do("POST", "/api/v1/stacks", map[string]any{"name": "vpn", "compose": priv}); r.Code != 422 || r.errorCode() != "policy_violation" {
		t.Fatalf("uncovered violation: %d %s", r.Code, r.Body)
	}
	if r := admin.do("POST", "/api/v1/stacks", map[string]any{"name": "vpn", "compose": priv, "exceptions": exc}); r.Code != 403 {
		t.Fatalf("admin approved: %d", r.Code)
	}
	owner.do("POST", "/api/v1/stacks", map[string]any{"name": "vpn", "compose": priv, "exceptions": exc}).expect(201)
	if auditCount(t, h, "policy.exception", "success") != 1 {
		t.Fatal("exception not audited")
	}
	// The admin may carry an existing exception into a new revision, but not add new ones.
	admin.do("POST", "/api/v1/stacks/vpn/revisions", map[string]any{"compose": priv, "exceptions": exc, "comment": "same"}).expect(201)
	priv2 := priv + "    privileged: true\n"
	exc2 := append(exc, map[string]string{"service": "vpn", "rule": "privileged", "reason": "kernel module loading"})
	if r := admin.do("POST", "/api/v1/stacks/vpn/revisions", map[string]any{"compose": priv2, "exceptions": exc2}); r.Code != 403 {
		t.Fatalf("admin added an exception: %d", r.Code)
	}
}

// AT-F03-06: secrets are encrypted at rest and never returned.
func TestStackSecrets(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	createStack(t, owner)
	var d stackDetail
	owner.do("GET", "/api/v1/stacks/shop", nil).expect(200).json(&d)
	if len(d.Variables) != 1 || !d.Variables[0].Secret || d.Variables[0].Value != "" {
		t.Fatalf("variables %+v", d.Variables)
	}
	if strings.Contains(owner.do("GET", "/api/v1/stacks/shop", nil).Body.String(), secretValue) {
		t.Fatal("secret returned by the API")
	}
	// Not in the database files (including the WAL).
	for _, f := range []string{"kernhaven.db", "kernhaven.db-wal"} {
		b, _ := os.ReadFile(filepath.Join(h.dataDir, f))
		if bytes.Contains(b, []byte(secretValue)) {
			t.Fatalf("secret in plaintext in %s", f)
		}
	}
	// Replacing variables: a secret without a value keeps it; a plain variable is returned.
	owner.do("PUT", "/api/v1/stacks/shop/variables", map[string]any{"variables": []map[string]any{
		{"name": "DB_PASSWORD", "secret": true}, {"name": "MODE", "value": "staging", "secret": false},
	}}).expect(204)
	owner.do("GET", "/api/v1/stacks/shop", nil).expect(200).json(&d)
	if len(d.Variables) != 2 || d.Variables[0].Name != "DB_PASSWORD" || d.Variables[1].Value != "staging" {
		t.Fatalf("variables %+v", d.Variables)
	}
	// The secret reaches the container.
	h.startJobs()
	var job struct {
		JobID int64 `json:"job_id"`
	}
	owner.do("POST", "/api/v1/stacks/shop/deploy", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	md.mu.Lock()
	env := md.specs["shop-web"].Env
	md.mu.Unlock()
	found := false
	for _, e := range env {
		found = found || (e.Name == "DB_PASSWORD" && e.Value == secretValue)
	}
	if !found {
		t.Fatalf("secret not rendered into the container: %+v", env)
	}
	if r := owner.do("PUT", "/api/v1/stacks/shop/variables", map[string]any{"variables": []map[string]any{{"name": "NEW", "secret": true}}}); r.Code != 422 {
		t.Fatalf("secret without value accepted: %d", r.Code)
	}
}

// AT-F03-04, AT-F03-05: revisions, deploy, update, rollback, down.
func TestStackLifecycleAndRollback(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	h.app.Stacks.VerifyTimeout = 5 * time.Second
	h.startJobs()
	createStack(t, owner)
	deploy := func() jobs.Job {
		var res struct {
			JobID int64 `json:"job_id"`
		}
		owner.do("POST", "/api/v1/stacks/shop/deploy", nil).expect(202).json(&res)
		deadline := time.Now().Add(10 * time.Second)
		for {
			j, _ := h.app.Jobs.Get(context.Background(), res.JobID)
			if j.State.Terminal() || time.Now().After(deadline) {
				return j
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	state := func() stackDetail {
		var d stackDetail
		owner.do("GET", "/api/v1/stacks/shop", nil).expect(200).json(&d)
		return d
	}

	if j := deploy(); j.State != jobs.Succeeded {
		t.Fatalf("deploy 1: %s %s", j.State, j.Error)
	}
	d := state()
	if d.Stack.Status != "deployed" || d.Stack.DeployedRevision != 1 || len(d.Services) != 2 {
		t.Fatalf("after deploy 1: %+v", d)
	}
	md.mu.Lock()
	if md.labels["shop-web"]["io.kernhaven.stack.revision"] != "1" || md.networks["shop_default"]["io.kernhaven.stack"] != "shop" || !md.volumes["shop_data"] {
		t.Fatalf("labels/network/volume: %v %v %v", md.labels["shop-web"], md.networks, md.volumes)
	}
	md.mu.Unlock()

	// Revision 2: change the web image; deploy replaces the containers.
	v2 := strings.Replace(stackV1, "nginx:1.27", "nginx:1.28", 1)
	owner.do("POST", "/api/v1/stacks/shop/revisions", map[string]any{"compose": v2, "comment": "upgrade nginx"}).expect(201)
	if j := deploy(); j.State != jobs.Succeeded {
		t.Fatalf("deploy 2: %s %s", j.State, j.Error)
	}
	if d := state(); d.Stack.DeployedRevision != 2 || d.Latest.Number != 2 {
		t.Fatalf("after deploy 2: %+v", d.Stack)
	}
	md.mu.Lock()
	if md.specs["shop-web"].Image != "nginx:1.28" || md.labels["shop-web"]["io.kernhaven.stack.revision"] != "2" {
		t.Fatalf("web not updated: %v", md.labels["shop-web"])
	}
	md.mu.Unlock()

	// Revision 3 adds a service that exits: the deployment fails and rolls back to 2.
	v3 := v2 + "  worker:\n    image: busybox-exits:1\n    user: \"1\"\n    mem_limit: 32m\n"
	v3 = strings.Replace(v3, "volumes:\n  data:\n", "", 1) + "volumes:\n  data:\n"
	owner.do("POST", "/api/v1/stacks/shop/revisions", map[string]any{"compose": v3, "comment": "add worker"}).expect(201)
	j := deploy()
	if j.State != jobs.Failed || !strings.Contains(j.Error, "worker exited") {
		t.Fatalf("deploy 3: %s %q", j.State, j.Error)
	}
	d = state()
	if d.Stack.Status != "failed" || d.Stack.DeployedRevision != 2 || !strings.Contains(d.Stack.StatusMessage, "rolled back to revision 2") {
		t.Fatalf("after failed deploy: %+v", d.Stack)
	}
	md.mu.Lock()
	_, workerLeft := md.containers["shop-worker"]
	webRev := md.labels["shop-web"]["io.kernhaven.stack.revision"]
	webState := md.containers["shop-web"].State
	md.mu.Unlock()
	if workerLeft || webRev != "2" || webState != "running" {
		t.Fatalf("rollback incomplete: worker left=%v web rev=%s state=%s", workerLeft, webRev, webState)
	}

	// Revisions are immutable.
	if _, err := h.db.Exec(`UPDATE stack_revisions SET compose = 'x'`); err == nil || !strings.Contains(err.Error(), "immutable") {
		t.Fatalf("revision update: %v", err)
	}
	var revs struct{ Revisions []stacks.Revision }
	owner.do("GET", "/api/v1/stacks/shop/revisions", nil).expect(200).json(&revs)
	if len(revs.Revisions) != 3 || revs.Revisions[0].Comment != "add worker" {
		t.Fatalf("revisions %+v", revs)
	}
	owner.do("GET", "/api/v1/stacks/shop/revisions/1", nil).expect(200)

	// Deleting a deployed stack is refused; down then delete works.
	if r := owner.do("DELETE", "/api/v1/stacks/shop", nil); r.Code != 409 {
		t.Fatalf("delete deployed: %d", r.Code)
	}
	var res struct {
		JobID int64 `json:"job_id"`
	}
	owner.do("POST", "/api/v1/stacks/shop/down", nil).expect(202).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	md.mu.Lock()
	left, netLeft, volKept := len(md.containers), len(md.networks), md.volumes["shop_data"]
	md.mu.Unlock()
	if left != 0 || netLeft != 0 || !volKept {
		t.Fatalf("after down: containers=%d networks=%d volume kept=%v", left, netLeft, volKept)
	}
	if d := state(); d.Stack.Status != "stopped" || d.Stack.DeployedRevision != 0 {
		t.Fatalf("after down: %+v", d.Stack)
	}
	owner.do("DELETE", "/api/v1/stacks/shop", nil).expect(204)
	for _, a := range []string{"stack.create", "stack.revision", "stack.deploy", "stack.down", "stack.delete"} {
		if auditCount(t, h, a, "success") == 0 {
			t.Errorf("%s not audited", a)
		}
	}
}

// AT-F03-01: URL import is HTTPS-only and never reaches internal addresses.
func TestStackImportURL(t *testing.T) {
	h, _ := withAgent(t)
	owner := h.setupOwner()
	big := strings.Repeat("#", 300<<10)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/compose.yaml":
			w.Write([]byte(stackV1))
		case "/big.yaml":
			w.Write([]byte(big))
		case "/redirect-http":
			http.Redirect(w, r, "http://example.org/x", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	// Default fetcher (public addresses only) refuses the loopback test server.
	for _, u := range []string{srv.URL + "/compose.yaml", "http://example.org/x.yaml", "file:///etc/passwd", "https://user:pw@example.org/"} {
		if r := owner.do("POST", "/api/v1/stacks/import-url", map[string]string{"url": u}); r.Code != 422 || r.errorCode() != "url_blocked" {
			t.Errorf("%s: %d %s", u, r.Code, r.Body)
		}
	}
	// A fetcher that trusts the test server's address and certificate.
	f := stacks.NewFetcher(func(ip net.IP) bool { return ip.IsLoopback() }, srv.Client().Transport.(*http.Transport))
	content, err := f.Fetch(context.Background(), srv.URL+"/compose.yaml")
	if err != nil || content != stackV1 {
		t.Fatalf("fetch: %v", err)
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"/big.yaml"); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("size limit: %v", err)
	}
	if _, err := f.Fetch(context.Background(), srv.URL+"/redirect-http"); err == nil {
		t.Fatal("redirect to http followed")
	}
	for _, ip := range []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fd00::1", "fe80::1"} {
		if stacks.PublicIP(net.ParseIP(ip)) {
			t.Errorf("%s treated as public", ip)
		}
	}
	if !stacks.PublicIP(net.ParseIP("93.184.216.34")) {
		t.Error("public address refused")
	}
}
