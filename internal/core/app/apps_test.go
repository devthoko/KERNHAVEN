package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/catalog"
	"github.com/devthoko/KERNHAVEN/internal/core/apps"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
)

func notesCompose(image string) string {
	return `services:
  app:
    image: ` + image + `
    user: "1000"
    mem_limit: 64m
    ports: ["${PORT}:8080"]
    environment:
      ADMIN_PASSWORD: ${ADMIN_PASSWORD}
      TITLE: ${TITLE}
    volumes: [data:/data]
volumes:
  data:
`
}

func notesApp(version, image string) catalog.App {
	min := int64(1024)
	return catalog.App{ID: "notes", Name: "Notes", Version: version, Summary: "A small notes app", Categories: []string{"Productivity"},
		Compose: notesCompose(image), Web: &catalog.Web{Service: "app", Port: 8080},
		Fields: []catalog.Field{
			{Name: "PORT", Label: "Port", Type: catalog.TypeNumber, Default: "18080", Min: &min, Required: true},
			{Name: "TITLE", Label: "Title", Type: catalog.TypeText, Default: "Notes"},
			{Name: "ADMIN_PASSWORD", Label: "Admin password", Type: catalog.TypePassword, Generate: catalog.GeneratePassword, Required: true},
		}}
}

var vpnApp = catalog.App{ID: "vpn", Name: "VPN", Version: "1", Summary: "WireGuard server", Categories: []string{"Network"},
	Compose:    "services:\n  wg:\n    image: kernhaven/wireguard:1\n    user: \"1000\"\n    mem_limit: 64m\n    cap_add: [NET_ADMIN]\n",
	Exceptions: []catalog.Exception{{Service: "wg", Rule: "capability", Reason: "WireGuard configures network interfaces"}}}

var socketApp = catalog.App{ID: "dashboard", Name: "Docker dashboard", Version: "1", Summary: "Wants the Docker socket", Categories: []string{"Tools"},
	Compose:    "services:\n  ui:\n    image: kernhaven/dash:1\n    user: \"1000\"\n    mem_limit: 64m\n    volumes: [\"/var/run/docker.sock:/var/run/docker.sock\"]\n",
	Exceptions: []catalog.Exception{{Service: "ui", Rule: "bind-mount", Reason: "reads the container list from Docker"}}}

type signer struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{pub, priv}
}

func (s signer) key() string { return base64.StdEncoding.EncodeToString(s.pub) }

func (s signer) sign(t *testing.T, serial int64, list ...catalog.App) []byte {
	t.Helper()
	b, err := catalog.Sign(s.priv, catalog.Catalog{Name: "Test", Serial: serial, Expires: time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), Apps: list})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// upload posts a raw signed catalog.
func upload(c *client, id int64, data []byte) response {
	return c.do("POST", "/api/v1/catalog/sources/"+itoa(id)+"/upload", json.RawMessage(data))
}

func addSource(t *testing.T, c *client, name, url, key string) apps.Source {
	t.Helper()
	var src apps.Source
	c.do("POST", "/api/v1/catalog/sources", map[string]string{"name": name, "url": url, "public_key": key}).expect(201).json(&src)
	return src
}

type appJob struct {
	App   apps.App `json:"app"`
	JobID int64    `json:"job_id"`
}

type appDetail struct {
	apps.App
	Versions []apps.Version
	Config   []stacks.Variable
	Update   *apps.UpdatePreview
}

func storeWithNotes(t *testing.T, h *harness, owner *client) (signer, apps.Source) {
	t.Helper()
	s := newSigner(t)
	src := addSource(t, owner, "Test", "", s.key())
	upload(owner, src.ID, s.sign(t, 1, notesApp("1.0", "kernhaven/notes:1"), vpnApp, socketApp)).expect(200)
	return s, src
}

// AT-F04-01, AT-F04-03: signed catalogs per source; everything else is rejected.
func TestCatalogSources(t *testing.T) {
	srv := httptest.NewTLSServer(nil)
	defer srv.Close()
	h, _ := withAgentOpts(t, func(o *Options) {
		o.Fetcher = stacks.NewFetcher(func(ip net.IP) bool { return ip.IsLoopback() }, srv.Client().Transport.(*http.Transport))
	})
	owner := h.setupOwner()
	h.createUser(owner, "admin", authz.Admin)
	admin := h.loginAs("admin")
	h.createUser(owner, "viewer", authz.Viewer)
	viewer := h.loginAs("viewer")
	a, b := newSigner(t), newSigner(t)

	if r := admin.do("POST", "/api/v1/catalog/sources", map[string]string{"name": "x", "public_key": a.key()}); r.Code != 403 {
		t.Fatalf("admin added a source: %d", r.Code)
	}
	for _, bad := range []map[string]string{
		{"name": "x", "public_key": "not a key"},
		{"name": "x", "public_key": a.key(), "url": "http://example.org/catalog.json"},
		{"name": "", "public_key": a.key()},
	} {
		if r := owner.do("POST", "/api/v1/catalog/sources", bad); r.Code != 422 {
			t.Errorf("%v: %d", bad, r.Code)
		}
	}
	srcA := addSource(t, owner, "Source A", "", a.key())
	srcB := addSource(t, owner, "Source B", "", b.key())
	if r := owner.do("POST", "/api/v1/catalog/sources", map[string]string{"name": "Source A", "public_key": a.key()}); r.Code != 409 {
		t.Fatalf("duplicate name: %d", r.Code)
	}

	var got apps.Source
	upload(owner, srcA.ID, a.sign(t, 5, notesApp("1.0", "kernhaven/notes:1"))).expect(200).json(&got)
	if got.Serial != 5 || got.AppCount != 1 || got.LastError != "" || got.KeyID != catalog.KeyID(a.pub) {
		t.Fatalf("accepted source %+v", got)
	}
	// Key A's catalog is not valid for source B; older serials are rejected.
	if r := upload(owner, srcB.ID, a.sign(t, 1, vpnApp)); r.Code != 422 || r.errorCode() != "catalog_rejected" {
		t.Fatalf("foreign key: %d %s", r.Code, r.Body)
	}
	if r := upload(owner, srcA.ID, a.sign(t, 4, vpnApp)); r.Code != 422 || !strings.Contains(r.Body.String(), "older") {
		t.Fatalf("rollback: %d %s", r.Code, r.Body)
	}
	tampered := bytes.Replace(a.sign(t, 6, vpnApp), []byte(`"signature": "`), []byte(`"signature": "AA`), 1)
	if r := upload(owner, srcA.ID, tampered); r.Code != 422 {
		t.Fatalf("tampered: %d", r.Code)
	}
	var list struct{ Sources []apps.Source }
	viewer.do("GET", "/api/v1/catalog/sources", nil).expect(200).json(&list)
	if len(list.Sources) != 2 || list.Sources[0].Serial != 5 || list.Sources[0].AppCount != 1 || list.Sources[0].LastError == "" {
		t.Fatalf("sources after rejections %+v", list.Sources)
	}
	if n := auditCount(t, h, "catalog.sync", "failure"); n != 3 {
		t.Fatalf("rejected syncs audited: %d", n)
	}
	if r := viewer.do("POST", "/api/v1/catalog/sources/"+itoa(srcA.ID)+"/upload", json.RawMessage(a.sign(t, 7))); r.Code != 403 {
		t.Fatalf("viewer upload: %d", r.Code)
	}

	// URL source: download through the SSRF-safe fetcher.
	signed := b.sign(t, 2, vpnApp)
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(signed) })
	srcC := addSource(t, owner, "Remote", srv.URL+"/catalog.json", b.key())
	owner.do("POST", "/api/v1/catalog/sources/"+itoa(srcC.ID)+"/sync", nil).expect(200).json(&got)
	if got.Serial != 2 || got.AppCount != 1 {
		t.Fatalf("synced %+v", got)
	}
	if r := owner.do("POST", "/api/v1/catalog/sources/"+itoa(srcB.ID)+"/sync", nil); r.Code != 422 {
		t.Fatalf("sync without URL: %d", r.Code)
	}
	owner.do("DELETE", "/api/v1/catalog/sources/"+itoa(srcC.ID), nil).expect(204)
	viewer.do("GET", "/api/v1/catalog/sources", nil).expect(200).json(&list)
	if len(list.Sources) != 2 {
		t.Fatalf("after delete %+v", list.Sources)
	}
}

// AT-F04-02, AT-F04-04: browse, search and the disclosure Kernhaven computes.
func TestCatalogBrowseAndDisclosure(t *testing.T) {
	h, _ := withAgent(t)
	owner := h.setupOwner()
	_, src := storeWithNotes(t, h, owner)
	h.createUser(owner, "viewer", authz.Viewer)
	viewer := h.loginAs("viewer")

	var res struct {
		Apps       []apps.Listing
		Categories []string
	}
	viewer.do("GET", "/api/v1/catalog/apps", nil).expect(200).json(&res)
	if len(res.Apps) != 3 || strings.Join(res.Categories, ",") != "Network,Productivity,Tools" {
		t.Fatalf("all apps %+v %v", res.Apps, res.Categories)
	}
	viewer.do("GET", "/api/v1/catalog/apps?q=wireguard", nil).expect(200).json(&res)
	if len(res.Apps) != 1 || res.Apps[0].AppID != "vpn" {
		t.Fatalf("search %+v", res.Apps)
	}
	viewer.do("GET", "/api/v1/catalog/apps?category=Productivity", nil).expect(200).json(&res)
	if len(res.Apps) != 1 || res.Apps[0].AppID != "notes" {
		t.Fatalf("category %+v", res.Apps)
	}

	var d apps.Detail
	viewer.do("GET", "/api/v1/catalog/apps/"+itoa(src.ID)+"/notes", nil).expect(200).json(&d)
	sd := d.Disclosure.Services
	if !d.Disclosure.Installable || d.Disclosure.NeedsApproval || len(sd) != 1 || sd[0].ImagePinned ||
		len(sd[0].Ports) != 1 || !strings.Contains(sd[0].Ports[0], "18080 → 8080/tcp") || len(sd[0].Volumes) != 1 || len(d.App.Fields) != 3 {
		t.Fatalf("notes disclosure %+v", d)
	}
	viewer.do("GET", "/api/v1/catalog/apps/"+itoa(src.ID)+"/vpn", nil).expect(200).json(&d)
	if !d.Disclosure.Installable || !d.Disclosure.NeedsApproval || d.Disclosure.Services[0].Capabilities[0] != "NET_ADMIN" ||
		len(d.Disclosure.Services[0].Exceptions) != 1 {
		t.Fatalf("vpn disclosure %+v", d.Disclosure)
	}
	viewer.do("GET", "/api/v1/catalog/apps/"+itoa(src.ID)+"/dashboard", nil).expect(200).json(&d)
	if d.Disclosure.Installable || len(d.Disclosure.Problems) == 0 || !strings.Contains(d.Disclosure.Problems[0], "never allowed") ||
		len(d.Disclosure.Services[0].BindMounts) != 1 {
		t.Fatalf("socket disclosure %+v", d.Disclosure)
	}
	viewer.do("GET", "/api/v1/catalog/apps/"+itoa(src.ID)+"/missing", nil).expect(404)
}

func waitApp(t *testing.T, h *harness, r response, want jobs.State) appJob {
	t.Helper()
	var res appJob
	r.expect(202).json(&res)
	h.waitJob(res.JobID, want)
	return res
}

func secretInFiles(t *testing.T, h *harness, value string) bool {
	t.Helper()
	for _, f := range []string{"kernhaven.db", "kernhaven.db-wal"} {
		b, err := os.ReadFile(filepath.Join(h.dataDir, f))
		if err == nil && bytes.Contains(b, []byte(value)) {
			return true
		}
	}
	return false
}

// AT-F05-01: install with form values, generated secrets and health check;
// apps' stacks cannot be changed through the stack API.
func TestAppInstall(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	h.startJobs()
	_, src := storeWithNotes(t, h, owner)
	h.createUser(owner, "admin", authz.Admin)
	admin := h.loginAs("admin")

	bad := []map[string]any{
		{"source_id": src.ID, "app_id": "notes", "values": map[string]string{"PORT": "80"}},
		{"source_id": src.ID, "app_id": "notes", "values": map[string]string{"SHELL": "x"}},
		{"source_id": src.ID, "app_id": "notes", "values": map[string]string{"ADMIN_PASSWORD": "short"}},
		{"source_id": src.ID, "app_id": "notes", "name": "Bad Name"},
		{"source_id": src.ID, "app_id": "dashboard"},
	}
	for _, in := range bad {
		if r := admin.do("POST", "/api/v1/apps", in); r.Code != 422 {
			t.Errorf("%v: %d %s", in, r.Code, r.Body)
		}
	}
	res := waitApp(t, h, admin.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes",
		"values": map[string]string{"TITLE": "Family notes"}}), jobs.Succeeded)
	if res.App.Name != "notes" || res.App.AppName != "Notes" {
		t.Fatalf("install result %+v", res.App)
	}
	var d appDetail
	admin.do("GET", "/api/v1/apps/notes", nil).expect(200).json(&d)
	if d.Status != "deployed" || d.Version != "1.0" || d.WebPort != 18080 || d.UpdateAvailable || len(d.Versions) != 1 || !d.Versions[0].Deployed {
		t.Fatalf("installed app %+v", d)
	}
	md.mu.Lock()
	env := map[string]string{}
	for _, e := range md.specs["notes-app"].Env {
		env[e.Name] = e.Value
	}
	md.mu.Unlock()
	generated := env["ADMIN_PASSWORD"]
	if env["TITLE"] != "Family notes" || len(generated) != 32 {
		t.Fatalf("container env %v", env)
	}
	for _, v := range d.Config {
		if v.Name == "ADMIN_PASSWORD" && (!v.Secret || v.Value != "") {
			t.Fatalf("secret exposed: %+v", v)
		}
	}
	if secretInFiles(t, h, generated) {
		t.Fatal("generated secret stored in plain text")
	}

	// The app's stack is read-only through the stack API.
	for _, r := range []response{
		owner.do("POST", "/api/v1/stacks/notes/revisions", map[string]any{"compose": notesCompose("evil:1")}),
		owner.do("PUT", "/api/v1/stacks/notes/variables", map[string]any{"variables": []any{}}),
		owner.do("POST", "/api/v1/stacks/notes/deploy", nil),
		owner.do("POST", "/api/v1/stacks/notes/down", nil),
		owner.do("DELETE", "/api/v1/stacks/notes", nil),
	} {
		if r.Code != 409 {
			t.Errorf("managed stack changed: %d %s", r.Code, r.Body)
		}
	}
	// Same name twice.
	if r := admin.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes", "values": map[string]string{"PORT": "18081"}}); r.Code != 409 {
		t.Fatalf("duplicate name: %d", r.Code)
	}

	// Exceptions: admins cannot approve, owners must approve explicitly.
	if r := admin.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "vpn", "approve_exceptions": true}); r.Code != 403 || r.errorCode() != "approval_required" {
		t.Fatalf("admin approval: %d %s", r.Code, r.Body)
	}
	if r := owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "vpn"}); r.Code != 403 {
		t.Fatalf("owner without approval: %d", r.Code)
	}
	waitApp(t, h, owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "vpn", "approve_exceptions": true}), jobs.Succeeded)
	var rev stacks.Revision
	owner.do("GET", "/api/v1/stacks/vpn/revisions/1", nil).expect(200).json(&rev)
	if len(rev.Exceptions) != 1 || rev.Exceptions[0].Rule != "capability" || !strings.HasPrefix(rev.Exceptions[0].Reason, "catalog: ") || rev.Exceptions[0].ApprovedBy != "owner" {
		t.Fatalf("exceptions on the revision %+v", rev.Exceptions)
	}
	if auditCount(t, h, "app.install", "success") != 2 || auditCount(t, h, "policy.exception", "success") != 1 {
		t.Fatal("install or exception not audited")
	}
	var list struct{ Apps []apps.App }
	admin.do("GET", "/api/v1/apps", nil).expect(200).json(&list)
	if len(list.Apps) != 2 {
		t.Fatalf("apps %+v", list.Apps)
	}
}

// AT-F05-02: a failed update restores the data and the previous version;
// a good update keeps the new data.
func TestAppUpdateRollback(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	h.app.Stacks.VerifyTimeout = 2 * time.Second
	h.startJobs()
	s, src := storeWithNotes(t, h, owner)
	waitApp(t, h, owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes"}), jobs.Succeeded)
	md.mu.Lock()
	md.data["notes_data"] = "user data of 1.0"
	md.mu.Unlock()

	broken := notesApp("2.0", "kernhaven/notes-migrate-exits:2")
	broken.Fields = append(broken.Fields, catalog.Field{Name: "THEME", Label: "Theme", Type: catalog.TypeSelect, Options: []string{"light", "dark"}, Default: "light"})
	broken.Compose = strings.Replace(broken.Compose, "      TITLE: ${TITLE}\n", "      TITLE: ${TITLE}\n      THEME: ${THEME}\n", 1)
	upload(owner, src.ID, s.sign(t, 2, broken)).expect(200)
	var d appDetail
	owner.do("GET", "/api/v1/apps/notes", nil).expect(200).json(&d)
	if !d.UpdateAvailable || d.Update == nil || d.Update.To != "2.0" || len(d.Update.Images) != 1 ||
		d.Update.Images[0].To != "kernhaven/notes-migrate-exits:2" || len(d.Update.NewFields) != 1 {
		t.Fatalf("update preview %+v", d.Update)
	}
	waitApp(t, h, owner.do("POST", "/api/v1/apps/notes/update", map[string]any{"values": map[string]string{"THEME": "dark"}}), jobs.Failed)
	md.mu.Lock()
	data, snap, image := md.data["notes_data"], md.data["notes_data.snapshot"], md.containers["notes-app"].Image
	state := md.containers["notes-app"].State
	helpers := 0
	for name := range md.containers {
		if strings.HasPrefix(name, "kh-volume-copy-") {
			helpers++
		}
	}
	md.mu.Unlock()
	if data != "user data of 1.0" || snap != "user data of 1.0" || image != "kernhaven/notes:1" || state != "running" || helpers != 0 {
		t.Fatalf("after failed update: data=%q snapshot=%q image=%s state=%s helpers=%d", data, snap, image, state, helpers)
	}
	owner.do("GET", "/api/v1/apps/notes", nil).expect(200).json(&d)
	if d.Version != "1.0" || d.Revision != 1 || d.Status != "failed" || !strings.Contains(d.StatusMessage, "rolled back to revision 1") || !d.UpdateAvailable {
		t.Fatalf("app after failed update %+v", d.App)
	}

	// A working update keeps the migrated data.
	good := notesApp("2.1", "kernhaven/notes-migrate:2.1")
	upload(owner, src.ID, s.sign(t, 3, good)).expect(200)
	waitApp(t, h, owner.do("POST", "/api/v1/apps/notes/update", map[string]any{}), jobs.Succeeded)
	owner.do("GET", "/api/v1/apps/notes", nil).expect(200).json(&d)
	md.mu.Lock()
	data = md.data["notes_data"]
	md.mu.Unlock()
	if d.Version != "2.1" || d.UpdateAvailable || len(d.Versions) != 3 || !d.Versions[0].Deployed || data != "migrated by kernhaven/notes-migrate:2.1" {
		t.Fatalf("after good update %+v data=%q", d, data)
	}
	if r := owner.do("POST", "/api/v1/apps/notes/update", map[string]any{}); r.Code != 409 {
		t.Fatalf("update without new version: %d", r.Code)
	}
}

// AT-F05-03: remove with or without data; deleting data needs the password.
func TestAppRemove(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	h.startJobs()
	_, src := storeWithNotes(t, h, owner)
	h.createUser(owner, "viewer", authz.Viewer)
	viewer := h.loginAs("viewer")
	install := func() {
		waitApp(t, h, owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes"}), jobs.Succeeded)
	}
	install()
	md.mu.Lock()
	md.data["notes_data"] = "keep me"
	md.mu.Unlock()
	if r := viewer.do("POST", "/api/v1/apps/notes/remove", map[string]any{}); r.Code != 403 {
		t.Fatalf("viewer removed: %d", r.Code)
	}
	var res appJob
	owner.do("POST", "/api/v1/apps/notes/remove", map[string]any{"delete_data": false}).expect(202).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	owner.do("GET", "/api/v1/apps/notes", nil).expect(404)
	owner.do("GET", "/api/v1/stacks/notes", nil).expect(404)
	md.mu.Lock()
	kept, running := md.data["notes_data"], len(md.containers)
	md.mu.Unlock()
	if kept != "keep me" || running != 0 {
		t.Fatalf("keep data: %q, %d containers", kept, running)
	}

	// Reinstalling under the same name finds the kept data.
	install()
	md.mu.Lock()
	kept = md.data["notes_data"]
	md.mu.Unlock()
	if kept != "keep me" {
		t.Fatalf("reinstall lost data: %q", kept)
	}
	// Deleting data needs a recent strong authentication (AT-F09-04): the
	// sign-in counts for 10 minutes, then the user must confirm again.
	h.clock.Advance(11 * time.Minute)
	if r := owner.do("POST", "/api/v1/apps/notes/remove", map[string]any{"delete_data": true}); r.Code != 403 || r.errorCode() != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.Code, r.Body)
	}
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": "wrong password!"}).expect(401)
	owner.do("GET", "/api/v1/apps/notes", nil).expect(200)
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": strongPassword}).expect(204)
	owner.do("POST", "/api/v1/apps/notes/remove", map[string]any{"delete_data": true}).expect(202).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	md.mu.Lock()
	_, vol := md.volumes["notes_data"]
	md.mu.Unlock()
	if vol {
		t.Fatal("volume kept although data deletion was confirmed")
	}
	if auditCount(t, h, "auth.step_up", "failure") != 1 || auditCount(t, h, "auth.step_up", "success") != 1 || auditCount(t, h, "app.remove", "success") != 2 {
		t.Fatal("step-up or removal not audited")
	}
}

// restartAfterCrash stops the runner hard and leaves the job as a killed
// process would (running, with a lease), then starts a new Core on the same
// database — like systemd restarting kernhaven-core after SIGKILL.
func (h *harness) restartAfterCrash(jobID int64) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	h.app.Runner.Stop(ctx)
	cancel()
	if _, err := h.db.Exec(`UPDATE jobs SET state = 'running', lease_owner = 'killed', lease_expires_ms = ? WHERE id = ?`,
		h.clock.Now().Add(time.Hour).UnixMilli(), jobID); err != nil {
		h.t.Fatal(err)
	}
	a, err := New(h.db, h.cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), h.opts)
	if err != nil {
		h.t.Fatal(err)
	}
	a.Stacks.VerifyTimeout = h.app.Stacks.VerifyTimeout
	h.app = a
	h.startJobs()
}

func waitBlocked(t *testing.T, md *memDocker) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if md.waiting.Load() > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("job did not reach the blocking step")
}

// AT-F05-04: a Core crash during install resumes; during an update it ends
// in a clean rollback with the data restored.
func TestAppInterrupted(t *testing.T) {
	h, md := withAgent(t)
	owner := h.setupOwner()
	h.app.Stacks.VerifyTimeout = 2 * time.Second
	h.startJobs()
	s := newSigner(t)
	src := addSource(t, owner, "Test", "", s.key())
	upload(owner, src.ID, s.sign(t, 1, notesApp("1.0", "kernhaven/notes-block:1"))).expect(200)

	md.mu.Lock()
	md.block = make(chan struct{})
	md.mu.Unlock()
	var res appJob
	owner.do("POST", "/api/v1/apps", map[string]any{"source_id": src.ID, "app_id": "notes"}).expect(202).json(&res)
	waitBlocked(t, md)
	h.restartAfterCrash(res.JobID)
	close(md.block)
	h.waitJob(res.JobID, jobs.Succeeded)
	var d appDetail
	owner.do("GET", "/api/v1/apps/notes", nil).expect(200).json(&d)
	if d.Status != "deployed" || d.Version != "1.0" || !resumed(t, h, res.JobID) {
		t.Fatalf("after resumed install: %+v", d.App)
	}

	md.mu.Lock()
	md.data["notes_data"] = "before update"
	md.block = make(chan struct{})
	md.mu.Unlock()
	upload(owner, src.ID, s.sign(t, 2, notesApp("2.0", "kernhaven/notes-block-migrate-exits:2"))).expect(200)
	owner.do("POST", "/api/v1/apps/notes/update", map[string]any{}).expect(202).json(&res)
	waitBlocked(t, md)
	h.restartAfterCrash(res.JobID)
	close(md.block)
	h.waitJob(res.JobID, jobs.Failed)
	if !resumed(t, h, res.JobID) {
		t.Fatal("update was not resumed after the restart")
	}
	owner.do("GET", "/api/v1/apps/notes", nil).expect(200).json(&d)
	md.mu.Lock()
	data, image, state := md.data["notes_data"], md.containers["notes-app"].Image, md.containers["notes-app"].State
	md.mu.Unlock()
	if d.Version != "1.0" || d.Revision != 1 || data != "before update" || image != "kernhaven/notes-block:1" || state != "running" {
		t.Fatalf("after interrupted update: %+v data=%q image=%s state=%s", d.App, data, image, state)
	}
}

// resumed reports whether the job was picked up again after a restart.
func resumed(t *testing.T, h *harness, jobID int64) bool {
	t.Helper()
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM job_logs WHERE job_id = ? AND message LIKE 'interrupted by a restart%'`, jobID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}
