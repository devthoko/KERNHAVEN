package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	agentfiles "github.com/devthoko/KERNHAVEN/internal/agent/files"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
)

// withRawBody replaces the request body (upload chunks are not JSON).
func withRawBody(b []byte) reqOpt {
	return func(r *http.Request) {
		r.Body = io.NopCloser(bytes.NewReader(b))
		r.ContentLength = int64(len(b))
		r.Header.Set("Content-Type", "application/octet-stream")
	}
}

var pngBytes = []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")

// withFiles starts a Core and a file service (files role) with the roots "data"
// (the mount root) and "media", filled with sample files.
func withFiles(t *testing.T, adjust func(*config.Config)) (*harness, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "files.sock")
	h := newHarnessWith(t, func(c *config.Config) {
		c.Agent.FilesSocket = sock
		if adjust != nil {
			adjust(c)
		}
	})
	pub, err := agentproto.ReadPublicKey(filepath.Join(h.dataDir, "agent-grant.pub"))
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	mount := filepath.Join(base, "mnt")
	for _, d := range []string{"docs", "media/movies"} {
		if err := os.MkdirAll(filepath.Join(mount, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(p string, b []byte) {
		if err := os.WriteFile(filepath.Join(mount, p), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("docs/readme.txt", []byte("hello <script>alert(1)</script>"))
	write("docs/blob.bin", []byte("a\x00b"))
	write("docs/pic.png", pngBytes)
	write("docs/fake.png", []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>`))
	write("docs/page.png", []byte("<html><script>alert(1)</script></html>"))
	if err := os.WriteFile(filepath.Join(base, "secret"), []byte("top secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "secret"), filepath.Join(mount, "docs", "secret-link")); err != nil {
		t.Fatal(err)
	}
	fs, err := agentfiles.New([]agentfiles.Root{{Name: "data", Path: mount}, {Name: "media", Path: filepath.Join(mount, "media")}}, mount)
	if err != nil {
		t.Fatal(err)
	}
	srv := agent.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, nil, agent.Options{Files: fs})
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return h, mount
}

type rootsBody struct {
	Roots []struct {
		Name     string
		Writable bool
	}
}

// AT-F07-04: role permissions and per-root restrictions, audited.
func TestFilesPermissions(t *testing.T) {
	h, _ := withFiles(t, func(c *config.Config) {
		c.Files.Roots = map[string]config.FileRootAccess{"media": {Read: []string{"owner"}, Write: []string{"owner"}}}
	})
	owner := h.setupOwner()
	h.createUser(owner, "admin1", authz.Admin)
	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer1", authz.Viewer)
	admin, op, viewer := h.loginAs("admin1"), h.loginAs("operator1"), h.loginAs("viewer1")

	var rb rootsBody
	owner.do("GET", "/api/v1/files/roots", nil).expect(200).json(&rb)
	if len(rb.Roots) != 2 || !rb.Roots[0].Writable {
		t.Fatalf("owner roots %+v", rb)
	}
	admin.do("GET", "/api/v1/files/roots", nil).expect(200).json(&rb)
	if len(rb.Roots) != 1 || rb.Roots[0].Name != "data" {
		t.Fatalf("admin sees %+v", rb)
	}
	op.do("GET", "/api/v1/files/roots", nil).expect(200).json(&rb)
	if len(rb.Roots) != 1 || rb.Roots[0].Writable {
		t.Fatalf("operator roots %+v", rb)
	}
	viewer.do("GET", "/api/v1/files/roots", nil).expect(403)
	admin.do("GET", "/api/v1/files/list?root=media", nil).expect(403)
	op.do("GET", "/api/v1/files/list?root=data&path=docs", nil).expect(200)
	op.do("POST", "/api/v1/files/mkdir", map[string]string{"root": "data", "path": "new"}).expect(403)
	// Copying from a readable root into an unwritable one is refused.
	admin.do("POST", "/api/v1/files/copy", map[string]string{"root": "data", "from": "docs", "to_root": "media", "to": "docs"}).expect(403)
	if auditCount(t, h, "files.denied", "failure") != 2 {
		t.Fatal("denials not audited")
	}
}

// AT-F07-01, TH-31 through the API.
func TestFilesConfinement(t *testing.T) {
	h, _ := withFiles(t, nil)
	owner := h.setupOwner()
	for _, p := range []string{"..", "../..", "/etc", "docs/../../x", ".kernhaven-trash"} {
		if r := owner.do("GET", "/api/v1/files/list?root=data&path="+p, nil); r.Code != 422 {
			t.Errorf("list %q: %d %s", p, r.Code, r.Body)
		}
	}
	if r := owner.do("GET", "/api/v1/files/download?root=data&path=docs/secret-link", nil); r.Code == 200 || strings.Contains(r.Body.String(), "top secret") {
		t.Fatalf("symlink escape: %d %s", r.Code, r.Body)
	}
	owner.do("GET", "/api/v1/files/list?root=nope", nil).expect(422)
}

// AT-F07-02, AT-F07-05: downloads, previews and their headers.
func TestFilesDownloadAndPreview(t *testing.T) {
	h, _ := withFiles(t, nil)
	owner := h.setupOwner()
	r := owner.do("GET", "/api/v1/files/download?root=data&path=docs/readme.txt", nil).expect(200)
	hd := r.Header()
	if r.Body.String() != "hello <script>alert(1)</script>" || hd.Get("Content-Type") != "application/octet-stream" ||
		!strings.HasPrefix(hd.Get("Content-Disposition"), "attachment") || !strings.HasPrefix(hd.Get("Content-Security-Policy"), "sandbox") ||
		hd.Get("X-Content-Type-Options") != "nosniff" || hd.Get("Content-Length") != "31" {
		t.Fatalf("download headers %v body %q", hd, r.Body)
	}
	if auditCount(t, h, "files.download", "success") != 1 {
		t.Fatal("download not audited")
	}
	var pv struct {
		Kind, Text string
		Truncated  bool
	}
	owner.do("GET", "/api/v1/files/preview?root=data&path=docs/readme.txt", nil).expect(200).json(&pv)
	if pv.Kind != "text" || pv.Text != "hello <script>alert(1)</script>" {
		t.Fatalf("text preview %+v", pv)
	}
	for p, kind := range map[string]string{"docs/blob.bin": "binary", "docs/pic.png": "image", "docs/fake.png": "text"} {
		owner.do("GET", "/api/v1/files/preview?root=data&path="+p, nil).expect(200).json(&pv)
		if pv.Kind != kind {
			t.Errorf("%s: kind %s, want %s", p, pv.Kind, kind)
		}
	}
	img := owner.do("GET", "/api/v1/files/image?root=data&path=docs/pic.png", nil).expect(200)
	if img.Header().Get("Content-Type") != "image/png" || !strings.HasPrefix(img.Header().Get("Content-Disposition"), "attachment") ||
		!strings.HasPrefix(img.Header().Get("Content-Security-Policy"), "sandbox") || !bytes.Equal(img.Body.Bytes(), pngBytes) {
		t.Fatalf("image %v", img.Header())
	}
	// Names do not decide the type: SVG and HTML named .png are refused.
	for _, p := range []string{"docs/fake.png", "docs/page.png", "docs/readme.txt"} {
		owner.do("GET", "/api/v1/files/image?root=data&path="+p, nil).expect(415)
	}
}

type uploadBody struct {
	ID        string
	Received  int64
	ChunkSize int `json:"chunk_size"`
}

// AT-F07-02: resumable, size-limited uploads.
func TestFilesUpload(t *testing.T) {
	h, mount := withFiles(t, func(c *config.Config) { c.Files.MaxUploadBytes = 64 << 20 })
	owner := h.setupOwner()
	var u uploadBody
	owner.do("POST", "/api/v1/files/uploads", map[string]any{"root": "data", "path": "docs/new.txt", "size": 11}).expect(201).json(&u)
	if len(u.ID) != 32 || u.ChunkSize != 8<<20 {
		t.Fatalf("session %+v", u)
	}
	put := func(offset string, b []byte) response {
		return owner.do("PUT", "/api/v1/files/uploads/"+u.ID+"?offset="+offset, nil, withRawBody(b))
	}
	put("0", []byte("hello ")).expect(200)
	put("0", []byte("again")).expect(409)
	owner.do("GET", "/api/v1/files/uploads/"+u.ID, nil).expect(200).json(&u)
	if u.Received != 6 {
		t.Fatalf("resume at %d", u.Received)
	}
	owner.do("POST", "/api/v1/files/uploads/"+u.ID+"/finish", nil).expect(422)
	put("6", []byte("world")).expect(200)
	owner.do("POST", "/api/v1/files/uploads/"+u.ID+"/finish", nil).expect(200)
	if b, _ := os.ReadFile(filepath.Join(mount, "docs", "new.txt")); string(b) != "hello world" {
		t.Fatalf("uploaded %q", b)
	}
	if auditCount(t, h, "files.upload", "success") != 1 {
		t.Fatal("upload not audited")
	}

	// Limits: announced size, chunk size, and the normal body limit elsewhere.
	owner.do("POST", "/api/v1/files/uploads", map[string]any{"root": "data", "path": "docs/huge", "size": 65 << 20}).expect(422)
	owner.do("POST", "/api/v1/files/uploads", map[string]any{"root": "data", "path": "docs/big.bin", "size": 9 << 20}).expect(201).json(&u)
	put("0", make([]byte, 8<<20+1)).expect(413)
	put("0", make([]byte, 8<<20)).expect(200)
	if r := owner.do("POST", "/api/v1/files/mkdir", nil, withRawBody(make([]byte, 2<<20))); r.Code != 413 {
		t.Fatalf("large body on another route: %d", r.Code)
	}
	owner.do("DELETE", "/api/v1/files/uploads/"+u.ID, nil).expect(204)
	owner.do("GET", "/api/v1/files/uploads/"+u.ID, nil).expect(404)
	// An existing file is never overwritten; another user cannot touch the session.
	owner.do("POST", "/api/v1/files/uploads", map[string]any{"root": "data", "path": "docs/readme.txt", "size": 1}).expect(201).json(&u)
	put("0", []byte("x")).expect(200)
	owner.do("POST", "/api/v1/files/uploads/"+u.ID+"/finish", nil).expect(409)
	h.createUser(owner, "admin1", authz.Admin)
	h.loginAs("admin1").do("GET", "/api/v1/files/uploads/"+u.ID, nil).expect(404)
}

// AT-F07-03: folders, rename, trash, restore, copy and purge jobs.
func TestFilesOperations(t *testing.T) {
	h, mount := withFiles(t, nil)
	owner := h.setupOwner()
	h.startJobs()
	owner.do("POST", "/api/v1/files/mkdir", map[string]string{"root": "data", "path": "photos"}).expect(200)
	owner.do("POST", "/api/v1/files/mkdir", map[string]string{"root": "data", "path": "photos"}).expect(409)
	owner.do("POST", "/api/v1/files/rename", map[string]string{"root": "data", "from": "docs/readme.txt", "to": "photos/readme.txt"}).expect(204)
	owner.do("POST", "/api/v1/files/rename", map[string]string{"root": "data", "from": "docs/blob.bin", "to": "photos/readme.txt"}).expect(409)

	var item agentproto.TrashItem
	owner.do("POST", "/api/v1/files/trash", map[string]string{"root": "data", "path": "photos/readme.txt"}).expect(200).json(&item)
	var trash struct{ Items []agentproto.TrashItem }
	owner.do("GET", "/api/v1/files/trash?root=data", nil).expect(200).json(&trash)
	if len(trash.Items) != 1 || trash.Items[0].DeletedBy != "owner" {
		t.Fatalf("trash %+v", trash)
	}
	owner.do("POST", "/api/v1/files/trash/restore", map[string]string{"root": "data", "id": item.ID}).expect(200)
	if b, _ := os.ReadFile(filepath.Join(mount, "photos", "readme.txt")); !strings.HasPrefix(string(b), "hello") {
		t.Fatal("restore")
	}

	var job struct {
		JobID int64 `json:"job_id"`
	}
	owner.do("POST", "/api/v1/files/copy", map[string]string{"root": "data", "from": "photos", "to_root": "media", "to": "photos"}).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	if _, err := os.Stat(filepath.Join(mount, "media", "photos", "readme.txt")); err != nil {
		t.Fatal("copy")
	}
	owner.do("POST", "/api/v1/files/copy", map[string]string{"root": "data", "from": "photos", "to_root": "media", "to": "photos"}).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Failed)

	owner.do("POST", "/api/v1/files/trash", map[string]string{"root": "data", "path": "photos"}).expect(200)
	owner.do("POST", "/api/v1/files/trash/purge", map[string]string{"root": "data"}).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	owner.do("GET", "/api/v1/files/trash?root=data", nil).expect(200).json(&trash)
	if len(trash.Items) != 0 {
		t.Fatalf("trash after purge %+v", trash)
	}
	for _, a := range []string{"files.mkdir", "files.rename", "files.trash", "files.restore", "files.copy"} {
		if auditCount(t, h, a, "success") == 0 {
			t.Errorf("%s not audited", a)
		}
	}
}
