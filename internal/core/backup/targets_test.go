package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
)

var loopback = netguard.Guard{AllowLoopback: true}

// exerciseTarget runs the operations every target must support.
func exerciseTarget(t *testing.T, tg Target) {
	t.Helper()
	ctx := context.Background()
	big := make([]byte, s3PartSize*2+1234)
	_, _ = rand.Read(big)
	objs := map[string][]byte{
		RepoFile: []byte(`{"x":1}`),
		"snapshots/20261029T030000Z-abcdef/0.khb":        big,
		"snapshots/20261029T030000Z-abcdef/1.khb":        {},
		"snapshots/20261029T030000Z-abcdef/manifest.khb": []byte("m"),
		"snapshots/20261030T030000Z-abcdef/0.khb":        []byte("other"),
	}
	for name, b := range objs {
		if n, err := tg.Put(ctx, name, bytes.NewReader(b)); err != nil || n != int64(len(b)) {
			t.Fatalf("put %s: %d %v", name, n, err)
		}
	}
	for name, b := range objs {
		rc, err := tg.Get(ctx, name)
		if err != nil {
			t.Fatalf("get %s: %v", name, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("get %s: %d bytes %v", name, len(got), err)
		}
	}
	if _, err := tg.Get(ctx, "snapshots/20261029T030000Z-abcdef/7.khb"); !errors.Is(err, ErrNotExist) {
		t.Fatalf("missing object: %v", err)
	}
	list, err := tg.List(ctx, "snapshots/")
	if err != nil || len(list) != 4 || list[0].Name != "snapshots/20261029T030000Z-abcdef/0.khb" || list[0].Size != int64(len(big)) {
		t.Fatalf("list %+v %v", list, err)
	}
	if one, err := tg.List(ctx, "snapshots/20261030T030000Z-abcdef/"); err != nil || len(one) != 1 {
		t.Fatalf("list one %+v %v", one, err)
	}
	// Replacing the repository file (passphrase change) works.
	if _, err := tg.Put(ctx, RepoFile, strings.NewReader(`{"x":2}`)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"../x", "/etc/passwd", "snapshots/../../x/0.khb", "snapshots/a/b/0.khb", "other.json"} {
		if _, err := tg.Put(ctx, bad, strings.NewReader("x")); err == nil {
			t.Errorf("put %q accepted", bad)
		}
		if _, err := tg.Get(ctx, bad); err == nil {
			t.Errorf("get %q accepted", bad)
		}
	}
	if _, err := tg.List(ctx, "../"); err == nil {
		t.Error("list ../ accepted")
	}
	for name := range objs {
		if err := tg.Delete(ctx, name); err != nil {
			t.Fatalf("delete %s: %v", name, err)
		}
	}
	if err := tg.Delete(ctx, RepoFile); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
	if list, _ := tg.List(ctx, "snapshots/"); len(list) != 0 {
		t.Fatalf("after delete %+v", list)
	}
}

// AT-F14-02: local directories, restricted to the configured roots.
func TestLocalTarget(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "repo")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.Symlink(other, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	for p, ok := range map[string]bool{
		dir: true, root: true, other: false, filepath.Join(root, "link"): false, filepath.Join(root, "missing"): false,
		"relative": false, dir + "/../repo": false, "": false,
	} {
		if err := CheckLocalPath(p, []string{root}); (err == nil) != ok {
			t.Errorf("%q: %v", p, err)
		}
	}
	tg, err := OpenLocal(LocalConfig{Path: dir}, []string{root})
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	exerciseTarget(t, tg)
	// No temporary files are left behind.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "snapshots" {
			t.Errorf("left %s", e.Name())
		}
	}
}

func sftpServer(t *testing.T, dir string, allow ssh.PublicKey) (host string, port int, hostKey ssh.PublicKey) {
	t.Helper()
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(hk)
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(k.Marshal(), allow.Marshal()) {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == "test-password" {
				return nil, nil
			}
			return nil, errors.New("denied")
		},
	}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				_, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, reqs, err := nc.Accept()
					if err != nil {
						continue
					}
					go func() {
						for r := range reqs {
							ok := r.Type == "subsystem" && string(r.Payload[4:]) == "sftp"
							_ = r.Reply(ok, nil)
							if ok {
								srv, _ := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(dir))
								_ = srv.Serve()
								ch.Close()
							}
						}
					}()
				}
			}()
		}
	}()
	a := ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", a.Port, signer.PublicKey()
}

// AT-F14-02: SFTP with a pinned host key and the Core's own key.
func TestSFTPTarget(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	auth, pub, err := NewSFTPKey()
	if err != nil || !strings.HasPrefix(pub, "ssh-ed25519 ") {
		t.Fatalf("key %q %v", pub, err)
	}
	pk, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(pub))
	host, port, hk := sftpServer(t, dir, pk)
	key, fp, err := ScanHostKey(ctx, loopback, host, port)
	if err != nil || fp != ssh.FingerprintSHA256(hk) || !strings.HasPrefix(key, "ssh-ed25519 ") {
		t.Fatalf("scan %q %q %v", key, fp, err)
	}
	if _, _, err := ScanHostKey(ctx, netguard.Guard{}, host, port); !errors.Is(err, netguard.ErrForbiddenAddress) {
		t.Fatalf("scan through guard: %v", err)
	}
	cfg := SFTPConfig{Host: host, Port: port, User: "backup", Path: dir, HostKey: key}
	tg, err := OpenSFTP(ctx, loopback, cfg, auth)
	if err != nil {
		t.Fatal(err)
	}
	exerciseTarget(t, tg)
	tg.Close()

	if tg, err := OpenSFTP(ctx, loopback, cfg, SFTPAuth{Password: "test-password"}); err != nil {
		t.Fatalf("password: %v", err)
	} else {
		tg.Close()
	}
	// Another host key is refused before authenticating.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	os2, _ := ssh.NewSignerFromKey(other)
	wrong := cfg
	wrong.HostKey = string(ssh.MarshalAuthorizedKey(os2.PublicKey()))
	if _, err := OpenSFTP(ctx, loopback, wrong, auth); err == nil || !strings.Contains(err.Error(), "host key") {
		t.Fatalf("wrong host key: %v", err)
	}
	if _, err := OpenSFTP(ctx, loopback, cfg, SFTPAuth{Password: "nope"}); err == nil {
		t.Fatal("wrong password accepted")
	}
	missing := cfg
	missing.Path = filepath.Join(dir, "missing")
	if _, err := OpenSFTP(ctx, loopback, missing, auth); err == nil {
		t.Fatal("missing directory accepted")
	}
	for name, c := range map[string]SFTPConfig{
		"no host key": {Host: host, Port: port, User: "u", Path: dir},
		"root path":   {Host: host, Port: port, User: "u", Path: "/", HostKey: key},
		"relative":    {Host: host, Port: port, User: "u", Path: "x", HostKey: key},
		"bad user":    {Host: host, Port: port, User: "a b", Path: dir, HostKey: key},
		"bad host":    {Host: "a/b", Port: port, User: "u", Path: dir, HostKey: key},
	} {
		if _, err := OpenSFTP(ctx, loopback, c, auth); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := OpenSFTP(ctx, netguard.Guard{}, cfg, auth); !errors.Is(err, netguard.ErrForbiddenAddress) {
		t.Fatalf("guard: %v", err)
	}
}

// Signature examples from the Amazon S3 SigV4 documentation.
func TestSignV4(t *testing.T) {
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	const id, secret = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	empty := sha256Hex(nil)
	r, _ := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	r.Header.Set("Range", "bytes=0-9")
	signV4(r, id, secret, "us-east-1", empty, now)
	if want := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"; r.Header.Get("Authorization") != want {
		t.Errorf("GET object:\n%s\n%s", r.Header.Get("Authorization"), want)
	}
	r, _ = http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	signV4(r, id, secret, "us-east-1", empty, now)
	if !strings.HasSuffix(r.Header.Get("Authorization"), "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7") {
		t.Errorf("list objects: %s", r.Header.Get("Authorization"))
	}
}

// fakeS3 is an in-memory bucket for the client's request flow; the real
// protocol is tested against an S3 server in the integration job.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	uploads map[string]map[int][]byte
	parts   int
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=key-id/") || r.Header.Get("x-amz-content-sha256") == "" {
		w.WriteHeader(403)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	q := r.URL.Query()
	body, _ := io.ReadAll(r.Body)
	if sha256Hex(body) != r.Header.Get("x-amz-content-sha256") {
		w.WriteHeader(400)
		return
	}
	switch {
	case r.Method == "GET" && q.Get("list-type") == "2":
		var keys []string
		for k := range f.objects {
			if strings.HasPrefix(k, q.Get("prefix")) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		fmt.Fprint(w, "<ListBucketResult>")
		for _, k := range keys {
			fmt.Fprintf(w, "<Contents><Key>%s</Key><Size>%d</Size></Contents>", k, len(f.objects[k]))
		}
		fmt.Fprint(w, "<IsTruncated>false</IsTruncated></ListBucketResult>")
	case r.Method == "POST" && q.Has("uploads"):
		id := strconv.Itoa(len(f.uploads) + 1)
		f.uploads[id] = map[int][]byte{}
		fmt.Fprintf(w, "<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>", id)
	case r.Method == "PUT" && q.Has("uploadId"):
		n, _ := strconv.Atoi(q.Get("partNumber"))
		f.uploads[q.Get("uploadId")][n] = body
		f.parts++
		w.Header().Set("ETag", fmt.Sprintf(`"%d"`, n))
	case r.Method == "POST" && q.Has("uploadId"):
		var c struct {
			Parts []struct {
				PartNumber int
				ETag       string
			} `xml:"Part"`
		}
		_ = xml.Unmarshal(body, &c)
		var all []byte
		for _, p := range c.Parts {
			all = append(all, f.uploads[q.Get("uploadId")][p.PartNumber]...)
		}
		f.objects[key] = all
		delete(f.uploads, q.Get("uploadId"))
		fmt.Fprint(w, "<CompleteMultipartUploadResult/>")
	case r.Method == "DELETE" && q.Has("uploadId"):
		delete(f.uploads, q.Get("uploadId"))
		w.WriteHeader(204)
	case r.Method == "PUT":
		f.objects[key] = body
	case r.Method == "GET":
		b, ok := f.objects[key]
		if !ok {
			w.WriteHeader(404)
			fmt.Fprint(w, "<Error><Code>NoSuchKey</Code></Error>")
			return
		}
		_, _ = w.Write(b)
	case r.Method == "DELETE":
		delete(f.objects, key)
		w.WriteHeader(204)
	default:
		w.WriteHeader(400)
	}
}

// AT-F14-02: S3-compatible buckets (request flow incl. multipart uploads).
func TestS3Target(t *testing.T) {
	ctx := context.Background()
	f := &fakeS3{objects: map[string][]byte{}, uploads: map[string]map[int][]byte{}}
	srv := httptest.NewServer(f)
	defer srv.Close()
	cfg := S3Config{Endpoint: srv.URL, Bucket: "bucket", AccessKeyID: "key-id", PathStyle: true}
	tg, err := OpenS3(ctx, loopback, cfg, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	exerciseTarget(t, tg)
	if f.parts != 3 || len(f.uploads) != 0 {
		t.Errorf("multipart: %d parts, %d open uploads", f.parts, len(f.uploads))
	}
	pref := cfg
	pref.Prefix = "kh/"
	tg2, _ := OpenS3(ctx, loopback, pref, "secret", nil)
	if _, err := tg2.Put(ctx, RepoFile, strings.NewReader("x")); err != nil || f.objects["kh/"+RepoFile] == nil {
		t.Fatalf("prefix: %v %v", err, f.objects)
	}
	if l, _ := tg2.List(ctx, "snapshots/"); len(l) != 0 {
		t.Fatalf("prefix list %v", l)
	}
	if _, err := OpenS3(ctx, netguard.Guard{}, cfg, "secret", nil); !errors.Is(err, netguard.ErrForbiddenAddress) {
		t.Fatalf("guard: %v", err)
	}
	for name, c := range map[string]S3Config{
		"path in endpoint": {Endpoint: srv.URL + "/x", Bucket: "bucket", AccessKeyID: "key-id"},
		"ftp":              {Endpoint: "ftp://x", Bucket: "bucket", AccessKeyID: "key-id"},
		"user info":        {Endpoint: "https://a:b@x", Bucket: "bucket", AccessKeyID: "key-id"},
		"bucket":           {Endpoint: srv.URL, Bucket: "B_", AccessKeyID: "key-id"},
		"prefix":           {Endpoint: srv.URL, Bucket: "bucket", AccessKeyID: "key-id", Prefix: "../"},
		"key id":           {Endpoint: srv.URL, Bucket: "bucket", AccessKeyID: "a b"},
	} {
		if _, err := OpenS3(ctx, loopback, c, "secret", nil); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if _, err := OpenS3(ctx, loopback, cfg, "", nil); err == nil {
		t.Error("empty secret accepted")
	}
}
