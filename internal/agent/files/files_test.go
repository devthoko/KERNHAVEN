package files

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// setup creates a mount root with the roots "data" (the mount root) and
// "media" (a folder below it) and a secret outside both.
func setup(t *testing.T) (*Service, string) {
	t.Helper()
	base := t.TempDir()
	mount := filepath.Join(base, "mnt")
	must(t, os.MkdirAll(filepath.Join(mount, "media", "movies"), 0o755))
	must(t, os.MkdirAll(filepath.Join(mount, "docs"), 0o755))
	must(t, os.WriteFile(filepath.Join(mount, "docs", "readme.txt"), []byte("hello"), 0o644))
	must(t, os.WriteFile(filepath.Join(base, "secret"), []byte("top secret"), 0o600))
	s, err := New([]Root{{Name: "data", Path: mount}, {Name: "media", Path: filepath.Join(mount, "media")}}, mount)
	if err != nil {
		t.Fatal(err)
	}
	return s, mount
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func isInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

func TestNewRoots(t *testing.T) {
	for name, roots := range map[string][]Root{
		"outside the mount root": {{Name: "etc", Path: "/etc"}},
		"prefix trick":           {{Name: "x", Path: "/srv/kernhaven2"}},
		"not clean":              {{Name: "x", Path: "/srv/kernhaven/a/../.."}},
		"bad name":               {{Name: "Data", Path: "/srv/kernhaven"}},
		"duplicate":              {{Name: "a", Path: "/srv/kernhaven"}, {Name: "a", Path: "/srv/kernhaven/b"}},
	} {
		if _, err := New(roots, "/srv/kernhaven"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	s, err := New(nil, "/srv/kernhaven")
	if err != nil || len(s.RootNames()) != 1 || s.roots["data"] != "/srv/kernhaven" {
		t.Fatalf("default root: %v %v", s, err)
	}
}

func TestCleanPath(t *testing.T) {
	good := map[string]string{"": ".", ".": ".", "a/b": "a/b", "a//b/": "a/b", "a/./b": "a/b", "a/b/../c": "a/c", "%2e%2e": "%2e%2e", `back\slash`: `back\slash`}
	for in, want := range good {
		if got, err := CleanPath(in, true); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, bad := range []string{"..", "../x", "a/../../x", "/etc/passwd", "a\x00b", ".kernhaven-trash", "a/.kernhaven-uploads/x", strings.Repeat("x", 256), strings.Repeat("a/", 2049)} {
		if _, err := CleanPath(bad, true); !isInvalid(err) {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := CleanPath("", false); !isInvalid(err) {
		t.Error("root accepted where a name is required")
	}
}

// AT-F07-01, TH-31: symlinks cannot leave the root; the kernel enforces it.
func TestSymlinkEscapes(t *testing.T) {
	s, mount := setup(t)
	base := filepath.Dir(mount)
	must(t, os.Symlink("/etc", filepath.Join(mount, "etc-link")))
	must(t, os.Symlink(filepath.Join(base, "secret"), filepath.Join(mount, "secret-link")))
	must(t, os.Symlink("../secret", filepath.Join(mount, "relative-out")))
	must(t, os.Symlink("hop2", filepath.Join(mount, "hop1")))
	must(t, os.Symlink("../../", filepath.Join(mount, "hop2")))
	must(t, os.Symlink("docs/readme.txt", filepath.Join(mount, "inside-link")))
	must(t, os.Symlink("../docs", filepath.Join(mount, "media", "docs-from-media")))

	for _, p := range []string{"etc-link", "hop1", "media/docs-from-media"} {
		if _, err := s.List(agentproto.FilesPath{Root: rootFor(p), Path: strings.TrimPrefix(p, "media/")}); err == nil {
			t.Errorf("listing %s left the root", p)
		}
	}
	for _, p := range []string{"etc-link/passwd", "secret-link", "relative-out", "hop1/secret"} {
		if _, rc, err := s.Open(agentproto.FilesRead{Root: "data", Path: p}); err == nil {
			b, _ := io.ReadAll(rc)
			rc.Close()
			t.Errorf("read %s outside the root: %q", p, b)
		}
	}
	// The "media" root cannot reach the files of "data" next to it.
	if _, _, err := s.Open(agentproto.FilesRead{Root: "media", Path: "docs-from-media/readme.txt"}); err == nil {
		t.Error("media root read data through a symlink")
	}
	// Writing through a symlink is confined too.
	if err := s.Mkdir(agentproto.FilesPath{Root: "data", Path: "etc-link/evil"}); err == nil {
		t.Error("created a folder in /etc")
	}
	if _, err := os.Stat("/etc/evil"); err == nil {
		t.Fatal("/etc/evil exists")
	}
	// A symlink inside the root works and is listed as a link.
	meta, rc, err := s.Open(agentproto.FilesRead{Root: "data", Path: "inside-link"})
	if err != nil {
		t.Fatalf("symlink inside the root: %v", err)
	}
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "hello" || meta.Size != 5 {
		t.Fatalf("read %q %+v", b, meta)
	}
	l, err := s.List(agentproto.FilesPath{Root: "data"})
	must(t, err)
	types := map[string]string{}
	for _, e := range l.Entries {
		types[e.Name] = e.Type
	}
	if types["inside-link"] != "symlink" || types["docs"] != "dir" || types["media"] != "dir" {
		t.Fatalf("listing %v", types)
	}
}

func rootFor(p string) string {
	if strings.HasPrefix(p, "media/") {
		return "media"
	}
	return "data"
}

// AT-F07-03: folder operations never overwrite.
func TestOperations(t *testing.T) {
	s, mount := setup(t)
	data := func(p string) agentproto.FilesPath { return agentproto.FilesPath{Root: "data", Path: p} }
	must(t, s.Mkdir(data("photos")))
	if err := s.Mkdir(data("photos")); !errors.Is(err, ErrExists) {
		t.Fatalf("mkdir twice: %v", err)
	}
	if err := s.Mkdir(data("missing/sub")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mkdir without parent: %v", err)
	}
	must(t, s.Rename(agentproto.FilesRename{Root: "data", From: "docs/readme.txt", To: "photos/readme.txt"}))
	must(t, os.WriteFile(filepath.Join(mount, "docs", "other.txt"), []byte("other"), 0o644))
	if err := s.Rename(agentproto.FilesRename{Root: "data", From: "docs/other.txt", To: "photos/readme.txt"}); !errors.Is(err, ErrExists) {
		t.Fatalf("rename onto existing file: %v", err)
	}
	if err := s.Rename(agentproto.FilesRename{Root: "data", From: "photos", To: "photos/inner"}); !isInvalid(err) {
		t.Fatalf("move into itself: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(mount, "photos", "readme.txt")); string(b) != "hello" {
		t.Fatal("rename lost content")
	}

	// Copy within and between roots; never over existing files.
	res, err := s.Copy(context.Background(), agentproto.FilesCopy{Root: "data", From: "photos", To: "photos-copy"})
	if err != nil || res.Files != 1 || res.Bytes != 5 {
		t.Fatalf("copy: %+v %v", res, err)
	}
	if _, err := s.Copy(context.Background(), agentproto.FilesCopy{Root: "data", From: "photos", To: "photos-copy"}); !errors.Is(err, ErrExists) {
		t.Fatalf("copy onto existing: %v", err)
	}
	if _, err := s.Copy(context.Background(), agentproto.FilesCopy{Root: "data", From: "photos", To: "photos/again"}); !isInvalid(err) {
		t.Fatalf("copy into itself: %v", err)
	}
	must(t, os.Symlink("/etc/passwd", filepath.Join(mount, "photos", "link")))
	res, err = s.Copy(context.Background(), agentproto.FilesCopy{Root: "data", From: "photos", ToRoot: "media", To: "photos"})
	if err != nil || res.Files != 1 || res.SkippedSymlinks != 1 {
		t.Fatalf("copy to media: %+v %v", res, err)
	}
	if b, _ := os.ReadFile(filepath.Join(mount, "media", "photos", "readme.txt")); string(b) != "hello" {
		t.Fatal("copied content")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Copy(ctx, agentproto.FilesCopy{Root: "data", From: "docs", To: "docs-cancelled"}); err == nil {
		t.Fatal("cancelled copy succeeded")
	}
}

// AT-F07-03: trash, restore, conflicts, purge.
func TestTrash(t *testing.T) {
	s, mount := setup(t)
	item, err := s.Trash(agentproto.FilesPath{Root: "data", Path: "docs/readme.txt"}, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(mount, "docs", "readme.txt")); !os.IsNotExist(err) {
		t.Fatal("file still there")
	}
	list, err := s.TrashList(agentproto.FilesPath{Root: "data"})
	if err != nil || len(list) != 1 || list[0].Path != "docs/readme.txt" || list[0].DeletedBy != "alice" || list[0].ID != item.ID {
		t.Fatalf("trash %+v %v", list, err)
	}
	l, _ := s.List(agentproto.FilesPath{Root: "data"})
	for _, e := range l.Entries {
		if strings.HasPrefix(e.Name, ".kernhaven") {
			t.Fatalf("reserved folder listed: %s", e.Name)
		}
	}
	// Something new at the original path blocks the restore.
	must(t, os.WriteFile(filepath.Join(mount, "docs", "readme.txt"), []byte("new"), 0o644))
	if _, err := s.Restore(agentproto.FilesTrashID{Root: "data", ID: item.ID}); !errors.Is(err, ErrExists) {
		t.Fatalf("restore over new file: %v", err)
	}
	must(t, os.Remove(filepath.Join(mount, "docs", "readme.txt")))
	must(t, os.Remove(filepath.Join(mount, "docs")))
	if p, err := s.Restore(agentproto.FilesTrashID{Root: "data", ID: item.ID}); err != nil || p != "docs/readme.txt" {
		t.Fatalf("restore: %q %v", p, err)
	}
	if b, _ := os.ReadFile(filepath.Join(mount, "docs", "readme.txt")); string(b) != "hello" {
		t.Fatal("restored content")
	}
	if list, _ := s.TrashList(agentproto.FilesPath{Root: "data"}); len(list) != 0 {
		t.Fatalf("trash after restore %+v", list)
	}
	for _, bad := range []string{"x", "../../etc.0000000000000-00000000", "Li4v.1234567890123-abcdef01"} {
		if _, err := s.Restore(agentproto.FilesTrashID{Root: "data", ID: bad}); err == nil {
			t.Errorf("trash id %q accepted", bad)
		}
	}
	a, _ := s.Trash(agentproto.FilesPath{Root: "data", Path: "docs"}, "bob")
	_, _ = s.Trash(agentproto.FilesPath{Root: "data", Path: "media/movies"}, "bob")
	must(t, s.Purge(agentproto.FilesTrashID{Root: "data", ID: a.ID}))
	if list, _ := s.TrashList(agentproto.FilesPath{Root: "data"}); len(list) != 1 {
		t.Fatalf("after purging one: %+v", list)
	}
	must(t, s.Purge(agentproto.FilesTrashID{Root: "data"}))
	if list, _ := s.TrashList(agentproto.FilesPath{Root: "data"}); len(list) != 0 {
		t.Fatalf("after emptying: %+v", list)
	}
}

// AT-F07-02: resumable uploads.
func TestUpload(t *testing.T) {
	s, mount := setup(t)
	id := strings.Repeat("ab", 16)
	up := func(off int64, data string) (agentproto.UploadState, error) {
		return s.Append(agentproto.UploadAppend{Root: "data", ID: id, Path: "docs/big.bin", Offset: off}, strings.NewReader(data))
	}
	if st, err := up(0, "hello "); err != nil || st.Size != 6 {
		t.Fatalf("chunk 1: %+v %v", st, err)
	}
	var oe *OffsetError
	if _, err := up(0, "again"); !errors.As(err, &oe) || oe.Size != 6 {
		t.Fatalf("wrong offset: %v", err)
	}
	if st, err := up(-1, ""); err != nil || st.Size != 6 {
		t.Fatalf("resume query: %+v %v", st, err)
	}
	if err := s.Finish(agentproto.UploadFinish{Root: "data", ID: id, Path: "docs/big.bin", Size: 11}); !isInvalid(err) {
		t.Fatalf("incomplete finish: %v", err)
	}
	if _, err := s.Append(agentproto.UploadAppend{Root: "data", ID: id, Path: "docs/big.bin", Offset: 6}, bytes.NewReader(make([]byte, MaxChunk+1))); !isInvalid(err) {
		t.Fatalf("oversized chunk: %v", err)
	}
	if st, err := up(6, "world"); err != nil || st.Size != 11 {
		t.Fatalf("chunk 2 after the oversized one was rolled back: %+v %v", st, err)
	}
	must(t, s.Finish(agentproto.UploadFinish{Root: "data", ID: id, Path: "docs/big.bin", Size: 11}))
	if b, _ := os.ReadFile(filepath.Join(mount, "docs", "big.bin")); string(b) != "hello world" {
		t.Fatalf("uploaded %q", b)
	}
	// Never over an existing file; staged data can be aborted.
	id2 := strings.Repeat("cd", 16)
	_, _ = s.Append(agentproto.UploadAppend{Root: "data", ID: id2, Path: "docs/readme.txt", Offset: 0}, strings.NewReader("x"))
	if err := s.Finish(agentproto.UploadFinish{Root: "data", ID: id2, Path: "docs/readme.txt", Size: 1}); !errors.Is(err, ErrExists) {
		t.Fatalf("finish over existing: %v", err)
	}
	must(t, s.Abort(agentproto.UploadFinish{Root: "data", ID: id2, Path: "docs/readme.txt"}))
	for _, bad := range []agentproto.UploadAppend{{Root: "data", ID: "../../x", Path: "a"}, {Root: "data", ID: id, Path: "../a"}, {Root: "nope", ID: id, Path: "a"}} {
		if _, err := s.Append(bad, strings.NewReader("x")); err == nil {
			t.Errorf("append %+v accepted", bad)
		}
	}
}

func TestOpenRange(t *testing.T) {
	s, _ := setup(t)
	_, rc, err := s.Open(agentproto.FilesRead{Root: "data", Path: "docs/readme.txt", Offset: 1, Limit: 3})
	must(t, err)
	b, _ := io.ReadAll(rc)
	rc.Close()
	if string(b) != "ell" {
		t.Fatalf("range %q", b)
	}
	if _, _, err := s.Open(agentproto.FilesRead{Root: "data", Path: "docs"}); !isInvalid(err) {
		t.Fatalf("folder opened: %v", err)
	}
}
