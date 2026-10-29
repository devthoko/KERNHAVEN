package agent

import (
	"archive/tar"
	"bytes"
	"io"
	"reflect"
	"strings"
	"testing"
)

type entry struct {
	name, link string
	typ        byte
	body       string
}

func mkTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: 0o640, Uid: 1000, Gid: 1000, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	return buf.Bytes()
}

// M16: only plain volume contents pass the agent, in both directions.
func TestFilterTar(t *testing.T) {
	root := entry{name: "data/", typ: tar.TypeDir}
	good := mkTar(t, root, entry{name: "data/.hidden", typ: tar.TypeReg, body: "x"}, entry{name: "data/sub/", typ: tar.TypeDir},
		entry{name: "data/sub/f", typ: tar.TypeReg, body: "hello"}, entry{name: "data/l", link: "/etc/passwd", typ: tar.TypeSymlink},
		entry{name: "data/h", link: "data/sub/f", typ: tar.TypeLink}, entry{name: "data/fifo", typ: tar.TypeFifo})
	var out bytes.Buffer
	n, size, err := filterTar(bytes.NewReader(good), &out)
	if err != nil || n != 7 || size != 6 {
		t.Fatalf("good archive: %d entries, %d bytes, %v", n, size, err)
	}
	tr := tar.NewReader(&out)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		if h.Uid != 1000 || h.Mode != 0o640 {
			t.Errorf("%s: owner or mode lost", h.Name)
		}
		if len(h.PAXRecords) > 0 && h.PAXRecords["SCHILY.xattr.security.capability"] != "" {
			t.Errorf("%s: xattrs carried over", h.Name)
		}
	}
	if want := []string{"data/", "data/.hidden", "data/sub/", "data/sub/f", "data/l", "data/h", "data/fifo"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("names %v", names)
	}
	bad := map[string][]byte{
		"parent":            mkTar(t, root, entry{name: "data/../etc/x", typ: tar.TypeReg}),
		"absolute":          mkTar(t, root, entry{name: "/data/x", typ: tar.TypeReg}),
		"outside":           mkTar(t, root, entry{name: "etc/passwd", typ: tar.TypeReg}),
		"below a symlink":   mkTar(t, root, entry{name: "data/l", link: "/etc", typ: tar.TypeSymlink}, entry{name: "data/l/passwd", typ: tar.TypeReg}),
		"dangling hardlink": mkTar(t, root, entry{name: "data/h", link: "/etc/shadow", typ: tar.TypeLink}),
		"device":            mkTar(t, root, entry{name: "data/sda", typ: tar.TypeBlock}),
		"char device":       mkTar(t, root, entry{name: "data/mem", typ: tar.TypeChar}),
		"root not a dir":    mkTar(t, entry{name: "data", typ: tar.TypeReg}),
		"empty":             mkTar(t),
		"garbage":           []byte(strings.Repeat("x", 1024)),
	}
	for name, b := range bad {
		if _, _, err := filterTar(bytes.NewReader(b), io.Discard); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestDockerStreamOperations(t *testing.T) {
	if got := DockerStreamOperationNames(); !reflect.DeepEqual(got, []string{"volumes.export", "volumes.import"}) {
		t.Fatalf("docker stream operations = %v", got)
	}
	// The other roles offer none of them.
	if got := StreamOperationNames(); !reflect.DeepEqual(got, []string{"files.read", "files.upload.append"}) {
		t.Fatalf("files stream operations = %v", got)
	}
	// A fake Docker without archive support offers no stream operations.
	if ops := streamOperations(&fakeDocker{}, Options{}); len(ops) != 0 {
		t.Fatalf("fake docker: %v", ops)
	}
	s := archiveHelperSpec(DefaultHelperImage, "h", "v", helperVolumeExport)
	if !s.Mounts[0].ReadOnly || !s.ReadOnlyRootfs || s.NetworkMode != "none" || len(s.CapAdd) != 0 || s.CapDrop[0] != "ALL" {
		t.Fatalf("export helper %+v", s)
	}
	s = archiveHelperSpec(DefaultHelperImage, "h", "v", "volume-clear")
	if s.Mounts[0].ReadOnly || s.NetworkMode != "none" || s.Cmd[2] != clearScript {
		t.Fatalf("clear helper %+v", s)
	}
}
