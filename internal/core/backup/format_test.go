package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func testKey(t *testing.T) []byte {
	k := make([]byte, keySize)
	_, _ = rand.Read(k)
	return k
}

func seal(t *testing.T, key []byte, name string, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	e, err := NewEncrypter(&buf, key, "repo", "snap", name)
	if err != nil {
		t.Fatal(err)
	}
	// Uneven writes exercise segment boundaries.
	for len(plain) > 0 {
		n := min(len(plain), 777777)
		if _, err := e.Write(plain[:n]); err != nil {
			t.Fatal(err)
		}
		plain = plain[n:]
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if int64(buf.Len()) != e.Written() {
		t.Fatalf("written %d, buffer %d", e.Written(), buf.Len())
	}
	return buf.Bytes()
}

func open(key []byte, name string, ct []byte) ([]byte, error) {
	d, err := NewDecrypter(bytes.NewReader(ct), key, "repo", "snap", name)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(d)
}

// AT-F14-01: authenticated encryption round trip for all segment edge cases.
func TestStreamRoundTrip(t *testing.T) {
	key := testKey(t)
	for _, n := range []int{0, 1, segmentSize - 1, segmentSize, segmentSize + 1, 3*segmentSize + 12345} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		ct := seal(t, key, "obj", plain)
		segs := max(1, (n+segmentSize-1)/segmentSize)
		if n%segmentSize == 0 && n > 0 {
			segs = n / segmentSize
		}
		if want := len(objectMagic) + saltSize + n + segs*tagSize; len(ct) != want {
			t.Errorf("%d bytes: ciphertext %d, want %d", n, len(ct), want)
		}
		got, err := open(key, "obj", ct)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("%d bytes: %v", n, err)
		}
		if bytes.Contains(ct, plain[:min(n, 64)]) && n >= 16 {
			t.Fatalf("%d bytes: plaintext visible", n)
		}
	}
}

// AT-F14-06: every kind of damage or tampering fails authentication.
func TestStreamTamper(t *testing.T) {
	key := testKey(t)
	plain := make([]byte, 2*segmentSize+500)
	_, _ = rand.Read(plain)
	ct := seal(t, key, "obj", plain)
	seg := segmentSize + tagSize
	hdr := len(objectMagic) + saltSize
	flip := func(i int) []byte { c := bytes.Clone(ct); c[i] ^= 1; return c }
	swapped := bytes.Clone(ct)
	copy(swapped[hdr:hdr+seg], ct[hdr+seg:hdr+2*seg])
	copy(swapped[hdr+seg:hdr+2*seg], ct[hdr:hdr+seg])
	cases := map[string]struct {
		ct   []byte
		key  []byte
		name string
	}{
		"bit flip in data":           {flip(hdr + 10), key, "obj"},
		"bit flip in tag":            {flip(len(ct) - 1), key, "obj"},
		"bit flip in salt":           {flip(len(objectMagic) + 3), key, "obj"},
		"truncated to full segments": {ct[:hdr+2*seg], key, "obj"},
		"truncated in a segment":     {ct[:hdr+seg+100], key, "obj"},
		"header only":                {ct[:hdr], key, "obj"},
		"segments reordered":         {swapped, key, "obj"},
		"data appended":              {append(bytes.Clone(ct), 0), key, "obj"},
		"other object name":          {ct, key, "other"},
		"other key":                  {ct, testKey(t), "obj"},
		"bad magic":                  {append([]byte("XXXX"), ct[4:]...), key, "obj"},
	}
	for name, c := range cases {
		got, err := open(c.key, c.name, c.ct)
		if !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: err %v (read %d bytes)", name, err, len(got))
		}
	}
	// A segment moved to another object of the same snapshot fails too.
	other := seal(t, key, "obj2", plain)
	mixed := append(bytes.Clone(ct[:hdr+seg]), other[hdr+seg:]...)
	if _, err := open(key, "obj", mixed); !errors.Is(err, ErrCorrupt) {
		t.Errorf("mixed objects: %v", err)
	}
}

// AT-F14-01: the repository file holds only the wrapped key.
func TestRepoHeader(t *testing.T) {
	if _, _, err := NewRepoHeader("0123456789abcdef0123456789abcdef", 1, "short"); err == nil {
		t.Fatal("short passphrase accepted")
	}
	h, key, err := NewRepoHeader("0123456789abcdef0123456789abcdef", 1, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(h)
	if bytes.Contains(b, key) || strings.Contains(string(b), "correct horse") {
		t.Fatal("key or passphrase in the repository file")
	}
	h2, err := ParseRepoHeader(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := h2.Unlock("correct horse battery")
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := h2.Unlock("correct horse batterz"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// The ID is bound to the wrapped key.
	h3 := h2
	h3.ID = "ffffffffffffffffffffffffffffffff"
	if _, err := h3.Unlock("correct horse battery"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("changed ID: %v", err)
	}
	for name, mut := range map[string]func(*RepoHeader){
		"memory too large": func(h *RepoHeader) { h.KDF.MemoryKiB = 4 << 20 },
		"time too large":   func(h *RepoHeader) { h.KDF.Time = 100 },
		"other kdf":        func(h *RepoHeader) { h.KDF.Name = "pbkdf2" },
		"short salt":       func(h *RepoHeader) { h.KDF.Salt = h.KDF.Salt[:8] },
		"version":          func(h *RepoHeader) { h.Version = 2 },
		"bad id":           func(h *RepoHeader) { h.ID = "../x" },
	} {
		c := h
		mut(&c)
		b, _ := json.Marshal(c)
		if _, err := ParseRepoHeader(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// AT-F14-06 at repository level: manifests and objects are verified.
func TestRepoObjects(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	tg, err := OpenLocal(LocalConfig{Path: dir}, []string{dir})
	if err != nil {
		t.Fatal(err)
	}
	r, err := InitRepo(ctx, tg, "correct horse battery", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InitRepo(ctx, tg, "correct horse battery", time.Now()); !errors.Is(err, ErrRepoExists) {
		t.Fatalf("second init: %v", err)
	}
	id := NewSnapshotID(time.Now())
	data := bytes.Repeat([]byte("kernhaven "), 300000)
	e, err := r.WriteObject(ctx, id, ObjectEntry{File: 0, Kind: KindVolume, Stack: "app", Volume: "app_data"}, bytes.NewReader(data))
	if err != nil || e.Size != int64(len(data)) || e.Stored <= e.Size || len(e.SHA256) != 64 {
		t.Fatalf("write: %+v %v", e, err)
	}
	if l, _ := r.ListSnapshots(ctx); len(l.Incomplete) != 1 || len(l.Complete) != 0 {
		t.Fatalf("before manifest: %+v", l)
	}
	if err := r.WriteManifest(ctx, Manifest{ID: id, Objects: []ObjectEntry{e}}); err != nil {
		t.Fatal(err)
	}
	r2, err := OpenRepo(ctx, tg, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenRepo(ctx, tg, "wrong passphrase!"); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	if _, err := OpenRepoKey(ctx, tg, "ffffffffffffffffffffffffffffffff", r.Key()); err == nil {
		t.Fatal("other repository ID accepted")
	}
	m, err := r2.ReadManifest(ctx, id)
	if err != nil || len(m.Objects) != 1 {
		t.Fatalf("manifest %+v %v", m, err)
	}
	read := func(e ObjectEntry) ([]byte, error) {
		rc, err := r2.OpenObject(ctx, id, e)
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(rc)
	}
	if got, err := read(m.Objects[0]); err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read: %v", err)
	}
	// A manifest that does not match the object is detected at the end.
	bad := m.Objects[0]
	bad.SHA256 = strings.Repeat("0", 64)
	if _, err := read(bad); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("hash mismatch: %v", err)
	}
	bad = m.Objects[0]
	bad.Kind = KindDatabase // another object's identity derives another key
	if _, err := read(bad); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("identity mismatch: %v", err)
	}
	// A manifest copied to another snapshot is refused.
	other := NewSnapshotID(time.Now().Add(time.Second))
	rc, _ := tg.Get(ctx, "snapshots/"+id+"/manifest.khb")
	if _, err := tg.Put(ctx, "snapshots/"+other+"/manifest.khb", rc); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	if _, err := r2.ReadManifest(ctx, other); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("moved manifest: %v", err)
	}
	if err := r2.DeleteSnapshot(ctx, other); err != nil {
		t.Fatal(err)
	}
	if err := r2.DeleteSnapshot(ctx, id); err != nil {
		t.Fatal(err)
	}
	if l, _ := r2.ListSnapshots(ctx); len(l.Complete)+len(l.Incomplete) != 0 {
		t.Fatalf("after delete: %+v", l)
	}
}
