package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	repoIDRe     = regexp.MustCompile(`^[0-9a-f]{32}$`)
	snapshotIDRe = regexp.MustCompile(`^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{6}$`)
)

func validRepoID(s string) bool { return repoIDRe.MatchString(s) }

// ValidSnapshotID reports whether s has the form of a snapshot ID.
func ValidSnapshotID(s string) bool { return snapshotIDRe.MatchString(s) }

// NewSnapshotID returns a time-ordered, unique snapshot ID.
func NewSnapshotID(now time.Time) string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return now.UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(b)
}

// Object kinds in a snapshot.
const (
	KindDatabase = "database"
	KindSecrets  = "secrets"
	KindConfig   = "config"
	KindVolume   = "volume"
)

// ObjectEntry describes one encrypted object of a snapshot.
type ObjectEntry struct {
	File   int    `json:"file"`
	Kind   string `json:"kind"`
	Stack  string `json:"stack,omitempty"`
	Volume string `json:"volume,omitempty"`
	Size   int64  `json:"size"`   // plaintext bytes
	Stored int64  `json:"stored"` // ciphertext bytes
	SHA256 string `json:"sha256"` // of the ciphertext
}

func (e ObjectEntry) name() string {
	return fmt.Sprintf("%d:%s:%s:%s", e.File, e.Kind, e.Stack, e.Volume)
}

func (e ObjectEntry) path(snapshot string) string {
	return fmt.Sprintf("snapshots/%s/%d.khb", snapshot, e.File)
}

// StackEntry records a stack whose volumes are in the snapshot.
type StackEntry struct {
	Name             string   `json:"name"`
	DeployedRevision int      `json:"deployed_revision"`
	Volumes          []string `json:"volumes"`
}

// Manifest lists a snapshot's objects; it is written last, so a snapshot
// without one is incomplete.
type Manifest struct {
	Version   int           `json:"version"`
	Repo      string        `json:"repo"`
	ID        string        `json:"id"`
	Plan      string        `json:"plan,omitempty"`
	CreatedMS int64         `json:"created_ms"`
	Host      string        `json:"host"`
	Kernhaven string        `json:"kernhaven"`
	Platform  bool          `json:"platform"`
	Objects   []ObjectEntry `json:"objects"`
	Stacks    []StackEntry  `json:"stacks"`
}

// Size is the stored size of all objects.
func (m Manifest) Size() int64 {
	var n int64
	for _, o := range m.Objects {
		n += o.Stored
	}
	return n
}

// Repo is an unlocked repository on a target.
type Repo struct {
	T      Target
	Header RepoHeader
	key    []byte
}

// ErrRepoExists means the target already holds a repository; connect to it
// with its passphrase instead.
var ErrRepoExists = errors.New("the target already contains a Kernhaven repository")

func readHeader(ctx context.Context, t Target) (RepoHeader, error) {
	rc, err := t.Get(ctx, RepoFile)
	if err != nil {
		return RepoHeader{}, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 64<<10))
	if err != nil {
		return RepoHeader{}, err
	}
	return ParseRepoHeader(b)
}

// InitRepo creates a repository on an empty target.
func InitRepo(ctx context.Context, t Target, pass string, now time.Time) (*Repo, error) {
	if _, err := readHeader(ctx, t); err == nil {
		return nil, ErrRepoExists
	} else if !errors.Is(err, ErrNotExist) {
		return nil, err
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	h, key, err := NewRepoHeader(hex.EncodeToString(id), now.UnixMilli(), pass)
	if err != nil {
		return nil, err
	}
	b, _ := json.MarshalIndent(h, "", "  ")
	if _, err := t.Put(ctx, RepoFile, bytes.NewReader(b)); err != nil {
		return nil, err
	}
	return &Repo{T: t, Header: h, key: key}, nil
}

// OpenRepo unlocks an existing repository with its passphrase.
func OpenRepo(ctx context.Context, t Target, pass string) (*Repo, error) {
	h, err := readHeader(ctx, t)
	if errors.Is(err, ErrNotExist) {
		return nil, errors.New("the target does not contain a Kernhaven repository")
	}
	if err != nil {
		return nil, err
	}
	key, err := h.Unlock(pass)
	if err != nil {
		return nil, err
	}
	return &Repo{T: t, Header: h, key: key}, nil
}

// OpenRepoKey opens a repository with the key the Core stored; the target
// must still hold the same repository.
func OpenRepoKey(ctx context.Context, t Target, id string, key []byte) (*Repo, error) {
	h, err := readHeader(ctx, t)
	if errors.Is(err, ErrNotExist) {
		return nil, errors.New("the repository file is missing on the target")
	}
	if err != nil {
		return nil, err
	}
	if h.ID != id || len(key) != keySize {
		return nil, errors.New("the target holds a different repository")
	}
	return &Repo{T: t, Header: h, key: key}, nil
}

// Key returns the data key (stored sealed by the Core).
func (r *Repo) Key() []byte { return r.key }

type hashCounter struct {
	h hash.Hash
	n int64
}

func (c *hashCounter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return c.h.Write(p)
}

// WriteObject encrypts src into object e.File of snapshot and fills in the
// sizes and hash.
func (r *Repo) WriteObject(ctx context.Context, snapshot string, e ObjectEntry, src io.Reader) (ObjectEntry, error) {
	pr, pw := io.Pipe()
	hc := &hashCounter{h: sha256.New()}
	go func() {
		enc, err := NewEncrypter(io.MultiWriter(pw, hc), r.key, r.Header.ID, snapshot, e.name())
		if err == nil {
			var n int64
			n, err = io.Copy(enc, ctxReader{ctx, src})
			e.Size = n
			if err == nil {
				err = enc.Close()
			}
		}
		pw.CloseWithError(err)
	}()
	stored, err := r.T.Put(ctx, e.path(snapshot), pr)
	pr.CloseWithError(errors.New("upload ended"))
	if err != nil {
		return e, err
	}
	e.Stored = stored
	if stored != hc.n {
		return e, fmt.Errorf("stored %d bytes, encrypted %d", stored, hc.n)
	}
	e.SHA256 = hex.EncodeToString(hc.h.Sum(nil))
	return e, nil
}

// WriteManifest completes a snapshot.
func (r *Repo) WriteManifest(ctx context.Context, m Manifest) error {
	m.Version, m.Repo = 1, r.Header.ID
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	enc, err := NewEncrypter(&buf, r.key, r.Header.ID, m.ID, "manifest")
	if err != nil {
		return err
	}
	if _, err := enc.Write(b); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	_, err = r.T.Put(ctx, "snapshots/"+m.ID+"/manifest.khb", &buf)
	return err
}

// ReadManifest reads and authenticates a snapshot's manifest.
func (r *Repo) ReadManifest(ctx context.Context, id string) (Manifest, error) {
	var m Manifest
	if !ValidSnapshotID(id) {
		return m, fmt.Errorf("invalid snapshot ID %q", id)
	}
	rc, err := r.T.Get(ctx, "snapshots/"+id+"/manifest.khb")
	if err != nil {
		return m, err
	}
	defer rc.Close()
	d, err := NewDecrypter(io.LimitReader(rc, 64<<20), r.key, r.Header.ID, id, "manifest")
	if err != nil {
		return m, err
	}
	b, err := io.ReadAll(d)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(b, &m); err != nil || m.ID != id || m.Repo != r.Header.ID || m.Version != 1 {
		return m, ErrCorrupt
	}
	seen := map[int]bool{}
	for _, o := range m.Objects {
		if seen[o.File] || o.File < 0 || o.File > 999999 {
			return m, ErrCorrupt
		}
		seen[o.File] = true
	}
	return m, nil
}

// verifyReader decrypts an object and, at its end, checks the stored size
// and hash recorded in the manifest.
type verifyReader struct {
	rc  io.ReadCloser
	d   *Decrypter
	hc  *hashCounter
	e   ObjectEntry
	n   int64
	err error
}

func (v *verifyReader) Read(p []byte) (int, error) {
	if v.err != nil {
		return 0, v.err
	}
	n, err := v.d.Read(p)
	v.n += int64(n)
	if errors.Is(err, io.EOF) {
		// Nothing may follow the final segment.
		if extra, _ := io.Copy(io.Discard, io.LimitReader(v.rc, 1)); extra > 0 {
			err = ErrCorrupt
		} else if v.hc.n != v.e.Stored || hex.EncodeToString(v.hc.h.Sum(nil)) != v.e.SHA256 || v.n != v.e.Size {
			err = ErrCorrupt
		}
	}
	if err != nil {
		v.err = err
	}
	return n, err
}

func (v *verifyReader) Close() error { return v.rc.Close() }

// OpenObject returns a reader of the object's plaintext. Read returns
// ErrCorrupt if anything does not match; data read before that is
// authenticated segment by segment.
func (r *Repo) OpenObject(ctx context.Context, snapshot string, e ObjectEntry) (io.ReadCloser, error) {
	rc, err := r.T.Get(ctx, e.path(snapshot))
	if errors.Is(err, ErrNotExist) {
		return nil, fmt.Errorf("%w: object %d is missing", ErrCorrupt, e.File)
	}
	if err != nil {
		return nil, err
	}
	hc := &hashCounter{h: sha256.New()}
	tee := io.TeeReader(rc, hc)
	d, err := NewDecrypter(tee, r.key, r.Header.ID, snapshot, e.name())
	if err != nil {
		rc.Close()
		return nil, err
	}
	return &verifyReader{rc: struct {
		io.Reader
		io.Closer
	}{tee, rc}, d: d, hc: hc, e: e}, nil
}

// SnapshotList is what a target holds.
type SnapshotList struct {
	Complete   []string // with a manifest, oldest first
	Incomplete []string
}

// ListSnapshots lists snapshot directories.
func (r *Repo) ListSnapshots(ctx context.Context) (SnapshotList, error) {
	objs, err := r.T.List(ctx, "snapshots/")
	if err != nil {
		return SnapshotList{}, err
	}
	ids := map[string]bool{}
	for _, o := range objs {
		parts := strings.Split(o.Name, "/")
		if len(parts) != 3 || !ValidSnapshotID(parts[1]) {
			continue
		}
		if parts[2] == "manifest.khb" {
			ids[parts[1]] = true
		} else if !ids[parts[1]] {
			ids[parts[1]] = false
		}
	}
	var l SnapshotList
	for id, complete := range ids {
		if complete {
			l.Complete = append(l.Complete, id)
		} else {
			l.Incomplete = append(l.Incomplete, id)
		}
	}
	sort.Strings(l.Complete)
	sort.Strings(l.Incomplete)
	return l, nil
}

// DeleteSnapshot removes the manifest first, so an interrupted deletion
// leaves an incomplete snapshot that is cleaned up later.
func (r *Repo) DeleteSnapshot(ctx context.Context, id string) error {
	if !ValidSnapshotID(id) {
		return fmt.Errorf("invalid snapshot ID %q", id)
	}
	if err := r.T.Delete(ctx, "snapshots/"+id+"/manifest.khb"); err != nil {
		return err
	}
	objs, err := r.T.List(ctx, "snapshots/"+id+"/")
	if err != nil {
		return err
	}
	for _, o := range objs {
		if err := r.T.Delete(ctx, o.Name); err != nil {
			return err
		}
	}
	return nil
}
