// Package files implements the file manager operations of the storage
// service (M10). Every operation opens its root with os.Root, so paths cannot
// leave the root through ".." or symlinks (ADR-0023); relative paths are
// validated before that, and names starting with ".kernhaven-" are reserved.
package files

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Errors shown to users.
var (
	ErrNotFound = errors.New("no such file or folder")
	ErrExists   = errors.New("a file or folder with this name already exists")
)

// InvalidError is a request the service refuses.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{fmt.Sprintf(format, a...)} }

// OffsetError means an upload chunk does not continue the staged data.
type OffsetError struct{ Size int64 }

func (e *OffsetError) Error() string {
	return fmt.Sprintf("the upload continues at byte %d", e.Size)
}

// Limits and reserved names.
const (
	MaxChunk       = 8 << 20
	MaxEntries     = 10000
	reservedPrefix = ".kernhaven-"
	trashDir       = ".kernhaven-trash"
	uploadsDir     = ".kernhaven-uploads"
)

// Root is a configured file root.
type Root struct {
	Name string `toml:"name"`
	Path string `toml:"path"`
}

var (
	rootNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	uploadIDRe = regexp.MustCompile(`^[a-f0-9]{32}$`)
	trashIDRe  = regexp.MustCompile(`^([A-Za-z0-9_-]*)\.([0-9]{13}-[a-f0-9]{8})$`)
)

// Service performs file operations within the configured roots.
type Service struct {
	roots map[string]string
	names []string
	now   func() time.Time
}

// New validates the roots: names are unique and every path lies at or below
// mountRoot. Without roots, mountRoot itself is the root "data".
func New(roots []Root, mountRoot string) (*Service, error) {
	if len(roots) == 0 {
		roots = []Root{{Name: "data", Path: mountRoot}}
	}
	s := &Service{roots: map[string]string{}, now: time.Now}
	for _, r := range roots {
		if !rootNameRe.MatchString(r.Name) {
			return nil, fmt.Errorf("file root %q: name must be 1-31 lowercase letters, digits or -", r.Name)
		}
		if _, dup := s.roots[r.Name]; dup {
			return nil, fmt.Errorf("file root %q is configured twice", r.Name)
		}
		if !filepath.IsAbs(r.Path) || filepath.Clean(r.Path) != r.Path || (r.Path != mountRoot && !strings.HasPrefix(r.Path, mountRoot+"/")) {
			return nil, fmt.Errorf("file root %q: %q must be a clean path at or below %s", r.Name, r.Path, mountRoot)
		}
		s.roots[r.Name] = r.Path
		s.names = append(s.names, r.Name)
	}
	sort.Strings(s.names)
	return s, nil
}

// CleanPath validates a path relative to a root. "" and "." mean the root
// itself, which is allowed only when allowRoot is set.
func CleanPath(p string, allowRoot bool) (string, error) {
	if len(p) > 4096 || strings.ContainsRune(p, 0) {
		return "", invalid("invalid path")
	}
	if strings.HasPrefix(p, "/") {
		return "", invalid("paths are relative to the root")
	}
	c := path.Clean("./" + p)
	if c == "." {
		if allowRoot {
			return ".", nil
		}
		return "", invalid("this is not possible on the root folder itself")
	}
	if c == ".." || strings.HasPrefix(c, "../") {
		return "", invalid("the path leaves the root")
	}
	for _, part := range strings.Split(c, "/") {
		if len(part) > 255 {
			return "", invalid("a name is longer than 255 bytes")
		}
		if strings.HasPrefix(part, reservedPrefix) {
			return "", invalid("names starting with %s are reserved", reservedPrefix)
		}
	}
	return c, nil
}

func (s *Service) open(name string) (*os.Root, error) {
	p, ok := s.roots[name]
	if !ok {
		return nil, invalid("unknown file root %q", name)
	}
	r, err := os.OpenRoot(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w: root %s is not available (is its disk mounted?)", ErrNotFound, name)
	}
	return r, err
}

// mapErr turns file system errors into the service's errors.
func mapErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fs.ErrNotExist):
		return ErrNotFound
	case errors.Is(err, fs.ErrExist):
		return ErrExists
	case errors.Is(err, syscall.EXDEV):
		return invalid("moving between disks is not possible; copy, then delete")
	case errors.Is(err, syscall.ELOOP), strings.Contains(err.Error(), "escapes"):
		return invalid("the path leaves the root")
	case errors.Is(err, syscall.ENOSPC):
		return invalid("the disk is full")
	case errors.Is(err, syscall.ENOTEMPTY):
		return invalid("the folder is not empty")
	}
	return err
}

// Roots lists the roots with their free space.
func (s *Service) Roots() []agentproto.FileRoot {
	out := []agentproto.FileRoot{}
	for _, n := range s.names {
		r := agentproto.FileRoot{Name: n, Path: s.roots[n]}
		var st syscall.Statfs_t
		if fi, err := os.Stat(r.Path); err == nil && fi.IsDir() && syscall.Statfs(r.Path, &st) == nil {
			r.Available = true
			r.FreeBytes = int64(st.Bavail) * st.Bsize
			r.TotalBytes = int64(st.Blocks) * st.Bsize
		}
		out = append(out, r)
	}
	return out
}

func entryOf(name string, fi fs.FileInfo) agentproto.FileEntry {
	e := agentproto.FileEntry{Name: name, Size: fi.Size(), ModTime: fi.ModTime().UTC(), Mode: fi.Mode().Perm().String()}
	switch {
	case fi.Mode()&fs.ModeSymlink != 0:
		e.Type = "symlink"
	case fi.IsDir():
		e.Type = "dir"
	case fi.Mode().IsRegular():
		e.Type = "file"
	default:
		e.Type = "other"
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		e.UID, e.GID = st.Uid, st.Gid
	}
	return e
}

// List lists a folder.
func (s *Service) List(p agentproto.FilesPath) (agentproto.FilesListing, error) {
	c, err := CleanPath(p.Path, true)
	if err != nil {
		return agentproto.FilesListing{}, err
	}
	r, err := s.open(p.Root)
	if err != nil {
		return agentproto.FilesListing{}, err
	}
	defer r.Close()
	f, err := r.Open(c)
	if err != nil {
		return agentproto.FilesListing{}, mapErr(err)
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.IsDir() {
		return agentproto.FilesListing{}, invalid("not a folder")
	}
	list, err := f.ReadDir(-1)
	if err != nil {
		return agentproto.FilesListing{}, mapErr(err)
	}
	out := agentproto.FilesListing{Path: strings.TrimPrefix(c, "."), Entries: []agentproto.FileEntry{}}
	for _, d := range list {
		if strings.HasPrefix(d.Name(), reservedPrefix) {
			continue
		}
		if len(out.Entries) == MaxEntries {
			out.Truncated = true
			break
		}
		fi, err := d.Info()
		if err != nil {
			continue
		}
		out.Entries = append(out.Entries, entryOf(d.Name(), fi))
	}
	sort.Slice(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if (a.Type == "dir") != (b.Type == "dir") {
			return a.Type == "dir"
		}
		return strings.ToLower(a.Name) < strings.ToLower(b.Name)
	})
	return out, nil
}

func owner(fi fs.FileInfo) (int, int) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}

// inherit gives name the owner of its parent folder, so apps keep access to
// what users create for them.
func inherit(r *os.Root, name string) error {
	pfi, err := r.Stat(path.Dir(name))
	if err != nil {
		return mapErr(err)
	}
	fi, err := r.Lstat(name)
	if err != nil {
		return mapErr(err)
	}
	pu, pg := owner(pfi)
	u, g := owner(fi)
	if pu < 0 || (pu == u && pg == g) {
		return nil
	}
	return mapErr(r.Lchown(name, pu, pg))
}

func requireDir(r *os.Root, dir string) error {
	fi, err := r.Stat(dir)
	if err != nil {
		return mapErr(err)
	}
	if !fi.IsDir() {
		return invalid("%s is not a folder", dir)
	}
	return nil
}

// Mkdir creates a folder.
func (s *Service) Mkdir(p agentproto.FilesPath) error {
	c, err := CleanPath(p.Path, false)
	if err != nil {
		return err
	}
	r, err := s.open(p.Root)
	if err != nil {
		return err
	}
	defer r.Close()
	if err := requireDir(r, path.Dir(c)); err != nil {
		return err
	}
	if err := r.Mkdir(c, 0o755); err != nil {
		return mapErr(err)
	}
	return inherit(r, c)
}

// Rename moves a file or folder within one root, never overwriting.
func (s *Service) Rename(p agentproto.FilesRename) error {
	from, err := CleanPath(p.From, false)
	if err != nil {
		return err
	}
	to, err := CleanPath(p.To, false)
	if err != nil {
		return err
	}
	if from == to || strings.HasPrefix(to, from+"/") {
		return invalid("a folder cannot be moved into itself")
	}
	r, err := s.open(p.Root)
	if err != nil {
		return err
	}
	defer r.Close()
	if _, err := r.Lstat(from); err != nil {
		return mapErr(err)
	}
	if _, err := r.Lstat(to); err == nil {
		return ErrExists
	}
	if err := requireDir(r, path.Dir(to)); err != nil {
		return err
	}
	return mapErr(r.Rename(from, to))
}

// ctxReader stops a copy when the context ends.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// Copy copies a file or folder within or between roots, never overwriting.
// Symlinks and special files are skipped and counted.
func (s *Service) Copy(ctx context.Context, p agentproto.FilesCopy) (agentproto.FilesCopyResult, error) {
	var res agentproto.FilesCopyResult
	from, err := CleanPath(p.From, false)
	if err != nil {
		return res, err
	}
	to, err := CleanPath(p.To, false)
	if err != nil {
		return res, err
	}
	toRoot := p.ToRoot
	if toRoot == "" {
		toRoot = p.Root
	}
	if toRoot == p.Root && (from == to || strings.HasPrefix(to, from+"/")) {
		return res, invalid("a folder cannot be copied into itself")
	}
	src, err := s.open(p.Root)
	if err != nil {
		return res, err
	}
	defer src.Close()
	dst, err := s.open(toRoot)
	if err != nil {
		return res, err
	}
	defer dst.Close()
	if _, err := src.Lstat(from); err != nil {
		return res, mapErr(err)
	}
	if _, err := dst.Lstat(to); err == nil {
		return res, ErrExists
	}
	if err := requireDir(dst, path.Dir(to)); err != nil {
		return res, err
	}
	err = copyTree(ctx, src, from, dst, to, &res)
	return res, mapErr(err)
}

func copyTree(ctx context.Context, src *os.Root, from string, dst *os.Root, to string, res *agentproto.FilesCopyResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	fi, err := src.Lstat(from)
	if err != nil {
		return err
	}
	switch {
	case fi.IsDir():
		if err := dst.Mkdir(to, fi.Mode().Perm()|0o700); err != nil {
			return err
		}
		if err := inherit(dst, to); err != nil {
			return err
		}
		d, err := src.Open(from)
		if err != nil {
			return err
		}
		list, err := d.ReadDir(-1)
		d.Close()
		if err != nil {
			return err
		}
		for _, e := range list {
			if strings.HasPrefix(e.Name(), reservedPrefix) {
				continue
			}
			if err := copyTree(ctx, src, path.Join(from, e.Name()), dst, path.Join(to, e.Name()), res); err != nil {
				return err
			}
		}
		return nil
	case fi.Mode().IsRegular():
		in, err := src.Open(from)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := dst.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fi.Mode().Perm())
		if err != nil {
			return err
		}
		n, err := io.Copy(out, ctxReader{ctx, in})
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = dst.Remove(to)
			return err
		}
		res.Files++
		res.Bytes += n
		_ = dst.Chtimes(to, fi.ModTime(), fi.ModTime())
		return inherit(dst, to)
	default:
		res.SkippedSymlinks++
		return nil
	}
}

func dev(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}

// fsTop returns the topmost folder (relative to the root) on the same file
// system as dir. Trash and upload staging live there, so moving into and out
// of them is a rename on one file system even when disks are mounted below
// the root.
func fsTop(r *os.Root, dir string) (string, error) {
	fi, err := r.Stat(dir)
	if err != nil {
		return "", mapErr(err)
	}
	d := dev(fi)
	cur := dir
	for cur != "." {
		parent := path.Dir(cur)
		pfi, err := r.Stat(parent)
		if err != nil {
			return "", mapErr(err)
		}
		if dev(pfi) != d {
			return cur, nil
		}
		cur = parent
	}
	return ".", nil
}

func token(now time.Time) string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%013d-%s", now.UnixMilli(), hex.EncodeToString(b))
}

type trashRecord struct {
	Path      string    `json:"path"`
	IsDir     bool      `json:"is_dir"`
	Size      int64     `json:"size"`
	DeletedAt time.Time `json:"deleted_at"`
	DeletedBy string    `json:"deleted_by"`
}

func encodeTop(top string) string {
	if top == "." {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(top))
}

func parseTrashID(id string) (top, tok string, err error) {
	m := trashIDRe.FindStringSubmatch(id)
	if m == nil {
		return "", "", invalid("invalid trash item")
	}
	top = "."
	if m[1] != "" {
		b, err := base64.RawURLEncoding.DecodeString(m[1])
		if err != nil {
			return "", "", invalid("invalid trash item")
		}
		if top, err = CleanPath(string(b), false); err != nil {
			return "", "", err
		}
	}
	return top, m[2], nil
}

// Trash moves a file or folder into the trash of its file system.
func (s *Service) Trash(p agentproto.FilesPath, actor string) (agentproto.TrashItem, error) {
	c, err := CleanPath(p.Path, false)
	if err != nil {
		return agentproto.TrashItem{}, err
	}
	r, err := s.open(p.Root)
	if err != nil {
		return agentproto.TrashItem{}, err
	}
	defer r.Close()
	fi, err := r.Lstat(c)
	if err != nil {
		return agentproto.TrashItem{}, mapErr(err)
	}
	top, err := fsTop(r, path.Dir(c))
	if err != nil {
		return agentproto.TrashItem{}, err
	}
	dir := path.Join(top, trashDir)
	if err := r.MkdirAll(dir, 0o700); err != nil {
		return agentproto.TrashItem{}, mapErr(err)
	}
	now := s.now().UTC()
	tok := token(now)
	if err := r.Mkdir(path.Join(dir, tok), 0o700); err != nil {
		return agentproto.TrashItem{}, mapErr(err)
	}
	rec := trashRecord{Path: c, IsDir: fi.IsDir(), Size: fi.Size(), DeletedAt: now, DeletedBy: actor}
	meta, _ := json.Marshal(rec)
	if err := r.WriteFile(path.Join(dir, tok+".json"), meta, 0o600); err != nil {
		return agentproto.TrashItem{}, mapErr(err)
	}
	if err := r.Rename(c, path.Join(dir, tok, path.Base(c))); err != nil {
		_ = r.Remove(path.Join(dir, tok+".json"))
		_ = r.Remove(path.Join(dir, tok))
		return agentproto.TrashItem{}, mapErr(err)
	}
	return agentproto.TrashItem{ID: encodeTop(top) + "." + tok, Path: c, IsDir: rec.IsDir, Size: rec.Size, DeletedAt: now, DeletedBy: actor}, nil
}

// trashTops are the folders whose trash is listed: the root and every folder
// directly below it that is another file system (mounted disks).
func trashTops(r *os.Root) []string {
	tops := []string{"."}
	rfi, err := r.Stat(".")
	if err != nil {
		return tops
	}
	d, err := r.Open(".")
	if err != nil {
		return tops
	}
	defer d.Close()
	list, _ := d.ReadDir(-1)
	for _, e := range list {
		if !e.IsDir() || strings.HasPrefix(e.Name(), reservedPrefix) {
			continue
		}
		if fi, err := r.Stat(e.Name()); err == nil && dev(fi) != dev(rfi) {
			tops = append(tops, e.Name())
		}
	}
	return tops
}

// TrashList lists the trash of a root, newest first.
func (s *Service) TrashList(p agentproto.FilesPath) ([]agentproto.TrashItem, error) {
	r, err := s.open(p.Root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out := []agentproto.TrashItem{}
	for _, top := range trashTops(r) {
		dir := path.Join(top, trashDir)
		d, err := r.Open(dir)
		if err != nil {
			continue
		}
		list, _ := d.ReadDir(-1)
		d.Close()
		for _, e := range list {
			tok, ok := strings.CutSuffix(e.Name(), ".json")
			if !ok {
				continue
			}
			b, err := r.ReadFile(path.Join(dir, e.Name()))
			if err != nil {
				continue
			}
			var rec trashRecord
			if json.Unmarshal(b, &rec) != nil {
				continue
			}
			out = append(out, agentproto.TrashItem{ID: encodeTop(top) + "." + tok, Path: rec.Path, IsDir: rec.IsDir, Size: rec.Size, DeletedAt: rec.DeletedAt, DeletedBy: rec.DeletedBy})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].DeletedAt.After(out[j].DeletedAt) })
	return out, nil
}

// Restore moves a trash item back to its original path.
func (s *Service) Restore(p agentproto.FilesTrashID) (string, error) {
	top, tok, err := parseTrashID(p.ID)
	if err != nil {
		return "", err
	}
	r, err := s.open(p.Root)
	if err != nil {
		return "", err
	}
	defer r.Close()
	dir := path.Join(top, trashDir)
	b, err := r.ReadFile(path.Join(dir, tok+".json"))
	if err != nil {
		return "", mapErr(err)
	}
	var rec trashRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return "", invalid("the trash record is damaged")
	}
	target, err := CleanPath(rec.Path, false)
	if err != nil {
		return "", err
	}
	if _, err := r.Lstat(target); err == nil {
		return "", fmt.Errorf("%w: %s", ErrExists, target)
	}
	if err := r.MkdirAll(path.Dir(target), 0o755); err != nil {
		return "", mapErr(err)
	}
	if err := r.Rename(path.Join(dir, tok, path.Base(target)), target); err != nil {
		return "", mapErr(err)
	}
	_ = r.Remove(path.Join(dir, tok))
	_ = r.Remove(path.Join(dir, tok+".json"))
	return target, nil
}

// Purge deletes one trash item, or the whole trash of the root if ID is empty.
func (s *Service) Purge(p agentproto.FilesTrashID) error {
	r, err := s.open(p.Root)
	if err != nil {
		return err
	}
	defer r.Close()
	if p.ID == "" {
		for _, top := range trashTops(r) {
			if err := r.RemoveAll(path.Join(top, trashDir)); err != nil {
				return mapErr(err)
			}
		}
		return nil
	}
	top, tok, err := parseTrashID(p.ID)
	if err != nil {
		return err
	}
	dir := path.Join(top, trashDir)
	if _, err := r.Lstat(path.Join(dir, tok+".json")); err != nil {
		return mapErr(err)
	}
	if err := r.RemoveAll(path.Join(dir, tok)); err != nil {
		return mapErr(err)
	}
	return mapErr(r.Remove(path.Join(dir, tok+".json")))
}

// Open opens a regular file for streaming, positioned at offset; the caller
// closes the returned reader.
func (s *Service) Open(p agentproto.FilesRead) (agentproto.FileMeta, io.ReadCloser, error) {
	c, err := CleanPath(p.Path, false)
	if err != nil {
		return agentproto.FileMeta{}, nil, err
	}
	if p.Offset < 0 || p.Limit < 0 {
		return agentproto.FileMeta{}, nil, invalid("invalid range")
	}
	r, err := s.open(p.Root)
	if err != nil {
		return agentproto.FileMeta{}, nil, err
	}
	defer r.Close()
	f, err := r.Open(c)
	if err != nil {
		return agentproto.FileMeta{}, nil, mapErr(err)
	}
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return agentproto.FileMeta{}, nil, invalid("not a file")
	}
	if p.Offset > 0 {
		if _, err := f.Seek(p.Offset, io.SeekStart); err != nil {
			f.Close()
			return agentproto.FileMeta{}, nil, err
		}
	}
	meta := agentproto.FileMeta{Name: path.Base(c), Size: fi.Size(), ModTime: fi.ModTime().UTC()}
	var rd io.Reader = f
	if p.Limit > 0 {
		rd = io.LimitReader(f, p.Limit)
	}
	return meta, readCloser{rd, f}, nil
}

type readCloser struct {
	io.Reader
	io.Closer
}

// staging returns the staged file of an upload into target (same file
// system as the target's folder).
func staging(r *os.Root, id, target string) (string, error) {
	if !uploadIDRe.MatchString(id) {
		return "", invalid("invalid upload")
	}
	if err := requireDir(r, path.Dir(target)); err != nil {
		return "", err
	}
	top, err := fsTop(r, path.Dir(target))
	if err != nil {
		return "", err
	}
	return path.Join(top, uploadsDir, id+".part"), nil
}

// Append adds body to a staged upload at offset. Offset -1 only reports the
// staged size. A chunk may be at most MaxChunk bytes.
func (s *Service) Append(p agentproto.UploadAppend, body io.Reader) (agentproto.UploadState, error) {
	c, err := CleanPath(p.Path, false)
	if err != nil {
		return agentproto.UploadState{}, err
	}
	r, err := s.open(p.Root)
	if err != nil {
		return agentproto.UploadState{}, err
	}
	defer r.Close()
	part, err := staging(r, p.ID, c)
	if err != nil {
		return agentproto.UploadState{}, err
	}
	if err := r.MkdirAll(path.Dir(part), 0o700); err != nil {
		return agentproto.UploadState{}, mapErr(err)
	}
	f, err := r.OpenFile(part, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return agentproto.UploadState{}, mapErr(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return agentproto.UploadState{}, err
	}
	if p.Offset == -1 {
		return agentproto.UploadState{Size: fi.Size()}, nil
	}
	if p.Offset != fi.Size() {
		return agentproto.UploadState{}, &OffsetError{Size: fi.Size()}
	}
	if _, err := f.Seek(p.Offset, io.SeekStart); err != nil {
		return agentproto.UploadState{}, err
	}
	n, err := io.Copy(f, io.LimitReader(body, MaxChunk+1))
	if err == nil && n > MaxChunk {
		err = invalid("a chunk may be at most %d bytes", MaxChunk)
	}
	if err != nil {
		_ = f.Truncate(p.Offset)
		return agentproto.UploadState{}, mapErr(err)
	}
	return agentproto.UploadState{Size: p.Offset + n}, nil
}

// Finish moves a complete staged upload into place, never overwriting.
func (s *Service) Finish(p agentproto.UploadFinish) error {
	c, err := CleanPath(p.Path, false)
	if err != nil {
		return err
	}
	r, err := s.open(p.Root)
	if err != nil {
		return err
	}
	defer r.Close()
	part, err := staging(r, p.ID, c)
	if err != nil {
		return err
	}
	fi, err := r.Lstat(part)
	if err != nil {
		return mapErr(err)
	}
	if fi.Size() != p.Size {
		return invalid("the upload is incomplete: %d of %d bytes", fi.Size(), p.Size)
	}
	if _, err := r.Lstat(c); err == nil {
		return ErrExists
	}
	if err := r.Rename(part, c); err != nil {
		return mapErr(err)
	}
	_ = r.Chmod(c, 0o644)
	return inherit(r, c)
}

// Abort removes a staged upload.
func (s *Service) Abort(p agentproto.UploadFinish) error {
	c, err := CleanPath(p.Path, false)
	if err != nil {
		return err
	}
	r, err := s.open(p.Root)
	if err != nil {
		return err
	}
	defer r.Close()
	part, err := staging(r, p.ID, c)
	if err != nil {
		return err
	}
	if err := r.Remove(part); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return mapErr(err)
	}
	return nil
}

// RootNames returns the configured root names.
func (s *Service) RootNames() []string { return append([]string(nil), s.names...) }
