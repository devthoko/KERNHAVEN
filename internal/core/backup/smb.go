package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cloudsoda/go-smb2"

	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
)

// SMBConfig is a directory in a Windows or Samba file share (a NAS). The
// Core speaks SMB 2/3 itself: nothing is mounted on the host and no root
// is needed (ADR-0036).
type SMBConfig struct {
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Share  string `json:"share"`
	Path   string `json:"path"` // directory inside the share, "" for its root
	User   string `json:"user"`
	Domain string `json:"domain"`
}

var (
	smbShareRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._$-]{0,79}$`)
	smbNameRe  = regexp.MustCompile(`^[^\\/:*?"<>|\x00-\x1f]{1,64}$`)
)

func (c *SMBConfig) validate() error {
	c.Host = strings.TrimSpace(c.Host)
	if !validHost(c.Host) {
		return targetErr("host is invalid")
	}
	if c.Port == 0 {
		c.Port = 445
	}
	if c.Port < 1 || c.Port > 65535 {
		return targetErr("port must be 1..65535")
	}
	if !smbShareRe.MatchString(c.Share) || strings.HasSuffix(c.Share, " ") {
		return targetErr("share must be the share's name (letters, digits, space, . _ - $), without slashes")
	}
	c.Path = strings.Trim(c.Path, "/")
	if c.Path != "" && (path.Clean(c.Path) != c.Path || strings.HasPrefix(c.Path, "..") || strings.Contains(c.Path, "/../") ||
		strings.ContainsAny(c.Path, "\\:*?\"<>|\x00\r\n")) {
		return targetErr("path must be a clean directory inside the share, with / between folders")
	}
	if !smbNameRe.MatchString(c.User) {
		return targetErr("user is invalid")
	}
	if c.Domain != "" && !smbNameRe.MatchString(c.Domain) {
		return targetErr("domain is invalid")
	}
	return nil
}

type smbTarget struct {
	conn    net.Conn
	session *smb2.Session
	share   *smb2.Share
	base    string
}

// OpenSMB connects, signs in and checks that the directory exists. Message
// signing is required: without it a machine in the middle could change
// what is stored or read. Interim STATUS_PENDING answers are the one
// unsigned message the protocol allows (MS-SMB2 3.2.5.1.3); the library
// skips only those. SMB 1 is not supported at all. Confidentiality
// does not depend on SMB encryption, because every object is already
// encrypted by the repository format (ADR-0029).
func OpenSMB(ctx context.Context, g netguard.Guard, c SMBConfig, password string) (Target, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	if password == "" {
		return nil, targetErr("a password is required")
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	conn, err := g.DialContext(dctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if err != nil {
		return nil, err
	}
	d := &smb2.Dialer{
		Negotiator: smb2.Negotiator{RequireMessageSigning: true},
		Initiator:  &smb2.NTLMInitiator{User: c.User, Password: password, Domain: c.Domain},
	}
	session, err := d.DialConn(dctx, conn, conn.RemoteAddr().String())
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smb: %w", err)
	}
	share, err := session.Mount(`\\` + c.Host + `\` + c.Share)
	if err != nil {
		_ = session.Logoff()
		conn.Close()
		return nil, targetErr("share %s cannot be opened: %v", c.Share, err)
	}
	t := &smbTarget{conn: conn, session: session, share: share, base: c.Path}
	if c.Path != "" {
		fi, err := share.Stat(c.Path)
		if err != nil || !fi.IsDir() {
			t.Close()
			return nil, targetErr("directory %s does not exist in share %s", c.Path, c.Share)
		}
	}
	return t, nil
}

func (t *smbTarget) p(name string) string {
	if t.base == "" {
		return name
	}
	return t.base + "/" + name
}

func (t *smbTarget) fs(ctx context.Context) *smb2.Share { return t.share.WithContext(ctx) }

func (t *smbTarget) Put(ctx context.Context, name string, r io.Reader) (int64, error) {
	if err := checkName(name); err != nil {
		return 0, err
	}
	s := t.fs(ctx)
	if dir := path.Dir(name); dir != "." {
		if err := s.MkdirAll(t.p(dir), 0o700); err != nil {
			return 0, err
		}
	}
	tmp := t.p(name + tmpSuffix())
	f, err := s.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, ctxReader{ctx, r})
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// SMB does not replace an existing file on rename; only the
		// repository file is ever replaced.
		if _, serr := s.Stat(t.p(name)); serr == nil {
			_ = s.Remove(t.p(name))
		}
		err = s.Rename(tmp, t.p(name))
	}
	if err != nil {
		_ = s.Remove(tmp)
	}
	return n, err
}

func (t *smbTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	f, err := t.fs(ctx).Open(t.p(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (t *smbTarget) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	root := t.base
	if root == "" {
		root = "."
	}
	var out []ObjectInfo
	dir := strings.TrimSuffix(prefix, "/")
	err := fs.WalkDir(t.fs(ctx).DirFS(root), dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == dir {
				return fs.SkipAll
			}
			return err
		}
		if d.Type().IsRegular() && objectNameRe.MatchString(p) {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			out = append(out, ObjectInfo{Name: p, Size: fi.Size()})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

func (t *smbTarget) Delete(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	s := t.fs(ctx)
	err := s.Remove(t.p(name))
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err == nil && strings.HasPrefix(name, "snapshots/") {
		_ = s.Remove(t.p(path.Dir(name))) // only succeeds once the directory is empty
	}
	return err
}

func (t *smbTarget) Close() error {
	_ = t.share.Umount()
	_ = t.session.Logoff()
	return t.conn.Close()
}
