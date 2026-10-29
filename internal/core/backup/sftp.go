package backup

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
)

// SFTPConfig is a directory on an SSH server. HostKey is required: the
// server's key is pinned, never accepted on first use without confirmation.
type SFTPConfig struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	Path    string `json:"path"`
	HostKey string `json:"host_key"` // authorized_keys format
}

// SFTPAuth holds the credentials: the Core's own key (generated per
// repository) or a password.
type SFTPAuth struct {
	PrivateKey []byte `json:"private_key,omitempty"` // Ed25519 seed
	Password   string `json:"password,omitempty"`
	// PEM is an administrator's own key, used only by the offline restore.
	PEM []byte `json:"-"`
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\@\r\n\t") {
		return false
	}
	return true
}

func (c *SFTPConfig) validate() error {
	c.Host = strings.TrimSpace(c.Host)
	if !validHost(c.Host) {
		return targetErr("host is invalid")
	}
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Port < 1 || c.Port > 65535 {
		return targetErr("port must be 1..65535")
	}
	if c.User == "" || len(c.User) > 64 || strings.ContainsAny(c.User, " /\\:@\r\n\t") {
		return targetErr("user is invalid")
	}
	if !path.IsAbs(c.Path) || path.Clean(c.Path) != c.Path || c.Path == "/" || strings.ContainsAny(c.Path, "\r\n\x00") {
		return targetErr("path must be an absolute, clean directory other than /")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(c.HostKey)); err != nil {
		return targetErr("host_key must be the server's public key (scan it first and compare the fingerprint)")
	}
	return nil
}

// NewSFTPKey creates the Core's key for one repository.
func NewSFTPKey() (SFTPAuth, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return SFTPAuth{}, "", err
	}
	a := SFTPAuth{PrivateKey: priv.Seed()}
	pub, err := a.PublicKey()
	return a, pub, err
}

// PublicKey is the authorized_keys line to install on the server.
func (a SFTPAuth) PublicKey() (string, error) {
	if len(a.PrivateKey) != ed25519.SeedSize {
		return "", errors.New("no key")
	}
	pk, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(a.PrivateKey).Public())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pk))) + " kernhaven-backup", nil
}

func (a SFTPAuth) methods() ([]ssh.AuthMethod, error) {
	var m []ssh.AuthMethod
	if len(a.PrivateKey) == ed25519.SeedSize {
		s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(a.PrivateKey))
		if err != nil {
			return nil, err
		}
		m = append(m, ssh.PublicKeys(s))
	}
	if len(a.PEM) > 0 {
		s, err := ssh.ParsePrivateKey(a.PEM)
		if err != nil {
			return nil, targetErr("the private key cannot be read (it must not be encrypted): %v", err)
		}
		m = append(m, ssh.PublicKeys(s))
	}
	if a.Password != "" {
		m = append(m, ssh.Password(a.Password))
	}
	if len(m) == 0 {
		return nil, targetErr("a key or a password is required")
	}
	return m, nil
}

// ScanHostKey connects to the server and returns its host key and SHA-256
// fingerprint, for the administrator to compare before saving (no trust on
// first use without confirmation).
func ScanHostKey(ctx context.Context, g netguard.Guard, host string, port int) (key, fingerprint string, err error) {
	if !validHost(host) || port < 0 || port > 65535 {
		return "", "", targetErr("host or port is invalid")
	}
	if port == 0 {
		port = 22
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := g.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	var got ssh.PublicKey
	errScanned := errors.New("scanned")
	_, _, _, err = ssh.NewClientConn(conn, host, &ssh.ClientConfig{
		User: "kernhaven-scan",
		HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
			got = k
			return errScanned
		},
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256},
	})
	if got == nil {
		return "", "", fmt.Errorf("no host key received: %w", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(got))), ssh.FingerprintSHA256(got), nil
}

type sftpTarget struct {
	ssh  *ssh.Client
	c    *sftp.Client
	base string
}

// OpenSFTP connects and checks that the directory exists.
func OpenSFTP(ctx context.Context, g netguard.Guard, c SFTPConfig, a SFTPAuth) (Target, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	pinned, _, _, _, _ := ssh.ParseAuthorizedKey([]byte(c.HostKey))
	methods, err := a.methods()
	if err != nil {
		return nil, err
	}
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	conn, err := g.DialContext(dctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	cc, chans, reqs, err := ssh.NewClientConn(conn, addr, &ssh.ClientConfig{
		User:              c.User,
		Auth:              methods,
		HostKeyCallback:   ssh.FixedHostKey(pinned),
		HostKeyAlgorithms: []string{pinned.Type()},
		Timeout:           20 * time.Second,
	})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh: %w", err)
	}
	_ = conn.SetDeadline(time.Time{})
	client := ssh.NewClient(cc, chans, reqs)
	sc, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("sftp: %w", err)
	}
	fi, err := sc.Stat(c.Path)
	if err != nil || !fi.IsDir() {
		sc.Close()
		client.Close()
		return nil, targetErr("directory %s does not exist on the server", c.Path)
	}
	return &sftpTarget{ssh: client, c: sc, base: c.Path}, nil
}

func (t *sftpTarget) p(name string) string { return path.Join(t.base, name) }

func (t *sftpTarget) Put(ctx context.Context, name string, r io.Reader) (int64, error) {
	if err := checkName(name); err != nil {
		return 0, err
	}
	if dir := path.Dir(name); dir != "." {
		if err := t.c.MkdirAll(t.p(dir)); err != nil {
			return 0, err
		}
	}
	tmp := t.p(name + tmpSuffix())
	f, err := t.c.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(f, ctxReader{ctx, r})
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = t.c.PosixRename(tmp, t.p(name))
		if err != nil {
			// Servers without the posix-rename extension refuse to replace
			// files; only the repository file is ever replaced.
			_ = t.c.Remove(t.p(name))
			err = t.c.Rename(tmp, t.p(name))
		}
	}
	if err != nil {
		_ = t.c.Remove(tmp)
	}
	return n, err
}

func (t *sftpTarget) Get(_ context.Context, name string) (io.ReadCloser, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	f, err := t.c.Open(t.p(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotExist
	}
	return f, err
}

func (t *sftpTarget) List(_ context.Context, prefix string) ([]ObjectInfo, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	var out []ObjectInfo
	w := t.c.Walk(t.p(prefix))
	for w.Step() {
		if err := w.Err(); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				break
			}
			return nil, err
		}
		if !w.Stat().Mode().IsRegular() {
			continue
		}
		rel := strings.TrimPrefix(w.Path(), t.base+"/")
		if objectNameRe.MatchString(rel) {
			out = append(out, ObjectInfo{Name: rel, Size: w.Stat().Size()})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (t *sftpTarget) Delete(_ context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	err := t.c.Remove(t.p(name))
	if errors.Is(err, fs.ErrNotExist) {
		err = nil
	}
	if err == nil && strings.HasPrefix(name, "snapshots/") {
		_ = t.c.RemoveDirectory(t.p(path.Dir(name)))
	}
	return err
}

func (t *sftpTarget) Close() error {
	t.c.Close()
	return t.ssh.Close()
}
