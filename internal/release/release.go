package release

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Release is a verified release directory.
type Release struct {
	Dir     string
	Comment string            // the signature's trusted comment
	Files   map[string]string // file name → SHA-256
}

var (
	sumLine = regexp.MustCompile(`^([0-9a-f]{64})  ([A-Za-z0-9._+~-]{1,128})$`)
	debName = regexp.MustCompile(`^kernhaven_([0-9]+\.[0-9]+\.[0-9]+(?:[~+-][0-9A-Za-z.~+-]{1,40})?)_(amd64|arm64)\.deb$`)
)

// Open verifies SHA256SUMS in dir with SHA256SUMS.minisig against keys.
func Open(dir string, keys []PublicKey) (Release, error) {
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		return Release{}, fmt.Errorf("the release has no SHA256SUMS: %w", err)
	}
	sig, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.minisig"))
	if err != nil {
		return Release{}, fmt.Errorf("the release is not signed (SHA256SUMS.minisig): %w", err)
	}
	comment, err := Verify(keys, sums, string(sig))
	if err != nil {
		return Release{}, err
	}
	r := Release{Dir: dir, Comment: comment, Files: map[string]string{}}
	for _, l := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		m := sumLine.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			return Release{}, fmt.Errorf("SHA256SUMS: malformed line %q", l)
		}
		r.Files[m[2]] = m[1]
	}
	return r, nil
}

// Package finds the .deb for arch and checks its hash. It returns the path
// and the package version.
func (r Release) Package(arch string) (string, string, error) {
	for name := range r.Files {
		m := debName.FindStringSubmatch(name)
		if m == nil || m[2] != arch {
			continue
		}
		p := filepath.Join(r.Dir, name)
		if err := r.Check(name); err != nil {
			return "", "", err
		}
		return p, m[1], nil
	}
	return "", "", fmt.Errorf("the release has no package for %s", arch)
}

// ErrMismatch means a file differs from its signed hash.
var ErrMismatch = errors.New("does not match the signed checksum")

// Check compares a listed file with its signed hash.
func (r Release) Check(name string) error {
	want, ok := r.Files[name]
	if !ok {
		return fmt.Errorf("%s is not part of the signed release", name)
	}
	f, err := os.Open(filepath.Join(r.Dir, name))
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != want {
		return fmt.Errorf("%s %w", name, ErrMismatch)
	}
	return nil
}

// ParsePackageName returns version and architecture of a package file name.
func ParsePackageName(name string) (string, string, bool) {
	m := debName.FindStringSubmatch(name)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}
