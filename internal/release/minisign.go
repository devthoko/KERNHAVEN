// Package release verifies signed releases (M18, ADR-0013): a SHA256SUMS
// file signed with minisign by a key the owner holds offline, and the
// packages it lists.
package release

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// PublicKey is a minisign public key.
type PublicKey struct {
	ID  uint64
	Key ed25519.PublicKey
}

// KeyID formats the key ID as minisign prints it.
func (k PublicKey) KeyID() string { return fmt.Sprintf("%016X", k.ID) }

// Errors of verification.
var (
	ErrNoTrustedKey = errors.New("no release key is trusted on this host (see /etc/kernhaven/release-keys)")
	ErrUnknownKey   = errors.New("the release is signed with a key this host does not trust")
	ErrBadSignature = errors.New("the release signature is invalid")
)

func decodeLine(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

// ParsePublicKey reads a minisign public key file (comment line and key)
// or a bare base64 key.
func ParsePublicKey(text string) (PublicKey, error) {
	var line string
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "untrusted comment:") {
			line = l
			break
		}
	}
	b, err := decodeLine(line)
	if err != nil || len(b) != 42 || string(b[:2]) != "Ed" {
		return PublicKey{}, errors.New("not a minisign Ed25519 public key")
	}
	return PublicKey{ID: binary.LittleEndian.Uint64(b[2:10]), Key: ed25519.PublicKey(bytes.Clone(b[10:]))}, nil
}

// LoadKeys reads every *.pub file in dir.
func LoadKeys(dir string) ([]PublicKey, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.pub"))
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	var keys []PublicKey
	for _, n := range names {
		b, err := os.ReadFile(n)
		if err != nil {
			return nil, err
		}
		k, err := ParsePublicKey(string(b))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", n, err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Signature is a parsed minisign signature.
type Signature struct {
	Algorithm      string // "Ed" (legacy) or "ED" (prehashed)
	KeyID          uint64
	Sig            []byte
	TrustedComment string
	GlobalSig      []byte
}

// ParseSignature reads a .minisig file.
func ParseSignature(text string) (Signature, error) {
	sc := bufio.NewScanner(strings.NewReader(text))
	var lines []string
	for sc.Scan() {
		if l := strings.TrimRight(sc.Text(), "\r"); l != "" {
			lines = append(lines, l)
		}
	}
	if len(lines) != 4 || !strings.HasPrefix(lines[0], "untrusted comment:") || !strings.HasPrefix(lines[2], "trusted comment: ") {
		return Signature{}, errors.New("not a minisign signature")
	}
	b, err := decodeLine(lines[1])
	if err != nil || len(b) != 74 || (string(b[:2]) != "Ed" && string(b[:2]) != "ED") {
		return Signature{}, errors.New("not a minisign Ed25519 signature")
	}
	g, err := decodeLine(lines[3])
	if err != nil || len(g) != ed25519.SignatureSize {
		return Signature{}, errors.New("invalid global signature")
	}
	return Signature{Algorithm: string(b[:2]), KeyID: binary.LittleEndian.Uint64(b[2:10]), Sig: b[10:], TrustedComment: strings.TrimPrefix(lines[2], "trusted comment: "), GlobalSig: g}, nil
}

func digest(alg string, msg []byte) []byte {
	if alg == "ED" {
		h := blake2b.Sum512(msg)
		return h[:]
	}
	return msg
}

// Verify checks msg against sig with one of keys and returns the trusted
// comment (it carries the release version and time).
func Verify(keys []PublicKey, msg []byte, sigText string) (string, error) {
	if len(keys) == 0 {
		return "", ErrNoTrustedKey
	}
	sig, err := ParseSignature(sigText)
	if err != nil {
		return "", err
	}
	for _, k := range keys {
		if k.ID != sig.KeyID {
			continue
		}
		if !ed25519.Verify(k.Key, digest(sig.Algorithm, msg), sig.Sig) {
			return "", ErrBadSignature
		}
		// The global signature binds the trusted comment to the signature.
		if !ed25519.Verify(k.Key, append(bytes.Clone(sig.Sig), []byte(sig.TrustedComment)...), sig.GlobalSig) {
			return "", ErrBadSignature
		}
		return sig.TrustedComment, nil
	}
	return "", ErrUnknownKey
}

// Sign creates a prehashed minisign signature. Releases are signed with the
// owner's offline key using the minisign tool; this exists for tests and
// the development signing tool.
func Sign(id uint64, priv ed25519.PrivateKey, msg []byte, trusted string) string {
	sig := ed25519.Sign(priv, digest("ED", msg))
	head := make([]byte, 10)
	copy(head, "ED")
	binary.LittleEndian.PutUint64(head[2:], id)
	global := ed25519.Sign(priv, append(bytes.Clone(sig), []byte(trusted)...))
	return "untrusted comment: signature from kernhaven test key\n" +
		base64.StdEncoding.EncodeToString(append(head, sig...)) + "\n" +
		"trusted comment: " + trusted + "\n" +
		base64.StdEncoding.EncodeToString(global) + "\n"
}

// FormatPublicKey writes a public key in minisign's file format.
func FormatPublicKey(k PublicKey) string {
	b := make([]byte, 10, 42)
	copy(b, "Ed")
	binary.LittleEndian.PutUint64(b[2:], k.ID)
	b = append(b, k.Key...)
	return "untrusted comment: minisign public key " + k.KeyID() + "\n" + base64.StdEncoding.EncodeToString(b) + "\n"
}
