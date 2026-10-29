// Package backup implements encrypted, scheduled backups and restores (M16,
// ADR-0029, ADR-0030).
package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// Format constants (ADR-0029). Changing any of them breaks existing backups.
const (
	RepoFile     = "kernhaven-repo.json"
	repoFormat   = "kernhaven-backup"
	repoVersion  = 1
	objectMagic  = "KHB1"
	saltSize     = 32
	segmentSize  = 1 << 20
	tagSize      = 16
	keySize      = 32
	minPassLen   = 12
	maxSegments  = 1 << 40 // far below the 2^88 nonce space
	kdfTime      = 3
	kdfMemoryKiB = 64 << 10
	kdfThreads   = 4
)

// ErrCorrupt means data failed authentication: it was damaged, truncated,
// reordered, swapped between objects or written with another key.
var ErrCorrupt = errors.New("backup data is corrupted or was tampered with")

// ErrPassphrase means the passphrase does not unlock the repository key.
var ErrPassphrase = errors.New("the passphrase does not unlock this repository")

// KDF describes the Argon2id parameters wrapping the repository key.
type KDF struct {
	Name      string `json:"name"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      []byte `json:"salt"`
}

// RepoHeader is the only plaintext file on the target. It holds the data key
// wrapped with a key derived from the passphrase, never the key itself
// (AT-F14-01).
type RepoHeader struct {
	Format     string `json:"format"`
	Version    int    `json:"version"`
	ID         string `json:"id"`
	CreatedMS  int64  `json:"created_ms"`
	KDF        KDF    `json:"kdf"`
	WrappedKey []byte `json:"wrapped_key"`
}

func keyAAD(id string) []byte { return []byte("kernhaven-backup key v1 " + id) }

func kek(pass string, k KDF) []byte {
	return argon2.IDKey([]byte(pass), k.Salt, k.Time, k.MemoryKiB, k.Threads, keySize)
}

func gcm(key []byte) cipher.AEAD {
	b, err := aes.NewCipher(key)
	if err != nil {
		panic(err) // key sizes are fixed
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		panic(err)
	}
	return a
}

// ValidatePassphrase enforces the minimum length of repository passphrases.
func ValidatePassphrase(p string) error {
	if len([]rune(p)) < minPassLen {
		return fmt.Errorf("the passphrase must have at least %d characters", minPassLen)
	}
	if len(p) > 1024 {
		return errors.New("the passphrase is too long")
	}
	return nil
}

// NewRepoHeader creates a random data key and wraps it with pass.
func NewRepoHeader(id string, createdMS int64, pass string) (RepoHeader, []byte, error) {
	if err := ValidatePassphrase(pass); err != nil {
		return RepoHeader{}, nil, err
	}
	key := make([]byte, keySize)
	salt := make([]byte, saltSize)
	nonce := make([]byte, 12)
	for _, b := range [][]byte{key, salt, nonce} {
		if _, err := rand.Read(b); err != nil {
			return RepoHeader{}, nil, err
		}
	}
	k := KDF{Name: "argon2id", Time: kdfTime, MemoryKiB: kdfMemoryKiB, Threads: kdfThreads, Salt: salt}
	wrapped := gcm(kek(pass, k)).Seal(nonce, nonce, key, keyAAD(id))
	return RepoHeader{Format: repoFormat, Version: repoVersion, ID: id, CreatedMS: createdMS, KDF: k, WrappedKey: wrapped}, key, nil
}

// ParseRepoHeader decodes and checks the plaintext repository file.
func ParseRepoHeader(b []byte) (RepoHeader, error) {
	var h RepoHeader
	if err := json.Unmarshal(b, &h); err != nil || h.Format != repoFormat {
		return h, errors.New("the target does not contain a Kernhaven backup repository")
	}
	if h.Version != repoVersion {
		return h, fmt.Errorf("unsupported repository version %d", h.Version)
	}
	// Bounded parameters: a forged header must not make unlocking take
	// unbounded memory or time.
	if h.KDF.Name != "argon2id" || h.KDF.Time < 1 || h.KDF.Time > 10 || h.KDF.MemoryKiB < 8<<10 || h.KDF.MemoryKiB > 1<<20 ||
		h.KDF.Threads < 1 || h.KDF.Threads > 16 || len(h.KDF.Salt) != saltSize || len(h.WrappedKey) != 12+keySize+tagSize || !validRepoID(h.ID) {
		return h, errors.New("the repository file is invalid")
	}
	return h, nil
}

// Unlock returns the data key.
func (h RepoHeader) Unlock(pass string) ([]byte, error) {
	key, err := gcm(kek(pass, h.KDF)).Open(nil, h.WrappedKey[:12], h.WrappedKey[12:], keyAAD(h.ID))
	if err != nil {
		return nil, ErrPassphrase
	}
	return key, nil
}

// objectKey derives the key of one object; binding repository, snapshot and
// object name means an object cannot be moved to another place unnoticed.
func objectKey(master, salt []byte, repo, snapshot, name string) []byte {
	k, err := hkdf.Key(sha256.New, master, salt, "kernhaven-backup v1 object "+repo+"/"+snapshot+"/"+name, keySize)
	if err != nil {
		panic(err)
	}
	return k
}

func nonce(counter uint64, last bool) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[3:11], counter)
	if last {
		n[11] = 1
	}
	return n
}

// Encrypter writes one object in the STREAM construction: segments of 1 MiB
// sealed with AES-256-GCM under a per-object key, nonces carrying a counter
// and a last-segment flag, so truncation and reordering fail.
type Encrypter struct {
	w       io.Writer
	aead    cipher.AEAD
	buf     []byte
	counter uint64
	closed  bool
	written int64
}

// NewEncrypter writes the object header and returns the encrypter. Close
// must be called to write the final segment.
func NewEncrypter(w io.Writer, master []byte, repo, snapshot, name string) (*Encrypter, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := w.Write(append([]byte(objectMagic), salt...)); err != nil {
		return nil, err
	}
	return &Encrypter{w: w, aead: gcm(objectKey(master, salt, repo, snapshot, name)), buf: make([]byte, 0, segmentSize), written: int64(len(objectMagic) + saltSize)}, nil
}

func (e *Encrypter) flush(last bool) error {
	if e.counter >= maxSegments {
		return errors.New("object too large")
	}
	out := e.aead.Seal(nil, nonce(e.counter, last), e.buf, nil)
	e.counter++
	e.buf = e.buf[:0]
	n, err := e.w.Write(out)
	e.written += int64(n)
	return err
}

// Write buffers p and writes every full segment.
func (e *Encrypter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("write after close")
	}
	n := len(p)
	for len(p) > 0 {
		c := copy(e.buf[len(e.buf):segmentSize], p)
		e.buf = e.buf[:len(e.buf)+c]
		p = p[c:]
		// A full segment is written only once more data follows, so the
		// final segment always carries the last flag.
		if len(e.buf) == segmentSize && len(p) > 0 {
			if err := e.flush(false); err != nil {
				return n - len(p), err
			}
		}
	}
	return n, nil
}

// Close writes the final segment (possibly empty).
func (e *Encrypter) Close() error {
	if e.closed {
		return nil
	}
	e.closed = true
	return e.flush(true)
}

// Written is the number of ciphertext bytes produced so far.
func (e *Encrypter) Written() int64 { return e.written }

// Decrypter reads an object written by Encrypter. Read returns ErrCorrupt
// for any authentication failure and never returns unauthenticated data.
type Decrypter struct {
	r       *bufio.Reader
	aead    cipher.AEAD
	seg     []byte
	pbuf    []byte
	plain   []byte
	counter uint64
	done    bool
	err     error
}

// NewDecrypter reads the object header.
func NewDecrypter(r io.Reader, master []byte, repo, snapshot, name string) (*Decrypter, error) {
	hdr := make([]byte, len(objectMagic)+saltSize)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, ErrCorrupt
	}
	if string(hdr[:len(objectMagic)]) != objectMagic {
		return nil, ErrCorrupt
	}
	return &Decrypter{
		r:    bufio.NewReaderSize(r, segmentSize+tagSize+1),
		aead: gcm(objectKey(master, hdr[len(objectMagic):], repo, snapshot, name)),
		seg:  make([]byte, segmentSize+tagSize),
		pbuf: make([]byte, 0, segmentSize),
	}, nil
}

func (d *Decrypter) next() error {
	n, err := io.ReadFull(d.r, d.seg)
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF) || (err == nil && n == len(d.seg)):
	case errors.Is(err, io.EOF):
		return ErrCorrupt // the last segment is missing (truncated)
	case err != nil:
		return err
	}
	last := false
	if err != nil {
		last = true // short read: the final segment
	} else if _, perr := d.r.Peek(1); errors.Is(perr, io.EOF) {
		last = true
	} else if perr != nil {
		return perr
	}
	if n < tagSize || d.counter >= maxSegments {
		return ErrCorrupt
	}
	p, oerr := d.aead.Open(d.pbuf[:0], nonce(d.counter, last), d.seg[:n], nil)
	if oerr != nil {
		return ErrCorrupt
	}
	if !last && len(p) != segmentSize {
		return ErrCorrupt
	}
	d.counter++
	d.plain = p
	d.done = last
	return nil
}

// Read implements io.Reader.
func (d *Decrypter) Read(p []byte) (int, error) {
	for len(d.plain) == 0 {
		if d.err != nil {
			return 0, d.err
		}
		if d.done {
			return 0, io.EOF
		}
		if err := d.next(); err != nil {
			d.err = err
			return 0, err
		}
	}
	n := copy(p, d.plain)
	d.plain = d.plain[n:]
	return n, nil
}
