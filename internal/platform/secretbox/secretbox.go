// Package secretbox encrypts small secrets at rest with AES-256-GCM using a
// key file in the data directory (ADR-0019).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// KeyFile is the key's file name inside the data directory.
const KeyFile = "secrets.key"

// Box encrypts and decrypts values.
type Box struct{ aead cipher.AEAD }

// ErrDecrypt means a ciphertext was modified, swapped or made with another key.
var ErrDecrypt = errors.New("secret cannot be decrypted")

// Open loads the key at path, creating it (mode 0600) if it does not exist.
func Open(path string) (*Box, error) {
	key, err := readKey(path)
	if errors.Is(err, os.ErrNotExist) {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return nil, err
		}
		_, werr := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n")
		serr := f.Sync()
		cerr := f.Close()
		if err := errors.Join(werr, serr, cerr); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

func readKey(path string) ([]byte, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %#o is too open; expected 0600", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != 32 {
		return nil, fmt.Errorf("%s: not a valid 256-bit key", path)
	}
	return key, nil
}

// Seal encrypts plaintext bound to context (e.g. "stack:3/var:DB_PASSWORD").
func (b *Box) Seal(plaintext, context string) ([]byte, error) {
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.aead.Seal(nonce, nonce, []byte(plaintext), []byte(context)), nil
}

// Open decrypts a value sealed with the same context.
func (b *Box) Open(ciphertext []byte, context string) (string, error) {
	n := b.aead.NonceSize()
	if len(ciphertext) < n+b.aead.Overhead() {
		return "", ErrDecrypt
	}
	pt, err := b.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(context))
	if err != nil {
		return "", ErrDecrypt
	}
	return string(pt), nil
}
