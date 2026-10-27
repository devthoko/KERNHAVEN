package secretbox

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// AT-F03-06
func TestSealOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), KeyFile)
	b, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %#o", fi.Mode().Perm())
	}
	ct, err := b.Seal("hunter2-password", "stack:1/var:DB")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("hunter2")) {
		t.Fatal("plaintext visible in ciphertext")
	}
	if pt, err := b.Open(ct, "stack:1/var:DB"); err != nil || pt != "hunter2-password" {
		t.Fatalf("open: %q %v", pt, err)
	}
	// Swapping a ciphertext to another variable fails (associated data).
	if _, err := b.Open(ct, "stack:1/var:OTHER"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("swapped context: %v", err)
	}
	ct[len(ct)-1] ^= 1
	if _, err := b.Open(ct, "stack:1/var:DB"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := b.Open([]byte("short"), "x"); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("short: %v", err)
	}
	// Same key after reopening; different nonce each time.
	b2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ct2, _ := b2.Seal("hunter2-password", "stack:1/var:DB")
	if pt, _ := b.Open(ct2, "stack:1/var:DB"); pt != "hunter2-password" {
		t.Fatal("reopened key differs")
	}
	ct3, _ := b2.Seal("hunter2-password", "stack:1/var:DB")
	if bytes.Equal(ct2, ct3) {
		t.Fatal("nonce reused")
	}
}

func TestKeyFileChecks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, KeyFile)
	if _, err := Open(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("world-readable key accepted")
	}
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("not base64!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(bad); err == nil {
		t.Fatal("garbage key accepted")
	}
}
