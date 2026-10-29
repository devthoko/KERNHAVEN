package release

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testKey(t *testing.T, id uint64) (PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PublicKey{ID: id, Key: pub}, priv
}

// A signature made by minisign 0.11 (prehashed, `minisign -S -m file`)
// cannot be produced here without the tool; the CI job signs with the real
// minisign and this package verifies it. Here the format round-trips.
func TestMinisignFormat(t *testing.T) {
	pk, priv := testKey(t, 0x1122334455667788)
	parsed, err := ParsePublicKey(FormatPublicKey(pk))
	if err != nil || parsed.ID != pk.ID || !parsed.Key.Equal(pk.Key) || parsed.KeyID() != "1122334455667788" {
		t.Fatalf("public key %v %v", parsed, err)
	}
	msg := []byte("abc  kernhaven_1.0.0_amd64.deb\n")
	sig := Sign(pk.ID, priv, msg, "kernhaven 1.0.0 timestamp:1700000000")
	comment, err := Verify([]PublicKey{pk}, msg, sig)
	if err != nil || comment != "kernhaven 1.0.0 timestamp:1700000000" {
		t.Fatalf("verify %q %v", comment, err)
	}
	other, otherPriv := testKey(t, 0x99)
	cases := map[string]struct {
		keys []PublicKey
		msg  []byte
		sig  string
		want error
	}{
		"no trusted key":                    {nil, msg, sig, ErrNoTrustedKey},
		"other key":                         {[]PublicKey{other}, msg, sig, ErrUnknownKey},
		"changed message":                   {[]PublicKey{pk}, append([]byte("x"), msg...), sig, ErrBadSignature},
		"changed comment":                   {[]PublicKey{pk}, msg, strings.Replace(sig, "kernhaven 1.0.0", "kernhaven 9.9.9", 1), ErrBadSignature},
		"same ID other key":                 {[]PublicKey{{ID: pk.ID, Key: other.Key}}, msg, sig, ErrBadSignature},
		"signed by another key with our ID": {[]PublicKey{pk}, msg, Sign(pk.ID, otherPriv, msg, "kernhaven 1.0.0"), ErrBadSignature},
	}
	for name, c := range cases {
		if _, err := Verify(c.keys, c.msg, c.sig); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
	for _, bad := range []string{"", "untrusted comment: x\nAAAA\n", strings.Replace(sig, "trusted comment: ", "comment: ", 1)} {
		if _, err := Verify([]PublicKey{pk}, msg, bad); err == nil {
			t.Errorf("malformed signature accepted: %q", bad)
		}
	}
	if _, err := ParsePublicKey("untrusted comment: x\nnot base64\n"); err == nil {
		t.Error("malformed key accepted")
	}
}

func writeRelease(t *testing.T, dir string, priv ed25519.PrivateKey, id uint64, files map[string]string) {
	t.Helper()
	var sums strings.Builder
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		h := sha256.Sum256([]byte(body))
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), name)
	}
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums.String()), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS.minisig"), []byte(Sign(id, priv, []byte(sums.String()), "kernhaven release")), 0o644)
}

// AT-F15-01: unsigned or mismatched artifacts are refused.
func TestRelease(t *testing.T) {
	pk, priv := testKey(t, 7)
	keysDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(keysDir, "owner.pub"), []byte(FormatPublicKey(pk)), 0o644)
	keys, err := LoadKeys(keysDir)
	if err != nil || len(keys) != 1 {
		t.Fatalf("keys %v %v", keys, err)
	}
	dir := t.TempDir()
	writeRelease(t, dir, priv, 7, map[string]string{"kernhaven_1.2.3_amd64.deb": "amd64 package", "kernhaven_1.2.3_arm64.deb": "arm64 package"})
	r, err := Open(dir, keys)
	if err != nil {
		t.Fatal(err)
	}
	p, v, err := r.Package("arm64")
	if err != nil || v != "1.2.3" || filepath.Base(p) != "kernhaven_1.2.3_arm64.deb" {
		t.Fatalf("package %s %s %v", p, v, err)
	}
	// A swapped package file is refused.
	_ = os.WriteFile(filepath.Join(dir, "kernhaven_1.2.3_amd64.deb"), []byte("evil package"), 0o644)
	if _, _, err := r.Package("amd64"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("swapped package: %v", err)
	}
	// A changed checksum list breaks the signature.
	_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(strings.Repeat("0", 64)+"  kernhaven_1.2.3_amd64.deb\n"), 0o644)
	if _, err := Open(dir, keys); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("changed sums: %v", err)
	}
	// Unsigned and untrusted releases are refused.
	_ = os.Remove(filepath.Join(dir, "SHA256SUMS.minisig"))
	if _, err := Open(dir, keys); err == nil {
		t.Fatal("unsigned release accepted")
	}
	if _, err := Open(dir, nil); err == nil {
		t.Fatal("release accepted without trusted keys")
	}
	for name, ok := range map[string]bool{"kernhaven_1.0.0_amd64.deb": true, "kernhaven_1.0.0~rc1_arm64.deb": true, "kernhaven_1.0_amd64.deb": false, "kernhaven_1.0.0_i386.deb": false, "../kernhaven_1.0.0_amd64.deb": false} {
		if _, _, got := ParsePackageName(name); got != ok {
			t.Errorf("%s: %v", name, got)
		}
	}
}
