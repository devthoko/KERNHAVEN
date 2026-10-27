package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newKey(t testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func grant() Grant {
	return Grant{Op: OpContainersStart, ParamsSHA256: ParamsHash([]byte(`{"id":"web"}`)), Actor: "owner",
		RequestID: "r1", Nonce: NewNonce(), IssuedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(30 * time.Second).UnixMilli()}
}

// AT-M4-03
func TestSignVerifyRoundTrip(t *testing.T) {
	pub, priv := newKey(t)
	tok, err := Sign(priv, grant())
	if err != nil {
		t.Fatal(err)
	}
	g, err := Verify(pub, tok, now.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if g.Op != OpContainersStart || g.Actor != "owner" {
		t.Fatalf("grant %+v", g)
	}
}

// AT-M4-03: every kind of invalid grant is rejected.
func TestVerifyRejectsInvalidGrants(t *testing.T) {
	pub, priv := newKey(t)
	otherPub, otherPriv := newKey(t)
	_ = otherPub
	sign := func(k ed25519.PrivateKey, g Grant) string {
		tok, err := Sign(k, g)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}
	valid := sign(priv, grant())
	p, s, _ := strings.Cut(valid, ".")

	long := grant()
	long.ExpiresAtMS = long.IssuedAtMS + MaxGrantLifetime.Milliseconds() + 1
	backwards := grant()
	backwards.ExpiresAtMS = backwards.IssuedAtMS - 1
	noNonce := grant()
	noNonce.Nonce = ""
	badHash := grant()
	badHash.ParamsSHA256 = "abc"

	cases := map[string]struct {
		token string
		at    time.Time
		want  error
	}{
		"empty":           {"", now, ErrMalformedGrant},
		"no dot":          {p, now, ErrMalformedGrant},
		"bad base64":      {"!!!." + s, now, ErrMalformedGrant},
		"short signature": {p + ".AAAA", now, ErrMalformedGrant},
		"wrong key":       {sign(otherPriv, grant()), now, ErrBadSignature},
		"tampered":        {b64.EncodeToString([]byte(`{"op":"containers.start","params_sha256":"`+strings.Repeat("0", 64)+`","actor":"x","request_id":"","nonce":"n","iat":0,"exp":1}`)) + "." + s, now, ErrBadSignature},
		"expired":         {valid, now.Add(36 * time.Second), ErrExpired},
		"not yet valid":   {valid, now.Add(-6 * time.Second), ErrExpired},
		"too long":        {sign(priv, long), now, ErrLifetime},
		"backwards":       {sign(priv, backwards), now, ErrLifetime},
		"no nonce":        {sign(priv, noNonce), now, ErrMalformedGrant},
		"bad hash":        {sign(priv, badHash), now, ErrMalformedGrant},
		"oversized":       {strings.Repeat("a", 5000), now, ErrMalformedGrant},
	}
	for name, tc := range cases {
		if _, err := Verify(pub, tc.token, tc.at); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tc.want)
		}
	}
	// Clock skew tolerance.
	if _, err := Verify(pub, valid, now.Add(34*time.Second)); err != nil {
		t.Errorf("within skew: %v", err)
	}
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	pub, priv := newKey(t)
	pp := filepath.Join(dir, "k")
	if err := WritePrivateKey(pp, priv); err != nil {
		t.Fatal(err)
	}
	if err := WritePrivateKey(pp, priv); err == nil {
		t.Fatal("private key overwritten")
	}
	got, err := ReadPrivateKey(pp)
	if err != nil || !got.Equal(priv) {
		t.Fatalf("read private: %v", err)
	}
	if err := os.Chmod(pp, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPrivateKey(pp); err == nil {
		t.Fatal("group-readable private key accepted")
	}
	pubPath := filepath.Join(dir, "k.pub")
	if err := WritePublicKey(pubPath, pub); err != nil {
		t.Fatal(err)
	}
	if gp, err := ReadPublicKey(pubPath); err != nil || !gp.Equal(pub) {
		t.Fatalf("read public: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte("not a key\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadPublicKey(pubPath); err == nil {
		t.Fatal("garbage public key accepted")
	}
}

// Malformed grants never panic.
func FuzzVerify(f *testing.F) {
	pub, priv := newKey(f)
	tok, _ := Sign(priv, grant())
	f.Add(tok)
	f.Add("")
	f.Add("a.b")
	f.Add(strings.Replace(tok, ".", "..", 1))
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Verify(pub, s, now)
	})
}
