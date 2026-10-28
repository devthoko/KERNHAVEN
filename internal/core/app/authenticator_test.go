package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // TOTP test computation
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"
	"time"
)

// totpAt computes a TOTP code independently of the implementation under test.
func totpAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	h := hmac.New(sha1.New, key)
	h.Write(msg[:])
	s := h.Sum(nil)
	o := s[19] & 15
	v := binary.BigEndian.Uint32(s[o:o+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

// ---- a minimal software authenticator (ES256, "none" attestation) ----

var b64 = base64.RawURLEncoding

// cbor encodes the few CBOR shapes WebAuthn needs: maps with int or string
// keys, ints, strings and byte strings.
func cborHead(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)}
	}
}

type kv struct {
	k any
	v any
}

func cbor(v any) []byte {
	switch x := v.(type) {
	case int:
		if x >= 0 {
			return cborHead(0, uint64(x))
		}
		return cborHead(1, uint64(-1-x))
	case string:
		return append(cborHead(3, uint64(len(x))), x...)
	case []byte:
		return append(cborHead(2, uint64(len(x))), x...)
	case []kv:
		out := cborHead(5, uint64(len(x)))
		for _, e := range x {
			out = append(out, cbor(e.k)...)
			out = append(out, cbor(e.v)...)
		}
		return out
	}
	panic(fmt.Sprintf("cbor: %T", v))
}

type authenticator struct {
	t       *testing.T
	origin  string
	rpID    string
	key     *ecdsa.PrivateKey
	credID  []byte
	handle  []byte
	counter uint32
}

func newAuthenticator(t *testing.T) *authenticator {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	u, _ := url.Parse(testOrigin)
	return &authenticator{t: t, origin: testOrigin, rpID: u.Hostname(), key: key, credID: id}
}

type ceremony struct {
	Token   string `json:"token"`
	Options struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
			User      struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	} `json:"options"`
}

func (a *authenticator) clientData(typ, challenge string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false})
	return b
}

func (a *authenticator) authData(attested bool) []byte {
	rp := sha256.Sum256([]byte(a.rpID))
	flags := byte(0x01 | 0x04) // user present, user verified
	if attested {
		flags |= 0x40
	}
	out := append(rp[:], flags)
	out = binary.BigEndian.AppendUint32(out, a.counter)
	if attested {
		out = append(out, make([]byte, 16)...) // AAGUID
		out = binary.BigEndian.AppendUint16(out, uint16(len(a.credID)))
		out = append(out, a.credID...)
		x, y := a.key.X.FillBytes(make([]byte, 32)), a.key.Y.FillBytes(make([]byte, 32))
		out = append(out, cbor([]kv{{1, 2}, {3, -7}, {-1, 1}, {-2, x}, {-3, y}})...)
	}
	return out
}

// create answers a registration ceremony.
func (a *authenticator) create(c ceremony) map[string]any {
	handle, err := b64.DecodeString(c.Options.PublicKey.User.ID)
	if err != nil {
		a.t.Fatalf("user id: %v", err)
	}
	a.handle = handle
	att := cbor([]kv{{"fmt", "none"}, {"attStmt", []kv{}}, {"authData", a.authData(true)}})
	return map[string]any{"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(a.clientData("webauthn.create", c.Options.PublicKey.Challenge)),
			"attestationObject": b64.EncodeToString(att), "transports": []string{"internal"}},
		"clientExtensionResults": map[string]any{}}
}

// get answers an authentication ceremony; it increments the counter.
func (a *authenticator) get(c ceremony) map[string]any {
	a.counter++
	return a.sign(c.Options.PublicKey.Challenge)
}

func (a *authenticator) sign(challenge string) map[string]any {
	ad := a.authData(false)
	cd := a.clientData("webauthn.get", challenge)
	h := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, ad...), h[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.key, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	return map[string]any{"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64.EncodeToString(cd), "authenticatorData": b64.EncodeToString(ad),
			"signature": b64.EncodeToString(sig), "userHandle": b64.EncodeToString(a.handle)},
		"clientExtensionResults": map[string]any{}}
}
