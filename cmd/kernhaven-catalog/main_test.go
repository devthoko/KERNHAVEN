package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const payload = `{
  "name": "Test",
  "serial": 1,
  "expires": "2027-01-01T00:00:00Z",
  "apps": [{
    "id": "hello", "name": "Hello", "version": "1", "summary": "Says hello", "categories": ["Tools"],
    "compose": "services:\n  app:\n    image: alpine:3\n    command: [\"sleep\", \"600\"]\n",
    "fields": [], "exceptions": []
  }]
}`

func TestKeygenSignVerify(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "catalog.key")
	now := func() time.Time { return time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC) }
	var out, errOut bytes.Buffer
	if code := run([]string{"keygen", "-key", key}, &out, &errOut, now); code != 0 {
		t.Fatalf("keygen: %d %s", code, errOut.String())
	}
	if st, _ := os.Stat(key); st.Mode().Perm() != 0o600 {
		t.Fatalf("key mode %o", st.Mode().Perm())
	}
	m := regexp.MustCompile(`trust key: (\S+)`).FindStringSubmatch(out.String())
	if m == nil {
		t.Fatalf("no trust key in %q", out.String())
	}
	if code := run([]string{"keygen", "-key", key}, &out, &errOut, now); code == 0 {
		t.Fatal("keygen overwrote an existing key")
	}

	in := filepath.Join(dir, "catalog.json")
	signed := filepath.Join(dir, "signed.json")
	if err := os.WriteFile(in, []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"sign", "-key", key, "-in", in, "-out", signed}, &out, &errOut, now); code != 0 {
		t.Fatalf("sign: %s", errOut.String())
	}
	out.Reset()
	if code := run([]string{"verify", "-pub", m[1], "-in", signed}, &out, &errOut, now); code != 0 || !strings.Contains(out.String(), "valid") {
		t.Fatalf("verify: %s %s", out.String(), errOut.String())
	}

	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	errOut.Reset()
	if code := run([]string{"sign", "-key", key, "-in", in, "-out", signed}, &out, &errOut, now); code == 0 || !strings.Contains(errOut.String(), "readable by other users") {
		t.Fatalf("world-readable key accepted: %s", errOut.String())
	}

	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte(strings.Replace(payload, `"id": "hello"`, `"id": "Hello World"`, 1)), 0o644)
	_ = os.Chmod(key, 0o600)
	if code := run([]string{"sign", "-key", key, "-in", bad, "-out", signed}, &out, &errOut, now); code == 0 {
		t.Fatal("invalid catalog signed")
	}
}
