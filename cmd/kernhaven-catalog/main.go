// Command kernhaven-catalog creates signing keys and signs app catalogs
// (ADR-0020). It runs on the catalog maintainer's machine, not on the server.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/catalog"
)

const usage = `usage:
  kernhaven-catalog keygen -key FILE           create a signing key (mode 0600) and print the trust key
  kernhaven-catalog pubkey -key FILE           print the trust key of a signing key
  kernhaven-catalog sign -key FILE -in CATALOG.json -out SIGNED.json
  kernhaven-catalog verify -pub TRUSTKEY -in SIGNED.json
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, time.Now))
}

func run(args []string, stdout, stderr io.Writer, now func() time.Time) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("kernhaven-catalog "+args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "", "signing key file")
	in := fs.String("in", "", "input file")
	out := fs.String("out", "", "output file")
	pubFlag := fs.String("pub", "", "base64 trust key")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() > 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "keygen":
		err = keygen(*keyPath, stdout)
	case "pubkey":
		var key ed25519.PrivateKey
		if key, err = readKey(*keyPath); err == nil {
			printTrustKey(stdout, key.Public().(ed25519.PublicKey))
		}
	case "sign":
		err = sign(*keyPath, *in, *out, stdout)
	case "verify":
		err = verify(*pubFlag, *in, stdout, now())
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}

func printTrustKey(w io.Writer, pub ed25519.PublicKey) {
	fmt.Fprintf(w, "trust key: %s\nkey id:    %s\n", base64.StdEncoding.EncodeToString(pub), catalog.KeyID(pub))
}

func keygen(path string, stdout io.Writer) error {
	if path == "" {
		return errors.New("-key is required")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	printTrustKey(stdout, pub)
	return nil
}

func readKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("-key is required")
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by other users (mode %o); run chmod 600", path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s is not a kernhaven-catalog signing key", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func sign(keyPath, in, out string, stdout io.Writer) error {
	if in == "" || out == "" {
		return errors.New("-in and -out are required")
	}
	key, err := readKey(keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	var c catalog.Catalog
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}
	signed, err := catalog.Sign(key, c)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, append(signed, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "signed %q serial %d (%d apps), key id %s\n", c.Name, c.Serial, len(c.Apps), catalog.KeyID(key.Public().(ed25519.PublicKey)))
	return nil
}

func verify(pub, in string, stdout io.Writer, now time.Time) error {
	key, err := catalog.ParsePublicKey(pub)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(in)
	if err != nil {
		return err
	}
	v, err := catalog.Open(raw, key, catalog.State{}, now)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "valid: %q serial %d, %d apps, expires %s\n", v.Catalog.Name, v.Catalog.Serial, len(v.Catalog.Apps), v.Catalog.Expires.UTC().Format(time.RFC3339))
	return nil
}
