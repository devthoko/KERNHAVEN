package upgrade

import (
	"bytes"
	"context"
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
	"time"

	"github.com/devthoko/KERNHAVEN/internal/release"
)

// fakeHost simulates dpkg, systemd and the Core: installing a package
// "runs" its version; versions containing "broken" never become healthy;
// a running Core of a new version migrates the database.
type fakeHost struct {
	t         *testing.T
	dataDir   string
	installed string
	running   bool
	log       []string
}

func (f *fakeHost) InstalledVersion(context.Context) (string, error) { return f.installed, nil }
func (f *fakeHost) Compare(_ context.Context, a, b string) (int, error) {
	return strings.Compare(a, b), nil
}
func (f *fakeHost) Install(_ context.Context, deb string, downgrade bool) error {
	v, _, ok := release.ParsePackageName(filepath.Base(deb))
	if !ok {
		return fmt.Errorf("bad package %s", deb)
	}
	if _, err := os.Stat(deb); err != nil {
		return err
	}
	f.installed = v
	f.log = append(f.log, fmt.Sprintf("install %s downgrade=%v", v, downgrade))
	return f.Start(context.Background(), CoreUnit) // postinst restarts the Core
}
func (f *fakeHost) Stop(_ context.Context, unit string) error {
	f.running = false
	f.log = append(f.log, "stop")
	return nil
}
func (f *fakeHost) Start(_ context.Context, unit string) error {
	f.running = true
	f.log = append(f.log, "start")
	// The new version migrates the database on start.
	db := filepath.Join(f.dataDir, "kernhaven.db")
	b, _ := os.ReadFile(db)
	if !bytes.Contains(b, []byte("schema "+f.installed)) {
		_ = os.WriteFile(db, append(b, []byte("\nschema "+f.installed)...), 0o600)
	}
	return nil
}
func (f *fakeHost) Healthy(_ context.Context, version string, _ time.Duration) error {
	if !f.running || f.installed != version {
		return fmt.Errorf("not running %s", version)
	}
	if strings.Contains(version, "broken") {
		return errors.New("the Core did not become ready")
	}
	return nil
}

func setup(t *testing.T) (*Upgrader, *fakeHost, func(version string) string) {
	t.Helper()
	root := t.TempDir()
	data, state, keys := filepath.Join(root, "data"), filepath.Join(root, "state"), filepath.Join(root, "keys")
	for _, d := range []string{data, state, keys} {
		_ = os.MkdirAll(d, 0o700)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	_ = os.WriteFile(filepath.Join(keys, "owner.pub"), []byte(release.FormatPublicKey(release.PublicKey{ID: 42, Key: pub})), 0o644)
	_ = os.WriteFile(filepath.Join(data, "kernhaven.db"), []byte("users: owner"), 0o600)
	_ = os.WriteFile(filepath.Join(data, "secrets.key"), []byte("key"), 0o600)
	host := &fakeHost{t: t, dataDir: data, installed: "1.0.0", running: true}
	u := &Upgrader{Sys: host, DataDir: data, StateDir: state, KeysDir: keys, Arch: "amd64", Out: &bytes.Buffer{}}
	makeRelease := func(version string) string {
		dir := filepath.Join(root, "release-"+version)
		_ = os.MkdirAll(dir, 0o755)
		name := "kernhaven_" + version + "_amd64.deb"
		body := []byte("package " + version)
		_ = os.WriteFile(filepath.Join(dir, name), body, 0o644)
		h := sha256.Sum256(body)
		sums := hex.EncodeToString(h[:]) + "  " + name + "\n"
		_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(sums), 0o644)
		_ = os.WriteFile(filepath.Join(dir, "SHA256SUMS.minisig"), []byte(release.Sign(42, priv, []byte(sums), "kernhaven "+version)), 0o644)
		return dir
	}
	// The installer cached the installed package.
	if err := u.CachePackage(filepath.Join(makeRelease("1.0.0"), "kernhaven_1.0.0_amd64.deb")); err != nil {
		t.Fatal(err)
	}
	return u, host, makeRelease
}

func db(t *testing.T, u *Upgrader) string {
	b, _ := os.ReadFile(filepath.Join(u.DataDir, "kernhaven.db"))
	return string(b)
}

// AT-F15-02: an upgrade takes a snapshot first and records the versions.
func TestUpgradeSucceeds(t *testing.T) {
	u, host, rel := setup(t)
	ctx := context.Background()
	if err := u.Apply(ctx, rel("1.1.0"), false); err != nil {
		t.Fatal(err)
	}
	st, _ := u.LoadState()
	if host.installed != "1.1.0" || st.Current != "1.1.0" || st.Previous != "1.0.0" || st.Snapshot == "" {
		t.Fatalf("state %+v, installed %s", st, host.installed)
	}
	snap, _ := os.ReadFile(filepath.Join(st.Snapshot, "kernhaven.db"))
	if string(snap) != "users: owner" || !strings.Contains(db(t, u), "schema 1.1.0") {
		t.Fatalf("snapshot %q db %q", snap, db(t, u))
	}
	if strings.Join(host.log, ",") != "stop,install 1.1.0 downgrade=false,start" {
		t.Fatalf("steps %v", host.log)
	}
	// Same or older versions need an explicit decision.
	if err := u.Apply(ctx, rel("1.1.0"), false); err == nil {
		t.Fatal("reinstall accepted")
	}
	if err := u.Apply(ctx, rel("0.9.0"), false); err == nil {
		t.Fatal("downgrade accepted")
	}

	// AT-F15-03 (manual): back to 1.0.0 with the database from before.
	_ = os.WriteFile(filepath.Join(u.DataDir, "kernhaven.db"), []byte("users: owner, alice\nschema 1.1.0"), 0o600)
	if err := u.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	st, _ = u.LoadState()
	if host.installed != "1.0.0" || st.Current != "1.0.0" || st.Previous != "" || !strings.HasPrefix(db(t, u), "users: owner\nschema 1.0.0") {
		t.Fatalf("after rollback: %+v %s %q", st, host.installed, db(t, u))
	}
	if err := u.Rollback(ctx); err == nil {
		t.Fatal("second rollback accepted")
	}
}

// AT-F15-03: a version that does not become healthy is rolled back with
// the database as it was.
func TestFailedUpgradeRollsBack(t *testing.T) {
	u, host, rel := setup(t)
	err := u.Apply(context.Background(), rel("1.1.0-broken"), false)
	if !errors.Is(err, ErrRolledBack) {
		t.Fatalf("apply: %v", err)
	}
	st, _ := u.LoadState()
	if host.installed != "1.0.0" || !host.running || st.Current != "1.0.0" || db(t, u) != "users: owner\nschema 1.0.0" {
		t.Fatalf("after rollback: installed %s running %v state %+v db %q", host.installed, host.running, st, db(t, u))
	}
	if _, err := os.Stat(u.packagePath("1.1.0-broken")); err == nil {
		t.Fatal("broken package cached")
	}
}

// AT-F15-01: nothing changes when the release is not trusted.
func TestUntrustedReleaseChangesNothing(t *testing.T) {
	u, host, rel := setup(t)
	dir := rel("1.1.0")
	_ = os.WriteFile(filepath.Join(dir, "kernhaven_1.1.0_amd64.deb"), []byte("tampered"), 0o644)
	if err := u.Apply(context.Background(), dir, false); !errors.Is(err, release.ErrMismatch) {
		t.Fatalf("tampered: %v", err)
	}
	_ = os.Remove(filepath.Join(u.KeysDir, "owner.pub"))
	if err := u.Apply(context.Background(), rel("1.2.0"), false); !errors.Is(err, release.ErrNoTrustedKey) {
		t.Fatalf("no key: %v", err)
	}
	if host.installed != "1.0.0" || len(host.log) != 0 {
		t.Fatalf("host changed: %v", host.log)
	}
}

// Without the installed package cached, an upgrade could not be rolled back.
func TestUpgradeNeedsCachedPackage(t *testing.T) {
	u, host, rel := setup(t)
	_ = os.Remove(u.packagePath("1.0.0"))
	if err := u.Apply(context.Background(), rel("1.1.0"), false); err == nil || !strings.Contains(err.Error(), "rolled back") && !strings.Contains(err.Error(), "install.sh") {
		t.Fatalf("apply: %v", err)
	}
	if len(host.log) != 0 {
		t.Fatalf("host changed: %v", host.log)
	}
}

func TestValidVersion(t *testing.T) {
	for v, ok := range map[string]bool{"1.0.0": true, "1.0.0~rc1": true, "1.0": false, "-1.0.0": false, "1.0.0; rm -rf /": false} {
		if validVersion(v) != ok {
			t.Errorf("%q", v)
		}
	}
}
