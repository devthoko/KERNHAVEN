//go:build integration

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"
)

// AT-F14-02 against a real Samba server (container in CI, ADR-0036):
// signed SMB 3 sessions, every target operation, a verified snapshot.
func TestSMBRealServer(t *testing.T) {
	addr := os.Getenv("KH_SMB_ADDR")
	if addr == "" {
		t.Fatal("KH_SMB_ADDR, KH_SMB_SHARE, KH_SMB_USER and KH_SMB_PASSWORD must name an SMB test server")
	}
	host, portS, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portS)
	ctx := context.Background()
	password := os.Getenv("KH_SMB_PASSWORD")
	base := SMBConfig{Host: host, Port: port, Share: os.Getenv("KH_SMB_SHARE"), User: os.Getenv("KH_SMB_USER")}

	// The directory must exist; the Core never creates the repository root.
	dir := base
	dir.Path = "it-" + NewSnapshotID(time.Now())[16:]
	if _, err := OpenSMB(ctx, loopback, dir, password); err == nil {
		t.Fatal("missing directory accepted")
	}
	root, err := OpenSMB(ctx, loopback, base, password)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.(*smbTarget).share.MkdirAll(dir.Path, 0o700); err != nil {
		t.Fatal(err)
	}
	root.Close()

	tg, err := OpenSMB(ctx, loopback, dir, password)
	if err != nil {
		t.Fatal(err)
	}
	defer tg.Close()
	exerciseTarget(t, tg)

	r, err := InitRepo(ctx, tg, "integration test passphrase", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	id := NewSnapshotID(time.Now())
	data := make([]byte, 12<<20)
	_, _ = rand.Read(data)
	e, err := r.WriteObject(ctx, id, ObjectEntry{File: 0, Kind: KindVolume, Stack: "s", Volume: "v"}, bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.WriteManifest(ctx, Manifest{ID: id, Objects: []ObjectEntry{e}}); err != nil {
		t.Fatal(err)
	}
	r2, err := OpenRepo(ctx, tg, "integration test passphrase")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifySnapshot(ctx, r2, id); err != nil {
		t.Fatal(err)
	}
	rc, err := r2.OpenObject(ctx, id, e)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(rc)
	rc.Close()
	if err != nil || !bytes.Equal(got, data) {
		t.Fatalf("read back: %v", err)
	}
	if err := r2.DeleteSnapshot(ctx, id); err != nil {
		t.Fatal(err)
	}
	_ = tg.Delete(ctx, RepoFile)

	// Wrong credentials and unknown shares are refused by the server.
	if _, err := OpenSMB(ctx, loopback, base, "wrong-password"); err == nil {
		t.Fatal("wrong password accepted")
	}
	other := base
	other.Share = "missing"
	if _, err := OpenSMB(ctx, loopback, other, password); err == nil {
		t.Fatal("missing share accepted")
	}
}
