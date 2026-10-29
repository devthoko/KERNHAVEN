//go:build integration

package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"os"
	"testing"
	"time"
)

// AT-F14-02 against a real S3 implementation (rclone serve s3 in CI):
// signatures, multipart uploads, listing and a verified snapshot.
func TestS3RealServer(t *testing.T) {
	endpoint := os.Getenv("KH_S3_ENDPOINT")
	if endpoint == "" {
		t.Fatal("KH_S3_ENDPOINT, KH_S3_ACCESS_KEY, KH_S3_SECRET_KEY and KH_S3_BUCKET must name an S3 test server")
	}
	ctx := context.Background()
	cfg := S3Config{Endpoint: endpoint, Bucket: os.Getenv("KH_S3_BUCKET"), AccessKeyID: os.Getenv("KH_S3_ACCESS_KEY"), PathStyle: true, Prefix: "it-" + NewSnapshotID(time.Now())[16:] + "/"}
	tg, err := OpenS3(ctx, loopback, cfg, os.Getenv("KH_S3_SECRET_KEY"), nil)
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
	data := make([]byte, 40<<20) // three parts
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
	// Wrong credentials are refused by the server.
	if _, err := OpenS3(ctx, loopback, cfg, "wrong-secret", nil); err == nil {
		t.Fatal("wrong secret accepted")
	}
	if err := r2.DeleteSnapshot(ctx, id); err != nil {
		t.Fatal(err)
	}
	_ = tg.Delete(ctx, RepoFile)
}
