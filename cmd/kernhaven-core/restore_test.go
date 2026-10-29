package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

// M16: the restore command refuses bad input and never runs beside a Core.
func TestRestoreCommand(t *testing.T) {
	cfg, dataDir := writeConfig(t, freePort(t), "")
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	repo := filepath.Join(dir, "repo")
	if err := os.Mkdir(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(target, []byte(`{"kind":"local","config":{"path":"`+repo+`"}}`), 0o600)
	pass := filepath.Join(dir, "pass")
	_ = os.WriteFile(pass, []byte("correct horse battery staple\n"), 0o600)
	for _, args := range [][]string{
		{"restore"},
		{"restore", "-config", cfg},
		{"restore", "-config", cfg, "-target", filepath.Join(dir, "absent.json"), "-passphrase-file", pass},
	} {
		if code := run(context.Background(), args, io.Discard, io.Discard); code != exitConfig {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	// A running Core holds the data directory.
	unlock, err := store.LockDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	if code := run(context.Background(), []string{"restore", "-config", cfg, "-target", target, "-passphrase-file", pass}, io.Discard, &stderr); code != exitRuntime || !strings.Contains(stderr.String(), "running kernhaven-core") {
		t.Fatalf("locked: exit %d, %s", code, stderr.String())
	}
	unlock()
	// The local root is not allowed by the configuration.
	stderr.Reset()
	if code := run(context.Background(), []string{"restore", "-config", cfg, "-target", target, "-passphrase-file", pass}, io.Discard, &stderr); code != exitRuntime || !strings.Contains(stderr.String(), "backup roots") {
		t.Fatalf("outside roots: exit %d, %s", code, stderr.String())
	}
	// A Core does not start while a restore holds the lock.
	unlock, _ = store.LockDir(dataDir)
	defer unlock()
	stderr.Reset()
	if code := run(context.Background(), []string{"-config", cfg}, io.Discard, &stderr); code != exitDatabase || !strings.Contains(stderr.String(), "in use") {
		t.Fatalf("core beside a restore: exit %d, %s", code, stderr.String())
	}
}
