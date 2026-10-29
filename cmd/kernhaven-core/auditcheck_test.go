package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

// M17 (TH-52): audit-check verifies exports and their continuation.
func TestAuditCheckCommand(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	l := audit.New(db, time.Now)
	export := func(name string) string {
		var b bytes.Buffer
		if _, err := l.Export(ctx, audit.Filter{}, &b); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), name)
		_ = os.WriteFile(p, b.Bytes(), 0o600)
		return p
	}
	for i := range 3 {
		_ = l.Record(ctx, audit.Event{Actor: "alice", Action: "test", Target: string(rune('a' + i)), Result: audit.Success})
	}
	older := export("old.jsonl")
	_ = l.Record(ctx, audit.Event{Actor: "alice", Action: "test", Result: audit.Success})
	newer := export("new.jsonl")
	var out bytes.Buffer
	if code := run(ctx, []string{"audit-check", newer, older}, &out, io.Discard); code != exitOK || !strings.Contains(out.String(), `"last": 4`) {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	// A rewritten newest record of the older export is detected.
	b, _ := os.ReadFile(newer)
	forged := filepath.Join(t.TempDir(), "forged.jsonl")
	_ = os.WriteFile(forged, bytes.Replace(b, []byte(`"target":"c"`), []byte(`"target":"x"`), 1), 0o600)
	var stderr bytes.Buffer
	if code := run(ctx, []string{"audit-check", forged}, io.Discard, &stderr); code != exitRuntime || !strings.Contains(stderr.String(), "modified") {
		t.Fatalf("forged: %d %s", code, stderr.String())
	}
	if code := run(ctx, []string{"audit-check"}, io.Discard, io.Discard); code != exitConfig {
		t.Fatal("usage not enforced")
	}
	// The older export does not continue a newer one that lost records.
	stderr.Reset()
	if code := run(ctx, []string{"audit-check", older, newer}, io.Discard, &stderr); code != exitRuntime || !strings.Contains(stderr.String(), "does not continue") {
		t.Fatalf("reversed: %d %s", code, stderr.String())
	}
}
