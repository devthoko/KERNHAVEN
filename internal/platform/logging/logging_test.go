package logging

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestNewWritesJSONAndRespectsLevel(t *testing.T) {
	var buf bytes.Buffer
	log, err := New(&buf, "warn")
	if err != nil {
		t.Fatal(err)
	}
	log.Info("hidden")
	log.Warn("shown", "key", "va\"lue\n")
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("output is not a single JSON record: %q", buf.String())
	}
	if rec["msg"] != "shown" || rec["key"] != "va\"lue\n" {
		t.Fatalf("unexpected record %v", rec)
	}
}

func TestNewRejectsUnknownLevel(t *testing.T) {
	if _, err := New(&bytes.Buffer{}, "chatty"); err == nil {
		t.Fatal("expected error")
	}
}
