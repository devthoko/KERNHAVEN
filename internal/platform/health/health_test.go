package health

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
	"github.com/devthoko/KERNHAVEN/internal/platform/version"
)

func setup(t *testing.T) (http.Handler, func(), *bytes.Buffer) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	rt := httpserver.NewRouter()
	Register(rt, db, log)
	return httpserver.Middleware(log, 1<<20, rt), func() { db.Close() }, &logs
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

// AT-F00-03
func TestLive(t *testing.T) {
	h, _, _ := setup(t)
	rec := get(h, "/api/v1/health/live")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body)
	}
}

// AT-F00-03: readiness reflects the real database state.
func TestReadyFailsWhenDatabaseUnavailable(t *testing.T) {
	h, closeDB, logs := setup(t)
	if rec := get(h, "/api/v1/health/ready"); rec.Code != http.StatusOK {
		t.Fatalf("ready before close: %d", rec.Code)
	}
	closeDB()
	rec := get(h, "/api/v1/health/ready")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready after close: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "closed") {
		t.Fatalf("readiness leaks error detail: %s", rec.Body)
	}
	if !strings.Contains(logs.String(), "readiness check failed") {
		t.Fatal("readiness failure not logged")
	}
}

// AT-F00-03
func TestVersion(t *testing.T) {
	h, _, _ := setup(t)
	rec := get(h, "/api/v1/version")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var info version.Info
	if err := json.NewDecoder(rec.Body).Decode(&info); err != nil {
		t.Fatal(err)
	}
	if info != version.Get() {
		t.Fatalf("version = %+v, want %+v", info, version.Get())
	}
}

func TestHealthRoutesRejectWrites(t *testing.T) {
	h, _, _ := setup(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/health/live", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
}
