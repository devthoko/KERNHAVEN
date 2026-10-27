package docker

import (
	"context"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDaemon serves h on a unix socket and returns the socket path.
func fakeDaemon(t *testing.T, h http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "d.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return sock
}

func versionHandler(api string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"Version":"29.0.0","ApiVersion":"` + api + `","Os":"linux","Arch":"amd64","KernelVersion":"7.0"}`))
	}
}

func TestNegotiatesAPIVersion(t *testing.T) {
	for api, want := range map[string]string{"1.52": "1.47", "1.45": "1.45"} {
		var mu sync.Mutex
		var seen string
		mux := http.NewServeMux()
		mux.HandleFunc("/version", versionHandler(api))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			seen = r.URL.Path
			mu.Unlock()
			w.Write([]byte("[]"))
		})
		c := New(fakeDaemon(t, mux), time.Second)
		if _, err := c.ListContainers(context.Background(), true); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		got := seen
		mu.Unlock()
		if got != "/v"+want+"/containers/json" {
			t.Errorf("daemon %s: path %s, want /v%s/...", api, got, want)
		}
	}
}

// AT-M4-07
func TestRejectsTooOldDaemon(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", versionHandler("1.41"))
	c := New(fakeDaemon(t, mux), time.Second)
	if _, err := c.ListContainers(context.Background(), false); !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "older") {
		t.Fatalf("err = %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/version", versionHandler("1.47"))
	mux.HandleFunc("/v1.47/containers/missing/json", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		w.Write([]byte(`{"message":"No such container: missing"}`))
	})
	mux.HandleFunc("/v1.47/containers/busy/start", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		w.Write([]byte(`{"message":"busy"}`))
	})
	mux.HandleFunc("/v1.47/containers/up/start", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(304) })
	mux.HandleFunc("/v1.47/containers/down/start", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("/v1.47/containers/broken/stop", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte(`{"message":"boom"}`))
	})
	mux.HandleFunc("/v1.47/containers/x/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("t") != "7" {
			t.Errorf("stop timeout query %q", r.URL.RawQuery)
		}
		w.WriteHeader(204)
	})
	c := New(fakeDaemon(t, mux), time.Second)
	ctx := context.Background()
	if _, err := c.Inspect(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404: %v", err)
	}
	if _, err := c.Start(ctx, "busy"); !errors.Is(err, ErrConflict) {
		t.Errorf("409: %v", err)
	}
	if changed, err := c.Start(ctx, "up"); err != nil || changed {
		t.Errorf("304: changed=%v err=%v", changed, err)
	}
	if changed, err := c.Start(ctx, "down"); err != nil || !changed {
		t.Errorf("204: changed=%v err=%v", changed, err)
	}
	if _, err := c.Stop(ctx, "broken", time.Second); !errors.Is(err, ErrUnavailable) {
		t.Errorf("500: %v", err)
	}
	if _, err := c.Stop(ctx, "x", 7*time.Second); err != nil {
		t.Errorf("stop: %v", err)
	}
}

// AT-M4-07: missing socket and hanging daemon are reported, not fatal.
func TestUnavailableDaemon(t *testing.T) {
	c := New(filepath.Join(t.TempDir(), "absent.sock"), time.Second)
	if _, err := c.Info(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("missing socket: %v", err)
	}
	block := make(chan struct{})
	defer close(block)
	hang := New(fakeDaemon(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block })), 200*time.Millisecond)
	start := time.Now()
	if _, err := hang.Info(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("hanging daemon: %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("timeout not applied")
	}
}

func TestPathEscaping(t *testing.T) {
	var mu sync.Mutex
	var raw string
	mux := http.NewServeMux()
	mux.HandleFunc("/version", versionHandler("1.47"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		raw = r.URL.EscapedPath()
		mu.Unlock()
		w.WriteHeader(404)
	})
	c := New(fakeDaemon(t, mux), time.Second)
	_, _ = c.Inspect(context.Background(), "../../images/x")
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(raw, "/images/") {
		t.Fatalf("reference escaped the path: %s", raw)
	}
}
