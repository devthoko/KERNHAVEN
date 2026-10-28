package certs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeCloudflare implements the parts of Cloudflare's API the client uses.
type fakeCloudflare struct {
	mu      sync.Mutex
	records map[string]map[string]any // id → record
	auth    []string
	paths   []string
}

func (f *fakeCloudflare) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.auth = append(f.auth, r.Header.Get("Authorization"))
	f.paths = append(f.paths, r.Method+" "+r.URL.RequestURI())
	reply := func(code int, result any, errs ...string) {
		es := []map[string]any{}
		for _, e := range errs {
			es = append(es, map[string]any{"code": 1000, "message": e})
		}
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(map[string]any{"success": len(errs) == 0, "errors": es, "result": result})
	}
	if r.Header.Get("Authorization") != "Bearer good-token" {
		reply(403, nil, "Authentication error")
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/zones":
		if r.URL.Query().Get("name") == "example.org" {
			reply(200, []map[string]string{{"id": "zone1", "name": "example.org"}})
			return
		}
		reply(200, []any{})
	case r.Method == http.MethodPost && r.URL.Path == "/zones/zone1/dns_records":
		var rec map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &rec)
		rec["id"] = "rec1"
		f.records["rec1"] = rec
		reply(200, rec)
	case r.Method == http.MethodDelete && r.URL.Path == "/zones/zone1/dns_records/rec1":
		delete(f.records, "rec1")
		reply(200, map[string]string{"id": "rec1"})
	default:
		reply(404, nil, "not found")
	}
}

func TestCloudflare(t *testing.T) {
	fake := &fakeCloudflare{records: map[string]map[string]any{}}
	srv := httptest.NewServer(fake)
	defer srv.Close()
	ctx := context.Background()
	c := newCloudflare("good-token", srv.URL)
	if err := c.Present(ctx, "_acme-challenge.home.lab.example.org", "token-value"); err != nil {
		t.Fatal(err)
	}
	rec := fake.records["rec1"]
	if rec["type"] != "TXT" || rec["name"] != "_acme-challenge.home.lab.example.org" || rec["content"] != "token-value" || rec["ttl"].(float64) != 120 {
		t.Fatalf("record %+v", rec)
	}
	// The closest zone is searched first, then its parents.
	want := []string{"GET /zones?name=home.lab.example.org", "GET /zones?name=lab.example.org", "GET /zones?name=example.org", "POST /zones/zone1/dns_records"}
	if strings.Join(fake.paths, ",") != strings.Join(want, ",") {
		t.Fatalf("requests %v", fake.paths)
	}
	if err := c.CleanUp(ctx, "_acme-challenge.home.lab.example.org", "token-value"); err != nil || len(fake.records) != 0 {
		t.Fatalf("cleanup: %v %v", err, fake.records)
	}
	if err := c.Present(ctx, "_acme-challenge.app.other.net", "v"); err == nil || !strings.Contains(err.Error(), "no zone for app.other.net") {
		t.Fatalf("foreign zone: %v", err)
	}
	if err := newCloudflare("bad", srv.URL).Present(ctx, "_acme-challenge.a.example.org", "v"); err == nil || !strings.Contains(err.Error(), "Authentication error") || strings.Contains(err.Error(), "bad") {
		t.Fatalf("bad token: %v", err)
	}
	for _, a := range fake.auth {
		if !strings.HasPrefix(a, "Bearer ") {
			t.Fatalf("auth header %q", a)
		}
	}
}
