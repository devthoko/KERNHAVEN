package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

var site = fstest.MapFS{
	"index.html":         {Data: []byte("<!doctype html><title>Kernhaven</title>")},
	"assets/app-abc.js":  {Data: []byte("console.log(1)")},
	"assets/app-abc.css": {Data: []byte("body{}")},
	"favicon.svg":        {Data: []byte("<svg/>")},
}

func get(h http.Handler, p string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", p, nil))
	return rec
}

// AT-F01-01
func TestServesIndexWithStrictCSP(t *testing.T) {
	h := Handler(site)
	for _, p := range []string{"/", "/users/3", "/jobs", "/index.html"} {
		rec := get(h, p)
		if p == "/index.html" {
			// ServeFile-style redirect is not used: index is served directly.
			if rec.Code != 200 {
				t.Fatalf("%s: %d", p, rec.Code)
			}
		}
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "<title>Kernhaven") {
			t.Fatalf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Content-Security-Policy") != CSP || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: headers %v", p, rec.Header())
		}
		if strings.Contains(CSP, "unsafe") {
			t.Fatal("CSP allows unsafe sources")
		}
	}
}

func TestServesAssetsWithCaching(t *testing.T) {
	h := Handler(site)
	rec := get(h, "/assets/app-abc.js")
	if rec.Code != 200 || rec.Body.String() != "console.log(1)" || !strings.Contains(rec.Header().Get("Content-Type"), "javascript") {
		t.Fatalf("asset: %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	if rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Fatalf("cache %q", rec.Header().Get("Cache-Control"))
	}
	if rec := get(h, "/favicon.svg"); rec.Header().Get("Cache-Control") != "no-cache" {
		t.Fatalf("favicon cache %q", rec.Header().Get("Cache-Control"))
	}
}

func TestMissingFilesAreNotIndex(t *testing.T) {
	h := Handler(site)
	for _, p := range []string{"/assets/missing.js", "/robots.txt", "/../../etc/passwd.txt"} {
		if rec := get(h, p); rec.Code != 404 || strings.Contains(rec.Body.String(), "<title>") {
			t.Errorf("%s: %d %q", p, rec.Code, rec.Body.String())
		}
	}
}

func TestTraversalStaysInsideFS(t *testing.T) {
	rec := get(Handler(site), "/assets/../../../etc/passwd")
	if strings.Contains(rec.Body.String(), "root:") {
		t.Fatal("path traversal")
	}
}

func TestWithoutBuildAnswers503(t *testing.T) {
	rec := get(Handler(fstest.MapFS{".gitkeep": {}}), "/")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "not included") {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestEmbeddedDistLoads(t *testing.T) {
	_ = Dist() // must not panic, with or without a UI build
}
