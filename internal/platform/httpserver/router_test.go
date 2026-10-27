package httpserver

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func expectPanic(t *testing.T, name string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatalf("%s: expected panic", name)
		}
	}()
	f()
}

func noop(http.ResponseWriter, *http.Request) {}

// AT-F09-01: routes cannot be registered without an access declaration.
func TestRouteWithoutAccessPanics(t *testing.T) {
	expectPanic(t, "zero access", func() { NewRouter(nil).HandleFunc("GET /x", Access{}, noop) })
	expectPanic(t, "empty permission", func() { RequirePermission("") })
	expectPanic(t, "permission without guard", func() { NewRouter(nil).HandleFunc("GET /x", RequirePermission("p"), noop) })
}

func TestGuardWrapsOnlyProtectedRoutes(t *testing.T) {
	var guarded []string
	guard := func(p string, next http.Handler) http.Handler {
		guarded = append(guarded, p)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
		})
	}
	rt := NewRouter(guard)
	rt.HandleFunc("GET /open", Public(), func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	rt.HandleFunc("GET /closed", RequirePermission("things.read"), func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })

	if len(guarded) != 1 || guarded[0] != "things.read" {
		t.Fatalf("guard calls = %v", guarded)
	}
	for path, want := range map[string]int{"/open": 204, "/closed": 401} {
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != want {
			t.Errorf("%s: status %d, want %d", path, rec.Code, want)
		}
	}
	routes := rt.Routes()
	if len(routes) != 2 || routes[0].Pattern != "GET /closed" || routes[0].Access.Permission() != "things.read" || !routes[1].Access.IsPublic() {
		t.Fatalf("routes = %+v", routes)
	}
}

func TestClientIP(t *testing.T) {
	cases := []struct {
		remote string
		xff    []string
		want   string
	}{
		{"203.0.113.9:4000", nil, "203.0.113.9"},
		{"203.0.113.9:4000", []string{"10.0.0.1"}, "203.0.113.9"}, // non-proxy peer: header ignored
		{"127.0.0.1:4000", nil, "127.0.0.1"},
		{"127.0.0.1:4000", []string{"198.51.100.7"}, "198.51.100.7"},
		{"127.0.0.1:4000", []string{"1.1.1.1, 198.51.100.7"}, "198.51.100.7"}, // spoofed left entry ignored
		{"127.0.0.1:4000", []string{"1.1.1.1", "198.51.100.8"}, "198.51.100.8"},
		{"[::1]:4000", []string{"2001:db8::1"}, "2001:db8::1"},
		{"127.0.0.1:4000", []string{"not-an-ip"}, "127.0.0.1"},
	}
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		for _, v := range tc.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := ClientIP(r); got != tc.want {
			t.Errorf("remote=%s xff=%v: got %s, want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func TestFallbackOnlyForNonAPIReads(t *testing.T) {
	rt := NewRouter(nil)
	rt.HandleFunc("GET /api/v1/x", Public(), func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	rt.SetFallback(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(299) }))
	cases := []struct {
		method, path string
		want         int
	}{
		{"GET", "/", 299},
		{"GET", "/users/5", 299},
		{"HEAD", "/jobs", 299},
		{"GET", "/api/v1/x", 204},
		{"GET", "/api/v1/missing", 404},
		{"GET", "/api", 404},
		{"POST", "/users", 404},
		{"DELETE", "/api/v1/x", 405},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		rt.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.want {
			t.Errorf("%s %s: %d, want %d", tc.method, tc.path, rec.Code, tc.want)
		}
	}
}
