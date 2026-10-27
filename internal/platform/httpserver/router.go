package httpserver

import (
	"net"
	"net/http"
	"sort"
	"strings"
)

// Access declares who may call a route. Every route must declare one; there is
// no implicit default (deny by default, AT-F09-01).
type Access struct {
	public     bool
	permission string
}

// Public marks a route as reachable without authentication. Public routes are
// reviewed against an allow-list by the API contract test.
func Public() Access { return Access{public: true} }

// RequirePermission marks a route as requiring an authenticated session that
// holds permission p.
func RequirePermission(p string) Access {
	if p == "" {
		panic("httpserver: empty permission")
	}
	return Access{permission: p}
}

// IsPublic reports whether the route is public.
func (a Access) IsPublic() bool { return a.public }

// Permission returns the required permission ("" for public routes).
func (a Access) Permission() string { return a.permission }

// Guard wraps a handler so that it only runs for requests holding permission.
type Guard func(permission string, next http.Handler) http.Handler

// Route describes a registered route.
type Route struct {
	Pattern string
	Access  Access
}

// Router is a method-aware router that answers unmatched requests with the
// uniform JSON error body (404 or 405).
type Router struct {
	mux      *http.ServeMux
	guard    Guard
	routes   []Route
	fallback http.Handler
}

// SetFallback serves GET and HEAD requests that match no route and are not
// under /api/ (the web UI with client-side routing). It must only serve
// static, public content.
func (rt *Router) SetFallback(h http.Handler) { rt.fallback = h }

// NewRouter returns an empty router. guard protects non-public routes; it may
// be nil only if every route is public.
func NewRouter(guard Guard) *Router { return &Router{mux: http.NewServeMux(), guard: guard} }

// Handle registers h for a method-qualified pattern such as
// "GET /api/v1/health/live" with the given access.
func (rt *Router) Handle(pattern string, access Access, h http.Handler) {
	if len(pattern) == 0 || pattern[0] == '/' {
		panic("httpserver: route pattern must start with an HTTP method: " + pattern)
	}
	if !access.public && access.permission == "" {
		panic("httpserver: route " + pattern + " declares no access")
	}
	if !access.public {
		if rt.guard == nil {
			panic("httpserver: route " + pattern + " requires a permission but the router has no guard")
		}
		h = rt.guard(access.permission, h)
	}
	rt.mux.Handle(pattern, h)
	rt.routes = append(rt.routes, Route{Pattern: pattern, Access: access})
}

// HandleFunc is Handle for functions.
func (rt *Router) HandleFunc(pattern string, access Access, h func(http.ResponseWriter, *http.Request)) {
	rt.Handle(pattern, access, http.HandlerFunc(h))
}

// Routes returns all registered routes sorted by pattern.
func (rt *Router) Routes() []Route {
	out := append([]Route(nil), rt.routes...)
	sort.Slice(out, func(i, j int) bool { return out[i].Pattern < out[j].Pattern })
	return out
}

func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h, pattern := rt.mux.Handler(r)
	if pattern != "" {
		rt.mux.ServeHTTP(w, r)
		return
	}
	// The mux produced its own plain-text 404/405; capture it and reply in
	// the uniform format instead.
	rec := &discardWriter{header: http.Header{}}
	h.ServeHTTP(rec, r)
	if rec.status == http.StatusMethodNotAllowed {
		w.Header().Set("Allow", rec.header.Get("Allow"))
		WriteError(w, r, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if rt.fallback != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) && !IsAPIPath(r.URL.Path) {
		rt.fallback.ServeHTTP(w, r)
		return
	}
	WriteError(w, r, http.StatusNotFound, "not_found", "not found")
}

// IsAPIPath reports whether p belongs to the JSON API namespace.
func IsAPIPath(p string) bool { return p == "/api" || strings.HasPrefix(p, "/api/") }

type discardWriter struct {
	header http.Header
	status int
}

func (d *discardWriter) Header() http.Header         { return d.header }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(code int)        { d.status = code }

// ClientIP returns the client address. The Core only listens on loopback
// (ADR-0010), so a loopback peer is the local reverse proxy and the right-most
// X-Forwarded-For entry (appended by Caddy) is the client. Any other peer is
// used as-is.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !peer.IsLoopback() {
		return host
	}
	xff := r.Header.Values("X-Forwarded-For")
	if len(xff) == 0 {
		return host
	}
	parts := strings.Split(xff[len(xff)-1], ",")
	if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
		return ip.String()
	}
	return host
}

// IsSafeMethod reports whether m is a method without side effects.
func IsSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}
