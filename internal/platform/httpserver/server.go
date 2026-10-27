// Package httpserver provides the Core HTTP router, middleware and server
// lifecycle with a deny-by-default, hardened baseline.
package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// Router is a method-aware router that answers unmatched requests with the
// uniform JSON error body (404 or 405).
type Router struct {
	mux *http.ServeMux
}

// NewRouter returns an empty router; nothing is reachable until registered.
func NewRouter() *Router { return &Router{mux: http.NewServeMux()} }

// Handle registers h for a method-qualified pattern such as
// "GET /api/v1/health/live". Patterns without a method are rejected so every
// route states which methods it accepts.
func (rt *Router) Handle(pattern string, h http.Handler) {
	if len(pattern) == 0 || pattern[0] == '/' {
		panic("httpserver: route pattern must start with an HTTP method: " + pattern)
	}
	rt.mux.Handle(pattern, h)
}

// HandleFunc is Handle for functions.
func (rt *Router) HandleFunc(pattern string, h func(http.ResponseWriter, *http.Request)) {
	rt.Handle(pattern, http.HandlerFunc(h))
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
	WriteError(w, r, http.StatusNotFound, "not_found", "not found")
}

type discardWriter struct {
	header http.Header
	status int
}

func (d *discardWriter) Header() http.Header         { return d.header }
func (d *discardWriter) Write(b []byte) (int, error) { return len(b), nil }
func (d *discardWriter) WriteHeader(code int)        { d.status = code }

// Options configures the server lifecycle.
type Options struct {
	ShutdownTimeout time.Duration
	Logger          *slog.Logger
}

// NewServer returns an http.Server with conservative timeouts (TH-06).
func NewServer(h http.Handler, log *slog.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
}

// Run serves on ln until ctx is cancelled, then shuts down gracefully,
// waiting up to opts.ShutdownTimeout for in-flight requests (AT-F00-05).
func Run(ctx context.Context, ln net.Listener, h http.Handler, opts Options) error {
	srv := NewServer(h, opts.Logger)
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	opts.Logger.Info("shutting down", "timeout", opts.ShutdownTimeout.String())
	sctx, cancel := context.WithTimeout(context.Background(), opts.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		_ = srv.Close()
		return err
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
