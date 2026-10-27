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
