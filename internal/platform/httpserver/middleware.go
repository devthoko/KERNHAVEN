package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

type ctxKey int

const (
	requestIDKey ctxKey = iota
	loggerKey
)

func loggerFrom(ctx context.Context) *slog.Logger {
	l, _ := ctx.Value(loggerKey).(*slog.Logger)
	return l
}

// RequestID returns the request ID assigned by the middleware, or "".
func RequestID(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// securityHeaders are set on every response (AT-F00-04). HSTS is the reverse
// proxy's responsibility because the Core never terminates TLS.
var securityHeaders = map[string]string{
	"Content-Security-Policy":      "default-src 'none'; frame-ancestors 'none'",
	"X-Content-Type-Options":       "nosniff",
	"Referrer-Policy":              "no-referrer",
	"X-Frame-Options":              "DENY",
	"Cross-Origin-Opener-Policy":   "same-origin",
	"Cross-Origin-Resource-Policy": "same-origin",
	"Cache-Control":                "no-store",
}

// statusWriter records the status code and whether headers were sent.
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Middleware builds the standard chain:
// request ID → access log → panic recovery → security headers → body limit.
func Middleware(log *slog.Logger, maxBodyBytes int64, next http.Handler) http.Handler {
	return withRequestID(log, withAccessLog(log, withRecover(log, withSecurityHeaders(withBodyLimit(maxBodyBytes, next)))))
}

// withRequestID assigns a random request ID. Client-supplied IDs are ignored
// to keep log correlation trustworthy.
func withRequestID(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		id := hex.EncodeToString(b)
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		ctx = context.WithValue(ctx, loggerKey, log)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func withAccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		log.LogAttrs(r.Context(), slog.LevelInfo, "http request",
			slog.String("request_id", RequestID(r.Context())),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", status),
			slog.Int64("bytes", sw.bytes),
			slog.Duration("duration", time.Since(start)),
		)
	})
}

// withRecover turns handler panics into a generic 500 and logs the details
// (TH-07). http.ErrAbortHandler is re-raised as the server expects.
func withRecover(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		defer func() {
			p := recover()
			if p == nil {
				return
			}
			if p == http.ErrAbortHandler {
				panic(p)
			}
			log.LogAttrs(r.Context(), slog.LevelError, "handler panic",
				slog.String("request_id", RequestID(r.Context())),
				slog.String("panic", fmt.Sprint(p)),
				slog.String("stack", string(debug.Stack())),
			)
			if sw.status == 0 {
				WriteError(sw, r, http.StatusInternalServerError, "internal_error", "internal server error")
			}
		}()
		next.ServeHTTP(sw, r)
	})
}

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		for k, v := range securityHeaders {
			h.Set(k, v)
		}
		next.ServeHTTP(w, r)
	})
}

// withBodyLimit rejects declared oversized bodies immediately and caps the
// rest with http.MaxBytesReader.
func withBodyLimit(defaultLimit int64, next http.Handler) http.Handler {
	raised, _ := next.(interface {
		BodyLimit(*http.Request) (int64, bool)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		limit := defaultLimit
		if raised != nil {
			if l, ok := raised.BodyLimit(r); ok {
				limit = l
			}
		}
		if r.ContentLength > limit {
			WriteError(w, r, http.StatusRequestEntityTooLarge, "body_too_large",
				fmt.Sprintf("request body exceeds %d bytes", limit))
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}
