package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func testLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, nil))
}

// testHandler builds the full middleware chain around a router with test routes.
func testHandler(t *testing.T, logs *bytes.Buffer, limit int64) http.Handler {
	t.Helper()
	rt := NewRouter(nil)
	rt.HandleFunc("GET /ok", Public(), func(w http.ResponseWriter, r *http.Request) {
		WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	rt.HandleFunc("GET /panic", Public(), func(w http.ResponseWriter, r *http.Request) {
		panic("secret internal detail: db password is hunter2")
	})
	rt.HandleFunc("POST /echo", Public(), func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Name string `json:"name"`
		}
		if DecodeJSON(w, r, &in) != nil {
			return
		}
		WriteJSON(w, http.StatusOK, in)
	})
	return Middleware(testLogger(logs), limit, rt)
}

func decodeError(t *testing.T, body io.Reader) ErrorDetail {
	t.Helper()
	var eb ErrorBody
	if err := json.NewDecoder(body).Decode(&eb); err != nil {
		t.Fatalf("error body is not JSON: %v", err)
	}
	return eb.Error
}

// AT-F00-04: security headers on every response, including errors.
func TestSecurityHeadersOnAllResponses(t *testing.T) {
	h := testHandler(t, &bytes.Buffer{}, 1024)
	for _, path := range []string{"/ok", "/missing", "/panic"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		for k, v := range securityHeaders {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s: header %s = %q, want %q", path, k, got, v)
			}
		}
		if rec.Header().Get("X-Request-ID") == "" {
			t.Errorf("%s: missing X-Request-ID", path)
		}
	}
}

// AT-F00-04: unknown routes return JSON 404.
func TestUnknownRouteIs404JSON(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(t, &bytes.Buffer{}, 1024).ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	if e := decodeError(t, rec.Body); e.Code != "not_found" || e.RequestID == "" {
		t.Fatalf("error = %+v", e)
	}
}

// AT-F00-04: wrong methods return JSON 405 with Allow.
func TestWrongMethodIs405JSON(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(t, &bytes.Buffer{}, 1024).ServeHTTP(rec, httptest.NewRequest("DELETE", "/ok", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Allow"), "GET") {
		t.Fatalf("Allow = %q", rec.Header().Get("Allow"))
	}
	if e := decodeError(t, rec.Body); e.Code != "method_not_allowed" {
		t.Fatalf("error = %+v", e)
	}
}

// AT-F00-04: panics become a generic 500; details only in the log.
func TestPanicIs500WithoutDetails(t *testing.T) {
	var logs bytes.Buffer
	rec := httptest.NewRecorder()
	testHandler(t, &logs, 1024).ServeHTTP(rec, httptest.NewRequest("GET", "/panic", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	body := rec.Body.String()
	if strings.Contains(body, "hunter2") || strings.Contains(body, "goroutine") {
		t.Fatalf("response leaks internals: %s", body)
	}
	if e := decodeError(t, strings.NewReader(body)); e.Code != "internal_error" {
		t.Fatalf("error = %+v", e)
	}
	if !strings.Contains(logs.String(), "hunter2") || !strings.Contains(logs.String(), "handler panic") {
		t.Fatalf("panic details not logged: %s", logs.String())
	}
}

// AT-F00-04: declared oversized bodies are rejected before the handler runs.
func TestDeclaredOversizedBodyIs413(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/echo", strings.NewReader(`{"name":"`+strings.Repeat("a", 2000)+`"}`))
	testHandler(t, &bytes.Buffer{}, 1024).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
	if e := decodeError(t, rec.Body); e.Code != "body_too_large" {
		t.Fatalf("error = %+v", e)
	}
}

// AT-F00-04: undeclared (chunked) oversized bodies are cut off while reading.
func TestStreamedOversizedBodyIs413(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/echo", strings.NewReader(`{"name":"`+strings.Repeat("a", 2000)+`"}`))
	req.ContentLength = -1
	testHandler(t, &bytes.Buffer{}, 1024).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestDecodeJSONRejectsInvalidInput(t *testing.T) {
	cases := map[string]string{
		"malformed":     `{"name":`,
		"unknown field": `{"name":"a","admin":true}`,
		"trailing data": `{"name":"a"}{"name":"b"}`,
		"wrong type":    `{"name":1}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			testHandler(t, &bytes.Buffer{}, 1024).ServeHTTP(rec, httptest.NewRequest("POST", "/echo", strings.NewReader(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d", rec.Code)
			}
			if e := decodeError(t, rec.Body); e.Code != "invalid_json" {
				t.Fatalf("error = %+v", e)
			}
		})
	}
}

func TestDecodeJSONAcceptsValidInput(t *testing.T) {
	rec := httptest.NewRecorder()
	testHandler(t, &bytes.Buffer{}, 1024).ServeHTTP(rec, httptest.NewRequest("POST", "/echo", strings.NewReader(`{"name":"kern"}`)))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"kern"`) {
		t.Fatalf("status = %d body = %s", rec.Code, rec.Body)
	}
}

func TestRequestIDIsGeneratedNotTrusted(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ok", nil)
	req.Header.Set("X-Request-ID", "injected\nvalue")
	testHandler(t, &bytes.Buffer{}, 1024).ServeHTTP(rec, req)
	id := rec.Header().Get("X-Request-ID")
	if id == "injected\nvalue" || len(id) != 32 {
		t.Fatalf("request id = %q", id)
	}
}

func TestAccessLogRecordsRequest(t *testing.T) {
	var logs bytes.Buffer
	rec := httptest.NewRecorder()
	testHandler(t, &logs, 1024).ServeHTTP(rec, httptest.NewRequest("GET", "/missing", nil))
	var entry map[string]any
	if err := json.Unmarshal(logs.Bytes(), &entry); err != nil {
		t.Fatalf("log is not JSON: %s", logs.String())
	}
	if entry["msg"] != "http request" || entry["status"] != float64(404) || entry["path"] != "/missing" {
		t.Fatalf("unexpected log entry %v", entry)
	}
}

func TestHandleRequiresMethod(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for pattern without method")
		}
	}()
	NewRouter(nil).HandleFunc("/no-method", Public(), func(http.ResponseWriter, *http.Request) {})
}

func TestServerTimeouts(t *testing.T) {
	srv := NewServer(http.NotFoundHandler(), testLogger(&bytes.Buffer{}))
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatalf("timeouts not set: %+v", srv)
	}
	if srv.MaxHeaderBytes != 16<<10 {
		t.Fatalf("MaxHeaderBytes = %d", srv.MaxHeaderBytes)
	}
}

// AT-F00-05: cancellation drains in-flight requests before Run returns.
func TestRunGracefulShutdownCompletesInFlightRequest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	rt := NewRouter(nil)
	rt.HandleFunc("GET /slow", Public(), func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
		WriteJSON(w, http.StatusOK, map[string]string{"status": "done"})
	})

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, ln, rt, Options{ShutdownTimeout: 5 * time.Second, Logger: testLogger(&bytes.Buffer{})})
	}()

	var wg sync.WaitGroup
	wg.Add(1)
	var status int
	var reqErr error
	go func() {
		defer wg.Done()
		resp, err := http.Get("http://" + ln.Addr().String() + "/slow")
		if err != nil {
			reqErr = err
			return
		}
		status = resp.StatusCode
		resp.Body.Close()
	}()

	<-started
	cancel()
	select {
	case err := <-runErr:
		t.Fatalf("Run returned before in-flight request finished: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	if reqErr != nil || status != http.StatusOK {
		t.Fatalf("in-flight request: status=%d err=%v", status, reqErr)
	}
	if err := <-runErr; err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := net.DialTimeout("tcp", ln.Addr().String(), time.Second); err == nil {
		t.Fatal("listener still accepting after shutdown")
	}
}

// AT-F00-05: a request exceeding the shutdown timeout makes Run report it.
func TestRunShutdownTimeoutReported(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	rt := NewRouter(nil)
	rt.HandleFunc("GET /stuck", Public(), func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-release
	})
	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() {
		runErr <- Run(ctx, ln, rt, Options{ShutdownTimeout: 100 * time.Millisecond, Logger: testLogger(&bytes.Buffer{})})
	}()
	go func() {
		if resp, err := http.Get("http://" + ln.Addr().String() + "/stuck"); err == nil {
			resp.Body.Close()
		}
	}()
	<-started
	cancel()
	select {
	case err := <-runErr:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Run error = %v, want deadline exceeded", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after shutdown timeout")
	}
}
