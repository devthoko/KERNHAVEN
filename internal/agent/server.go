// Package agent implements kernhaven-agent: the only component with access to
// the Docker Engine. It accepts typed, allow-listed operations over a unix
// socket from allow-listed peers carrying grants signed by the Core (M4).
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// Server serves the agent protocol.
type Server struct {
	log     *slog.Logger
	pub     ed25519.PublicKey
	allowed map[uint32]bool
	ops     map[string]handler
	streams map[string]streamHandler
	nonces  *nonceCache
	now     func() time.Time
}

// NewServer returns a server using docker for operations.
func NewServer(log *slog.Logger, pub ed25519.PublicKey, allowedUIDs []uint32, d Docker, o Options) *Server {
	allowed := map[uint32]bool{}
	for _, u := range allowedUIDs {
		allowed[u] = true
	}
	return &Server{log: log, pub: pub, allowed: allowed, ops: operations(d, time.Now(), o), streams: streamOperations(o), nonces: newNonceCache(100000), now: time.Now}
}

// Listen creates the unix socket with mode 0660. An existing socket file is
// replaced; any other file type at path is an error.
func Listen(path string) (net.Listener, error) {
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	old := syscall.Umask(0o117)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		ln.Close()
		return nil, err
	}
	return ln, nil
}

// peerListener closes connections from peers whose UID is not allowed before
// any byte is read (AT-M4-02, TH-22).
type peerListener struct {
	net.Listener
	allowed map[uint32]bool
	log     *slog.Logger
}

func peerUID(c net.Conn) (uint32, int32, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, 0, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return cred.Uid, cred.Pid, nil
}

func (l *peerListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		uid, pid, err := peerUID(c)
		if err != nil || !l.allowed[uid] {
			l.log.Warn("rejected connection from unauthorized peer", "uid", uid, "pid", pid, "error", errString(err))
			c.Close()
			continue
		}
		return c, nil
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/op/{op}", s.handleOp)
	mux.HandleFunc("POST /v1/stream/{op}", s.handleStream)
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      6 * time.Minute, // stop/restart may wait up to 300 s
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(&peerListener{Listener: ln, allowed: s.allowed, log: s.log}) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close()
	}
	if err := <-errc; err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	var body agentproto.ErrorBody
	body.Error.Code, body.Error.Message = code, msg
	writeJSON(w, status, body)
}

func (s *Server) handleOp(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	op := r.PathValue("op")
	// Only an operation this server offers may use a larger limit.
	limit := int64(agentproto.MaxRequestBytes)
	if _, ok := s.ops[op]; ok {
		limit = agentproto.RequestLimit(op)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		writeErr(w, http.StatusRequestEntityTooLarge, agentproto.CodeInvalidRequest, "request too large")
		return
	}
	var req agentproto.Request
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || dec.More() {
		writeErr(w, http.StatusBadRequest, agentproto.CodeInvalidRequest, "malformed request envelope")
		return
	}

	params := []byte(req.Params)
	if len(params) == 0 {
		params = []byte("null")
	}
	g, ok := s.authorize(w, op, req.Grant, params)
	if !ok {
		return
	}
	h, ok := s.ops[op]
	if !ok {
		writeErr(w, http.StatusNotFound, agentproto.CodeUnknownOp, "unknown operation")
		return
	}
	if longOps[op] {
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Hour))
	}

	result, err := h(context.WithValue(r.Context(), actorKey{}, g.Actor), json.RawMessage(params))
	attrs := []any{"op", op, "actor", g.Actor, "request_id", g.RequestID, "duration", time.Since(start).String()}
	if err != nil {
		code, status := errorCode(err)
		s.log.Info("operation failed", append(attrs, "code", code, "error", err.Error())...)
		msg := err.Error()
		if code == agentproto.CodeInternal {
			msg = "internal error"
		}
		if errors.As(err, new(*policy.PolicyError)) {
			s.log.Warn("policy rejected container", append(attrs, "error", err.Error())...)
		}
		writeErr(w, status, code, msg)
		return
	}
	s.log.Info("operation succeeded", attrs...)
	writeJSON(w, http.StatusOK, map[string]any{"result": result})
}

// authorize verifies the grant for op and params and consumes its nonce.
// Nothing about operations is revealed without a valid grant.
func (s *Server) authorize(w http.ResponseWriter, op, grant string, params []byte) (agentproto.Grant, bool) {
	g, err := agentproto.Verify(s.pub, grant, s.now())
	if err != nil {
		s.log.Warn("rejected request: invalid grant", "op", op, "error", err.Error())
		writeErr(w, http.StatusUnauthorized, agentproto.CodeInvalidGrant, err.Error())
		return g, false
	}
	if g.Op != op || g.ParamsSHA256 != agentproto.ParamsHash(params) {
		s.log.Warn("rejected request: grant does not match request", "op", op, "grant_op", g.Op, "actor", g.Actor)
		writeErr(w, http.StatusUnauthorized, agentproto.CodeInvalidGrant, "grant does not cover this operation and parameters")
		return g, false
	}
	if !s.nonces.use(g.Nonce, time.UnixMilli(g.ExpiresAtMS).Add(agentproto.ClockSkew), s.now()) {
		s.log.Warn("rejected request: replayed grant", "op", op, "actor", g.Actor, "request_id", g.RequestID)
		writeErr(w, http.StatusUnauthorized, agentproto.CodeInvalidGrant, "grant already used")
		return g, false
	}
	return g, true
}

// handleStream serves stream operations (M10, ADR-0023): grant and
// parameters travel in headers, data in the request or response body.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	op := r.PathValue("op")
	params, err := base64.StdEncoding.DecodeString(r.Header.Get(agentproto.HeaderParams))
	if err != nil || len(params) == 0 {
		writeErr(w, http.StatusBadRequest, agentproto.CodeInvalidRequest, "malformed stream request")
		return
	}
	g, ok := s.authorize(w, op, r.Header.Get(agentproto.HeaderGrant), params)
	if !ok {
		return
	}
	h, ok := s.streams[op]
	if !ok {
		writeErr(w, http.StatusNotFound, agentproto.CodeUnknownOp, "unknown operation")
		return
	}
	// Transfers may take long; extend the deadlines for this request only.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(15 * time.Minute))
	_ = rc.SetWriteDeadline(time.Now().Add(6 * time.Hour))
	err = h(context.WithValue(r.Context(), actorKey{}, g.Actor), json.RawMessage(params), r.Body, w)
	attrs := []any{"op", op, "actor", g.Actor, "request_id", g.RequestID, "duration", time.Since(start).String()}
	if err != nil {
		code, status := errorCode(err)
		s.log.Info("operation failed", append(attrs, "code", code, "error", err.Error())...)
		msg := err.Error()
		if code == agentproto.CodeInternal {
			msg = "internal error"
		}
		writeErr(w, status, code, msg)
		return
	}
	s.log.Info("operation succeeded", attrs...)
}
