// Package files is the Core side of the file manager (M10): authorization
// per role and root, upload sessions, safe download and preview headers,
// audit and jobs. Every file access happens in the storage service.
package files

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// Job kinds.
const (
	KindCopy  = "files.copy"
	KindPurge = "files.purge"
)

// Limits.
const (
	ChunkSize     = 8 << 20
	PreviewBytes  = 256 << 10
	MaxImageBytes = 50 << 20
	UploadTTL     = 24 * time.Hour
)

// Service implements the file manager API.
type Service struct {
	client    *agentclient.Client
	db        *sql.DB
	audit     *audit.Log
	jobs      *jobs.Service
	wake      func()
	maxUpload int64
	access    map[string]config.FileRootAccess
	now       func() time.Time
}

// New returns the service and registers its jobs.
func New(client *agentclient.Client, db *sql.DB, auditLog *audit.Log, js *jobs.Service, wake func(), cfg config.Files, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	s := &Service{client: client, db: db, audit: auditLog, jobs: js, wake: wake, maxUpload: cfg.MaxUploadBytes, access: cfg.Roots, now: now}
	// Copies and purges are not retried: a retried copy would find its own
	// partial result.
	js.Register(jobs.Kind{Name: KindCopy, MaxAttempts: 1, Plan: s.planCall(agentproto.OpFilesCopy, func(raw json.RawMessage) (any, error) {
		var p agentproto.FilesCopy
		return p, json.Unmarshal(raw, &p)
	})})
	js.Register(jobs.Kind{Name: KindPurge, MaxAttempts: 1, Plan: s.planCall(agentproto.OpFilesTrashPurge, func(raw json.RawMessage) (any, error) {
		var p agentproto.FilesTrashID
		return p, json.Unmarshal(raw, &p)
	})})
	return s
}

type jobPayload struct {
	Params json.RawMessage `json:"params"`
	Actor  string          `json:"actor"`
}

func (s *Service) planCall(op string, parse func(json.RawMessage) (any, error)) func(json.RawMessage) ([]jobs.Step, error) {
	return func(raw json.RawMessage) ([]jobs.Step, error) {
		var p jobPayload
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		params, err := parse(p.Params)
		if err != nil {
			return nil, err
		}
		return []jobs.Step{{Name: op, Run: func(ctx context.Context, sc *jobs.StepContext) error {
			if s.client == nil {
				return jobs.Permanent(agentclient.ErrUnavailable)
			}
			cctx, cancel := context.WithTimeout(ctx, 6*time.Hour)
			defer cancel()
			var out json.RawMessage
			err := s.client.Do(cctx, agentclient.Call{Op: op, Params: params, Actor: p.Actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}, &out)
			_ = s.audit.Record(context.WithoutCancel(ctx), audit.Event{Actor: p.Actor, Action: op + ".result", Target: "files", Result: result(err),
				Details: details(err, "job", fmt.Sprint(sc.JobID), "result", string(out))})
			if err != nil {
				return jobs.Permanent(err)
			}
			sc.Logf("%s finished: %s", op, out)
			return nil
		}}}, nil
	}
}

func result(err error) audit.Result {
	if err != nil {
		return audit.Failure
	}
	return audit.Success
}

func details(err error, kv ...string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			m[kv[i]] = kv[i+1]
		}
	}
	if err != nil {
		m["error"] = err.Error()
	}
	return m
}

var errNoAccess = errors.New("you have no access to this file root")

// allowed applies the role permission and the optional per-root lists
// (AT-F07-04). Lists only narrow access.
func (s *Service) allowed(p *identity.Principal, root string, write bool) bool {
	perm := authz.FilesRead
	if write {
		perm = authz.FilesWrite
	}
	if p == nil || !p.Has(perm) {
		return false
	}
	a, ok := s.access[root]
	if !ok {
		return true
	}
	list := a.Read
	if write {
		list = a.Write
	}
	return slices.Contains(list, string(p.User.Role))
}

type request struct {
	w   http.ResponseWriter
	r   *http.Request
	p   *identity.Principal
	m   identity.Meta
	svc *Service
}

func (s *Service) req(w http.ResponseWriter, r *http.Request) *request {
	p, _ := identity.FromContext(r.Context())
	return &request{w: w, r: r, p: p, m: identity.MetaFrom(r), svc: s}
}

func (q *request) actor() string {
	if q.p == nil {
		return "system"
	}
	return q.p.User.Username
}

func (q *request) call(op string, params, out any) error {
	if q.svc.client == nil {
		return agentclient.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(q.r.Context(), 2*time.Minute)
	defer cancel()
	return q.svc.client.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: q.actor(), RequestID: q.m.RequestID}, out)
}

func (q *request) record(action, root, target string, err error, kv ...string) {
	ev := audit.Event{Action: action, Target: "file:" + root + ":/" + target, Result: result(err), RequestID: q.m.RequestID, IP: q.m.IP, Details: details(err, kv...)}
	if q.p != nil {
		ev.ActorID, ev.Actor = q.p.User.ID, q.p.User.Username
	}
	_ = q.svc.audit.Record(context.WithoutCancel(q.r.Context()), ev)
}

func (q *request) fail(err error) {
	w, r := q.w, q.r
	var ae *agentclient.Error
	switch {
	case errors.Is(err, errNoAccess):
		httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, agentclient.ErrUnavailable):
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "storage_unavailable", "the storage service is not running or not reachable")
	case errors.Is(err, jobs.ErrDuplicate):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", "this operation is already running")
	case errors.As(err, &ae):
		switch ae.Code {
		case agentproto.CodeNotFound:
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", ae.Message)
		case agentproto.CodeConflict:
			httpserver.WriteError(w, r, http.StatusConflict, "conflict", ae.Message)
		case agentproto.CodeInvalidParams:
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ae.Message)
		default:
			httpserver.InternalError(w, r, err)
		}
	default:
		var ve *validationError
		if errors.As(err, &ve) {
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.msg)
			return
		}
		httpserver.InternalError(w, r, err)
	}
}

type validationError struct{ msg string }

func (e *validationError) Error() string { return e.msg }

// check enforces access to root; it records denials.
func (q *request) check(root string, write bool, target string) bool {
	if q.svc.allowed(q.p, root, write) {
		return true
	}
	q.record("files.denied", root, target, errNoAccess)
	q.fail(errNoAccess)
	return false
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// RootView is a root as the user sees it.
type RootView struct {
	Name       string `json:"name"`
	Available  bool   `json:"available"`
	FreeBytes  int64  `json:"free_bytes"`
	TotalBytes int64  `json:"total_bytes"`
	Writable   bool   `json:"writable"`
}

// sniffImage recognises the raster formats that may be shown inline. SVG and
// everything else are not images here (they can carry scripts).
func sniffImage(b []byte) string {
	switch {
	case bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n")):
		return "image/png"
	case bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF}):
		return "image/jpeg"
	case bytes.HasPrefix(b, []byte("GIF87a")), bytes.HasPrefix(b, []byte("GIF89a")):
		return "image/gif"
	case len(b) >= 12 && bytes.Equal(b[:4], []byte("RIFF")) && bytes.Equal(b[8:12], []byte("WEBP")):
		return "image/webp"
	}
	return ""
}

// untrustedHeaders are set on every response carrying file content
// (AT-F07-05, TH-04): never rendered as a page by the browser.
func untrustedHeaders(w http.ResponseWriter, name, contentType string, size int64) {
	h := w.Header()
	h.Set("Content-Type", contentType)
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
	if size >= 0 {
		h.Set("Content-Length", strconv.FormatInt(size, 10))
	}
}

func (q *request) open(root, p string, offset, limit int64) (agentproto.FileMeta, io.ReadCloser, error) {
	if q.svc.client == nil {
		return agentproto.FileMeta{}, nil, agentclient.ErrUnavailable
	}
	st, err := q.svc.client.DoStream(q.r.Context(), agentclient.Call{Op: agentproto.OpFilesRead,
		Params: agentproto.FilesRead{Root: root, Path: p, Offset: offset, Limit: limit}, Actor: q.actor(), RequestID: q.m.RequestID}, nil)
	if err != nil {
		return agentproto.FileMeta{}, nil, err
	}
	var meta agentproto.FileMeta
	if err := json.Unmarshal(st.Meta, &meta); err != nil {
		st.Body.Close()
		return meta, nil, fmt.Errorf("storage service: missing file metadata")
	}
	return meta, st.Body, nil
}

// Preview is a text or image preview.
type Preview struct {
	Name      string `json:"name"`
	Size      int64  `json:"size"`
	Kind      string `json:"kind"` // text, image, binary
	Text      string `json:"text,omitempty"`
	Truncated bool   `json:"truncated"`
}

func makePreview(meta agentproto.FileMeta, head []byte) Preview {
	pv := Preview{Name: meta.Name, Size: meta.Size, Kind: "binary"}
	switch {
	case sniffImage(head) != "":
		pv.Kind = "image"
	case !bytes.ContainsRune(head, 0):
		text := head
		pv.Truncated = meta.Size > int64(len(head))
		if pv.Truncated {
			// Do not cut a multi-byte character in half.
			for i := 0; i < utf8.UTFMax && len(text) > 0 && !utf8.Valid(text); i++ {
				text = text[:len(text)-1]
			}
		}
		if utf8.Valid(text) {
			pv.Kind, pv.Text = "text", string(text)
		}
	}
	return pv
}

func readAllLimited(rc io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(rc, n))
}

func bufPeek(r io.Reader, n int) (*bufio.Reader, []byte) {
	br := bufio.NewReaderSize(r, 64<<10)
	head, _ := br.Peek(n)
	return br, head
}
