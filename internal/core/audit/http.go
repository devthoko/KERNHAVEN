package audit

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// filterFrom reads the search parameters shared by the list and the export.
func filterFrom(r *http.Request) (Filter, error) {
	q := r.URL.Query()
	f := Filter{Action: q.Get("action"), Actor: q.Get("actor"), Query: q.Get("q")}
	if len(f.Query) > 200 {
		return f, fmt.Errorf("q is longer than 200 characters")
	}
	switch v := Result(q.Get("result")); v {
	case "", Success, Failure, Denied:
		f.Result = v
	default:
		return f, fmt.Errorf("result must be success, failure or denied")
	}
	for name, dst := range map[string]*int64{"since": &f.SinceMS, "until": &f.UntilMS} {
		if v := q.Get(name); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return f, fmt.Errorf("%s must be an RFC 3339 time", name)
			}
			*dst = t.UnixMilli()
		}
	}
	return f, nil
}

// Register adds the audit API routes. actor names the signed-in user for
// recording exports.
func Register(rt *httpserver.Router, l *Log, actor func(*http.Request) (int64, string)) {
	read := httpserver.RequirePermission(string(authz.AuditRead))

	rt.HandleFunc("GET /api/v1/audit", read, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		f, err := filterFrom(r)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", err.Error())
			return
		}
		if v := q.Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 500 {
				httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", "limit must be 1..500")
				return
			}
			f.Limit = n
		}
		if v := q.Get("before"); v != "" {
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil || n < 1 {
				httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", "before must be a positive sequence number")
				return
			}
			f.BeforeSeq = n
		}
		recs, err := l.List(r.Context(), f)
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"events": recs})
	})

	// AT-F10-03: JSON Lines with the chain hashes; the export is recorded.
	rt.HandleFunc("GET /api/v1/audit/export", read, func(w http.ResponseWriter, r *http.Request) {
		f, err := filterFrom(r)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", err.Error())
			return
		}
		id, name := actor(r)
		if err := l.Record(r.Context(), Event{ActorID: id, Actor: name, Action: "audit.export", Target: "audit", Result: Success, RequestID: httpserver.RequestID(r.Context()), IP: httpserver.ClientIP(r),
			Details: map[string]string{"q": f.Query, "action": f.Action, "actor": f.Actor, "result": string(f.Result), "since": r.URL.Query().Get("since"), "until": r.URL.Query().Get("until")}}); err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="kernhaven-audit-`+time.Now().UTC().Format("20060102T150405Z")+`.jsonl"`)
		w.WriteHeader(http.StatusOK)
		if _, err := l.Export(r.Context(), f, w); err != nil {
			panic(http.ErrAbortHandler) // break the download rather than end it short
		}
	})

	rt.HandleFunc("GET /api/v1/audit/verify", read, func(w http.ResponseWriter, r *http.Request) {
		res, err := l.Verify(r.Context())
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, res)
	})
}
