package audit

import (
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// Register adds the audit API routes.
func Register(rt *httpserver.Router, l *Log) {
	read := httpserver.RequirePermission(string(authz.AuditRead))

	rt.HandleFunc("GET /api/v1/audit", read, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		var f Filter
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
		f.Action = q.Get("action")
		f.Actor = q.Get("actor")
		recs, err := l.List(r.Context(), f)
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"events": recs})
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
