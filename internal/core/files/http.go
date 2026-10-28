package files

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// Register adds the file manager routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.FilesRead))
	write := httpserver.RequirePermission(string(authz.FilesWrite))
	// Upload chunks are the only bodies larger than max_body_bytes (M10).
	rt.AllowBody(http.MethodPut, "/api/v1/files/uploads/", ChunkSize)

	rt.HandleFunc("GET /api/v1/files/roots", read, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		var roots []agentproto.FileRoot
		if err := q.call(agentproto.OpFilesRoots, nil, &roots); err != nil {
			q.fail(err)
			return
		}
		out := []RootView{}
		for _, rt := range roots {
			if s.allowed(q.p, rt.Name, false) {
				out = append(out, RootView{Name: rt.Name, Available: rt.Available, FreeBytes: rt.FreeBytes, TotalBytes: rt.TotalBytes, Writable: s.allowed(q.p, rt.Name, true)})
			}
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"roots": out})
	})

	rt.HandleFunc("GET /api/v1/files/list", read, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		root, p := r.URL.Query().Get("root"), r.URL.Query().Get("path")
		if !q.check(root, false, p) {
			return
		}
		var l agentproto.FilesListing
		if err := q.call(agentproto.OpFilesList, agentproto.FilesPath{Root: root, Path: p}, &l); err != nil {
			q.fail(err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, l)
	})

	rt.HandleFunc("GET /api/v1/files/download", read, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		root, p := r.URL.Query().Get("root"), r.URL.Query().Get("path")
		if !q.check(root, false, p) {
			return
		}
		meta, body, err := q.open(root, p, 0, 0)
		q.record("files.download", root, p, err)
		if err != nil {
			q.fail(err)
			return
		}
		defer body.Close()
		_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(6 * time.Hour))
		untrustedHeaders(w, meta.Name, "application/octet-stream", meta.Size)
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, body)
	})

	rt.HandleFunc("GET /api/v1/files/preview", read, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		root, p := r.URL.Query().Get("root"), r.URL.Query().Get("path")
		if !q.check(root, false, p) {
			return
		}
		meta, body, err := q.open(root, p, 0, PreviewBytes)
		if err != nil {
			q.fail(err)
			return
		}
		head, err := readAllLimited(body, PreviewBytes)
		body.Close()
		if err != nil {
			q.fail(err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, makePreview(meta, head))
	})

	rt.HandleFunc("GET /api/v1/files/image", read, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		root, p := r.URL.Query().Get("root"), r.URL.Query().Get("path")
		if !q.check(root, false, p) {
			return
		}
		meta, body, err := q.open(root, p, 0, MaxImageBytes+1)
		if err != nil {
			q.fail(err)
			return
		}
		defer body.Close()
		if meta.Size > MaxImageBytes {
			q.fail(&validationError{fmt.Sprintf("images larger than %d MB are not previewed", MaxImageBytes>>20)})
			return
		}
		br, head := bufPeek(body, 16)
		typ := sniffImage(head)
		if typ == "" {
			httpserver.WriteError(w, r, http.StatusUnsupportedMediaType, "not_an_image", "this file is not a PNG, JPEG, GIF or WebP image")
			return
		}
		untrustedHeaders(w, meta.Name, typ, meta.Size)
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, br)
	})

	type pathBody struct {
		Root string `json:"root"`
		Path string `json:"path"`
	}
	simple := func(action, op string, params func(pathBody) any) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			q := s.req(w, r)
			var in pathBody
			if httpserver.DecodeJSON(w, r, &in) != nil || !q.check(in.Root, true, in.Path) {
				return
			}
			var out json.RawMessage
			err := q.call(op, params(in), &out)
			q.record(action, in.Root, in.Path, err)
			if err != nil {
				q.fail(err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out)
		}
	}
	rt.HandleFunc("POST /api/v1/files/mkdir", write, simple("files.mkdir", agentproto.OpFilesMkdir, func(b pathBody) any {
		return agentproto.FilesPath{Root: b.Root, Path: b.Path}
	}))
	rt.HandleFunc("POST /api/v1/files/trash", write, simple("files.trash", agentproto.OpFilesTrash, func(b pathBody) any {
		return agentproto.FilesPath{Root: b.Root, Path: b.Path}
	}))

	rt.HandleFunc("POST /api/v1/files/rename", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		var in agentproto.FilesRename
		if httpserver.DecodeJSON(w, r, &in) != nil || !q.check(in.Root, true, in.From) {
			return
		}
		err := q.call(agentproto.OpFilesRename, in, nil)
		q.record("files.rename", in.Root, in.From, err, "to", in.To)
		if err != nil {
			q.fail(err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	rt.HandleFunc("GET /api/v1/files/trash", read, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		root := r.URL.Query().Get("root")
		if !q.check(root, false, "") {
			return
		}
		var items []agentproto.TrashItem
		if err := q.call(agentproto.OpFilesTrashList, agentproto.FilesPath{Root: root}, &items); err != nil {
			q.fail(err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})

	rt.HandleFunc("POST /api/v1/files/trash/restore", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		var in agentproto.FilesTrashID
		if httpserver.DecodeJSON(w, r, &in) != nil || !q.check(in.Root, true, "") {
			return
		}
		var res agentproto.ActionResult
		err := q.call(agentproto.OpFilesTrashRestore, in, &res)
		q.record("files.restore", in.Root, res.ID, err, "item", in.ID)
		if err != nil {
			q.fail(err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"path": res.ID})
	})

	enqueue := func(q *request, kind, root, target string, params any, dedupe string) {
		raw, _ := json.Marshal(params)
		id, err := s.jobs.Enqueue(q.r.Context(), jobs.Request{Kind: kind, Payload: jobPayload{Params: raw, Actor: q.actor()}, CreatedBy: q.p.User.ID, DedupeKey: dedupe})
		q.record(kind, root, target, err, "job", fmt.Sprint(id), "params", string(raw))
		if err != nil {
			q.fail(err)
			return
		}
		if s.wake != nil {
			s.wake()
		}
		httpserver.WriteJSON(q.w, http.StatusAccepted, map[string]any{"job_id": id})
	}

	rt.HandleFunc("POST /api/v1/files/copy", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		var in agentproto.FilesCopy
		if httpserver.DecodeJSON(w, r, &in) != nil || !q.check(in.Root, false, in.From) {
			return
		}
		if in.ToRoot == "" {
			in.ToRoot = in.Root
		}
		if !q.check(in.ToRoot, true, in.To) {
			return
		}
		enqueue(q, KindCopy, in.Root, in.From, in, "files:copy:"+in.ToRoot+":"+in.To)
	})

	rt.HandleFunc("POST /api/v1/files/trash/purge", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		var in agentproto.FilesTrashID
		if httpserver.DecodeJSON(w, r, &in) != nil || !q.check(in.Root, true, "") {
			return
		}
		// Emptying the trash deletes for good (AT-F09-04).
		if err := identity.CheckStepUp(r.Context()); err != nil {
			httpserver.WriteError(w, r, http.StatusForbidden, "step_up_required", err.Error())
			return
		}
		enqueue(q, KindPurge, in.Root, "", in, "files:purge:"+in.Root+":"+in.ID)
	})

	s.registerUploads(rt, write)
}

// upload is a resumable upload session.
type upload struct {
	ID       string `json:"id"`
	Root     string `json:"root"`
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Received int64  `json:"received"`
	Chunk    int    `json:"chunk_size"`
	userID   int64
}

func (s *Service) loadUpload(ctx context.Context, id string, userID int64) (upload, error) {
	u := upload{Chunk: ChunkSize}
	err := s.db.QueryRowContext(ctx, `SELECT id, root, path, size, received, user_id FROM file_uploads WHERE id = ? AND user_id = ? AND expires_ms > ?`,
		id, userID, s.now().UnixMilli()).Scan(&u.ID, &u.Root, &u.Path, &u.Size, &u.Received, &u.userID)
	if errors.Is(err, sql.ErrNoRows) {
		return u, &agentclient.Error{Status: 404, Code: agentproto.CodeNotFound, Message: "no such upload (it may have expired)"}
	}
	return u, err
}

// expire aborts upload sessions that are older than UploadTTL.
func (s *Service) expire(q *request) {
	rows, err := s.db.QueryContext(q.r.Context(), `SELECT id, root, path FROM file_uploads WHERE expires_ms <= ?`, s.now().UnixMilli())
	if err != nil {
		return
	}
	var stale []upload
	for rows.Next() {
		var u upload
		if rows.Scan(&u.ID, &u.Root, &u.Path) == nil {
			stale = append(stale, u)
		}
	}
	rows.Close()
	for _, u := range stale {
		_ = q.call(agentproto.OpFilesUploadAbort, agentproto.UploadFinish{Root: u.Root, ID: u.ID, Path: u.Path}, nil)
		_, _ = s.db.ExecContext(q.r.Context(), `DELETE FROM file_uploads WHERE id = ?`, u.ID)
	}
}

func (s *Service) registerUploads(rt *httpserver.Router, write httpserver.Access) {
	rt.HandleFunc("POST /api/v1/files/uploads", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		var in struct {
			Root string `json:"root"`
			Path string `json:"path"`
			Size int64  `json:"size"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil || !q.check(in.Root, true, in.Path) {
			return
		}
		if in.Size < 0 || in.Size > s.maxUpload {
			q.fail(&validationError{fmt.Sprintf("uploads may be at most %d bytes", s.maxUpload)})
			return
		}
		s.expire(q)
		u := upload{ID: newID(), Root: in.Root, Path: in.Path, Size: in.Size, Chunk: ChunkSize}
		// Validates root, path and target folder and creates the staging area.
		if s.client == nil {
			q.fail(agentclient.ErrUnavailable)
			return
		}
		var st agentproto.UploadState
		err := s.client.DoStreamJSON(r.Context(), agentclient.Call{Op: agentproto.OpFilesUploadAppend,
			Params: agentproto.UploadAppend{Root: u.Root, ID: u.ID, Path: u.Path, Offset: -1}, Actor: q.actor(), RequestID: q.m.RequestID}, nil, &st)
		if err != nil {
			q.fail(err)
			return
		}
		now := s.now()
		if _, err := s.db.ExecContext(r.Context(), `INSERT INTO file_uploads (id, user_id, root, path, size, received, created_ms, expires_ms) VALUES (?, ?, ?, ?, ?, 0, ?, ?)`,
			u.ID, q.p.User.ID, u.Root, u.Path, u.Size, now.UnixMilli(), now.Add(UploadTTL).UnixMilli()); err != nil {
			q.fail(err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, u)
	})

	stage := func(q *request, u upload, offset int64, body io.Reader) (agentproto.UploadState, error) {
		var st agentproto.UploadState
		if s.client == nil {
			return st, agentclient.ErrUnavailable
		}
		err := s.client.DoStreamJSON(q.r.Context(), agentclient.Call{Op: agentproto.OpFilesUploadAppend,
			Params: agentproto.UploadAppend{Root: u.Root, ID: u.ID, Path: u.Path, Offset: offset}, Actor: q.actor(), RequestID: q.m.RequestID}, body, &st)
		if err == nil {
			_, _ = s.db.ExecContext(q.r.Context(), `UPDATE file_uploads SET received = ? WHERE id = ?`, st.Size, u.ID)
		}
		return st, err
	}

	rt.HandleFunc("GET /api/v1/files/uploads/{id}", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		u, err := s.loadUpload(r.Context(), r.PathValue("id"), q.p.User.ID)
		if err != nil {
			q.fail(err)
			return
		}
		st, err := stage(q, u, -1, nil)
		if err != nil {
			q.fail(err)
			return
		}
		u.Received = st.Size
		httpserver.WriteJSON(w, http.StatusOK, u)
	})

	rt.HandleFunc("PUT /api/v1/files/uploads/{id}", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		u, err := s.loadUpload(r.Context(), r.PathValue("id"), q.p.User.ID)
		if err != nil {
			q.fail(err)
			return
		}
		offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if err != nil || offset < 0 || offset > u.Size {
			q.fail(&validationError{"offset must be between 0 and the upload size"})
			return
		}
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Minute))
		st, err := stage(q, u, offset, r.Body)
		if err != nil {
			q.fail(err)
			return
		}
		if st.Size > u.Size {
			_ = q.call(agentproto.OpFilesUploadAbort, agentproto.UploadFinish{Root: u.Root, ID: u.ID, Path: u.Path}, nil)
			_, _ = s.db.ExecContext(r.Context(), `DELETE FROM file_uploads WHERE id = ?`, u.ID)
			q.fail(&validationError{"more data than announced; the upload was cancelled"})
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]int64{"received": st.Size})
	})

	rt.HandleFunc("POST /api/v1/files/uploads/{id}/finish", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		u, err := s.loadUpload(r.Context(), r.PathValue("id"), q.p.User.ID)
		if err != nil {
			q.fail(err)
			return
		}
		err = q.call(agentproto.OpFilesUploadFinish, agentproto.UploadFinish{Root: u.Root, ID: u.ID, Path: u.Path, Size: u.Size}, nil)
		q.record("files.upload", u.Root, u.Path, err, "size", fmt.Sprint(u.Size))
		if err != nil {
			q.fail(err)
			return
		}
		_, _ = s.db.ExecContext(r.Context(), `DELETE FROM file_uploads WHERE id = ?`, u.ID)
		httpserver.WriteJSON(w, http.StatusOK, map[string]string{"path": u.Path})
	})

	rt.HandleFunc("DELETE /api/v1/files/uploads/{id}", write, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		u, err := s.loadUpload(r.Context(), r.PathValue("id"), q.p.User.ID)
		if err != nil {
			q.fail(err)
			return
		}
		_ = q.call(agentproto.OpFilesUploadAbort, agentproto.UploadFinish{Root: u.Root, ID: u.ID, Path: u.Path}, nil)
		_, _ = s.db.ExecContext(r.Context(), `DELETE FROM file_uploads WHERE id = ?`, u.ID)
		w.WriteHeader(http.StatusNoContent)
	})
}
