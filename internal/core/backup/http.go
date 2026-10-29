package backup

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
)

func actorFrom(r *http.Request) Actor {
	m := identity.MetaFrom(r)
	a := Actor{Name: "system", RequestID: m.RequestID, IP: m.IP}
	if p, ok := identity.FromContext(r.Context()); ok {
		a.ID, a.Name = p.User.ID, p.User.Username
	}
	return a
}

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ve *ValidationError
	var te *TargetError
	switch {
	case errors.As(err, &ve):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ve.Msg)
	case errors.As(err, &te):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", te.Msg)
	case errors.Is(err, ErrPassphrase), errors.Is(err, netguard.ErrForbiddenAddress):
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", err.Error())
	case errors.Is(err, ErrNotFound):
		httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "not found")
	case errors.Is(err, ErrExists), errors.Is(err, ErrRepoExists), errors.Is(err, ErrInUse), errors.Is(err, jobs.ErrDuplicate):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, identity.ErrStepUpRequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "step_up_required", err.Error())
	case errors.As(err, new(*UnavailableError)):
		// Target problems (unreachable, refused credentials) are the
		// administrator's to fix; they are not internal errors.
		httpserver.WriteError(w, r, http.StatusBadGateway, "target_unavailable", err.Error())
	default:
		httpserver.InternalError(w, r, err)
	}
}

// stepUp: repositories hold credentials and decide where data goes, and
// restores overwrite data.
func stepUp(w http.ResponseWriter, r *http.Request) bool {
	if err := identity.CheckStepUp(r.Context()); err != nil {
		writeErr(w, r, err)
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, r, ErrNotFound)
		return 0, false
	}
	return id, true
}

// Register adds the backup routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.BackupRead))
	run := httpserver.RequirePermission(string(authz.BackupRun))
	manage := httpserver.RequirePermission(string(authz.BackupManage))

	rt.HandleFunc("GET /api/v1/backup/repositories", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Repositories(r.Context())
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"repositories": list})
	})
	rt.HandleFunc("POST /api/v1/backup/repositories", manage, func(w http.ResponseWriter, r *http.Request) {
		var in RepoInput
		if httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		repo, err := s.CreateRepository(r.Context(), actorFrom(r), in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, repo)
	})
	rt.HandleFunc("PUT /api/v1/backup/repositories/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		var in RepoInput
		if !ok || httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		repo, err := s.UpdateRepository(r.Context(), actorFrom(r), id, in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, repo)
	})
	rt.HandleFunc("DELETE /api/v1/backup/repositories/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok || !stepUp(w, r) {
			return
		}
		if err := s.DeleteRepository(r.Context(), actorFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/backup/repositories/{id}/verify", run, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		job, err := s.StartVerify(r.Context(), actorFrom(r), id)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": job})
	})
	rt.HandleFunc("GET /api/v1/backup/repositories/{id}/snapshots", read, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		list, err := s.Snapshots(r.Context(), id)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"snapshots": list})
	})
	rt.HandleFunc("GET /api/v1/backup/repositories/{id}/snapshots/{snapshot}", read, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		m, err := s.SnapshotDetail(r.Context(), id, r.PathValue("snapshot"))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, m)
	})
	rt.HandleFunc("POST /api/v1/backup/repositories/{id}/snapshots/{snapshot}/restore", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		var in struct {
			Stack string `json:"stack"`
		}
		if !ok || httpserver.DecodeJSON(w, r, &in) != nil || !stepUp(w, r) {
			return
		}
		job, err := s.StartRestore(r.Context(), actorFrom(r), id, r.PathValue("snapshot"), in.Stack)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": job})
	})
	rt.HandleFunc("GET /api/v1/backup/plans", read, func(w http.ResponseWriter, r *http.Request) {
		list, err := s.Plans(r.Context())
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"plans": list})
	})
	rt.HandleFunc("POST /api/v1/backup/plans", manage, func(w http.ResponseWriter, r *http.Request) {
		var in PlanInput
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		p, err := s.SavePlan(r.Context(), actorFrom(r), 0, in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, p)
	})
	rt.HandleFunc("PUT /api/v1/backup/plans/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		var in PlanInput
		if !ok || httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		p, err := s.SavePlan(r.Context(), actorFrom(r), id, in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, p)
	})
	rt.HandleFunc("DELETE /api/v1/backup/plans/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		if err := s.DeletePlan(r.Context(), actorFrom(r), id); err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("POST /api/v1/backup/plans/{id}/run", run, func(w http.ResponseWriter, r *http.Request) {
		id, ok := pathID(w, r)
		if !ok {
			return
		}
		job, err := s.StartBackup(r.Context(), actorFrom(r), id, "manual")
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": job})
	})
	rt.HandleFunc("GET /api/v1/backup/sftp-key", manage, func(w http.ResponseWriter, r *http.Request) {
		key, err := s.SFTPPublicKey(r.Context())
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"public_key": key})
	})
	rt.HandleFunc("POST /api/v1/backup/sftp-scan", manage, func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		key, fp, err := s.ScanHostKey(r.Context(), in.Host, in.Port)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, map[string]any{"host_key": key, "fingerprint": fp})
	})
}
