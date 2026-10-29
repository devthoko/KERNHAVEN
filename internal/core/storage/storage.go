// Package storage exposes disk inventory, formatting and mounts (M9). All
// host access and every safety decision happen in the storage service
// (kernhaven-agent in the storage role); the Core adds authorization,
// re-authentication, typed confirmation, audit and the journaled job.
package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// KindFormat is the job that formats a disk.
const KindFormat = "storage.format"

// Service implements the storage API.
type Service struct {
	client *agentclient.Client // nil when no storage service is configured
	audit  *audit.Log
	ids    *identity.Service
	jobs   *jobs.Service
	wake   func()
}

// New returns the service and registers the format job.
func New(client *agentclient.Client, auditLog *audit.Log, ids *identity.Service, js *jobs.Service, wake func()) *Service {
	s := &Service{client: client, audit: auditLog, ids: ids, jobs: js, wake: wake}
	// Formatting is never retried automatically: it destroys data.
	js.Register(jobs.Kind{Name: KindFormat, MaxAttempts: 1, Plan: s.planFormat})
	return s
}

type formatPayload struct {
	Params agentproto.StorageFormat `json:"params"`
	Actor  string                   `json:"actor"`
}

func (s *Service) planFormat(raw json.RawMessage) ([]jobs.Step, error) {
	var p formatPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	return []jobs.Step{{
		Name: "format " + p.Params.Path + " with " + p.Params.FSType,
		Run: func(ctx context.Context, sc *jobs.StepContext) error {
			if s.client == nil {
				return jobs.Permanent(errors.New("no storage service is configured"))
			}
			cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
			defer cancel()
			var res agentproto.StorageFormatResult
			err := s.client.Do(cctx, agentclient.Call{Op: agentproto.OpStorageFormat, Params: p.Params, Actor: p.Actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}, &res)
			_ = s.audit.Record(context.WithoutCancel(ctx), audit.Event{Actor: p.Actor, Action: "storage.format.result", Target: "disk:" + p.Params.Path,
				Result: result(err), Details: details(err, "job", fmt.Sprint(sc.JobID), "partition", res.Partition, "uuid", res.UUID)})
			if err != nil {
				return jobs.Permanent(err)
			}
			sc.Logf("created %s file system %s on %s", res.FSType, res.UUID, res.Partition)
			return sc.SetOutput("result", res)
		},
	}}, nil
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

func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	var ae *agentclient.Error
	var rl *identity.RateLimitError
	switch {
	case errors.Is(err, agentclient.ErrUnavailable):
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "storage_unavailable", "the storage service is not running or not reachable")
	case errors.Is(err, identity.ErrStepUpRequired):
		httpserver.WriteError(w, r, http.StatusForbidden, "step_up_required", err.Error())
	case errors.As(err, &rl):
		httpserver.WriteError(w, r, http.StatusTooManyRequests, "rate_limited", rl.Error())
	case errors.Is(err, jobs.ErrDuplicate):
		httpserver.WriteError(w, r, http.StatusConflict, "conflict", "this disk is already being formatted")
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
		httpserver.InternalError(w, r, err)
	}
}

func (s *Service) call(r *http.Request, op string, params, out any) error {
	if s.client == nil {
		return agentclient.ErrUnavailable
	}
	actor := "system"
	if p, ok := identity.FromContext(r.Context()); ok {
		actor = p.User.Username
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()
	return s.client.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: actor, RequestID: identity.MetaFrom(r).RequestID}, out)
}

func (s *Service) record(r *http.Request, action, target string, err error, kv ...string) {
	m := identity.MetaFrom(r)
	ev := audit.Event{Action: action, Target: target, Result: result(err), RequestID: m.RequestID, IP: m.IP, Details: details(err, kv...)}
	if p, ok := identity.FromContext(r.Context()); ok {
		ev.ActorID, ev.Actor = p.User.ID, p.User.Username
	}
	_ = s.audit.Record(context.WithoutCancel(r.Context()), ev)
}

// Inventory returns the disks and file systems (M15 alerts); ErrUnavailable
// from agentclient when no storage service is configured.
func (s *Service) Inventory(ctx context.Context) (agentproto.StorageInventory, error) {
	var inv agentproto.StorageInventory
	if s.client == nil {
		return inv, agentclient.ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	err := s.client.Do(ctx, agentclient.Call{Op: agentproto.OpStorageInventory, Actor: "system", RequestID: "alerts"}, &inv)
	return inv, err
}

// FormatRequest is the API input for formatting.
type FormatRequest struct {
	agentproto.StorageFormat
	// Confirm must be the disk's name (for example "sdb").
	Confirm string `json:"confirm"`
}

// Register adds the storage routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.StorageRead))
	manage := httpserver.RequirePermission(string(authz.StorageManage))

	rt.HandleFunc("GET /api/v1/storage", read, func(w http.ResponseWriter, r *http.Request) {
		var inv agentproto.StorageInventory
		if err := s.call(r, agentproto.OpStorageInventory, nil, &inv); err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, inv)
	})

	rt.HandleFunc("POST /api/v1/storage/format", manage, func(w http.ResponseWriter, r *http.Request) {
		var in FormatRequest
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		target := "disk:" + in.Path
		// Typed confirmation (AT-F06-03): the disk's name, as shown in the UI.
		if in.Path == "" || in.Confirm != path.Base(in.Path) {
			s.record(r, "storage.format", target, errors.New("confirmation does not match"))
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "confirmation_required", "type the disk's name to confirm")
			return
		}
		p, _ := identity.FromContext(r.Context())
		if err := identity.CheckStepUp(r.Context()); err != nil {
			writeErr(w, r, err)
			return
		}
		in.FSType, in.Label = strings.TrimSpace(in.FSType), strings.TrimSpace(in.Label)
		id, err := s.jobs.Enqueue(r.Context(), jobs.Request{Kind: KindFormat, Payload: formatPayload{Params: in.StorageFormat, Actor: p.User.Username},
			CreatedBy: p.User.ID, DedupeKey: "storage:format:" + in.Path})
		s.record(r, "storage.format", target, err, "fstype", in.FSType, "label", in.Label, "serial", in.Serial, "size", fmt.Sprint(in.SizeBytes), "job", fmt.Sprint(id))
		if err != nil {
			writeErr(w, r, err)
			return
		}
		if s.wake != nil {
			s.wake()
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]any{"job_id": id})
	})

	rt.HandleFunc("POST /api/v1/storage/mounts", manage, func(w http.ResponseWriter, r *http.Request) {
		var in agentproto.StorageMount
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		var m agentproto.ManagedMount
		err := s.call(r, agentproto.OpStorageMount, in, &m)
		s.record(r, "storage.mount", "mount:"+in.Name, err, "device", in.Path, "uuid", in.UUID, "path", m.Path)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusCreated, m)
	})

	rt.HandleFunc("DELETE /api/v1/storage/mounts/{name}", manage, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		err := s.call(r, agentproto.OpStorageUnmount, agentproto.StorageUnmount{Name: name}, nil)
		s.record(r, "storage.unmount", "mount:"+name, err)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
