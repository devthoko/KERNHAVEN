// Package containers is the Core's container management module (M6). It
// authorizes and audits requests, evaluates the container policy for
// previews and early rejection, and forwards operations to the agent.
package containers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// KindImagePull is the job kind for image pulls.
const KindImagePull = "images.pull"

// Service implements the container API.
type Service struct {
	agent      *agentclient.Client // nil when no agent is configured
	audit      *audit.Log
	jobs       *jobs.Service
	wake       func()
	bindRoots  []string
	opTimeout  time.Duration
	pullBudget time.Duration
}

// New returns the service and registers the image pull job kind.
func New(agent *agentclient.Client, auditLog *audit.Log, js *jobs.Service, wake func(), bindRoots []string) *Service {
	s := &Service{agent: agent, audit: auditLog, jobs: js, wake: wake, bindRoots: bindRoots,
		opTimeout: 2 * time.Minute, pullBudget: 6 * time.Minute}
	js.Register(jobs.Kind{Name: KindImagePull, MaxAttempts: 3, Plan: s.planPull})
	return s
}

type pullPayload struct {
	Reference string `json:"reference"`
	Actor     string `json:"actor"`
}

func (s *Service) planPull(raw json.RawMessage) ([]jobs.Step, error) {
	var p pullPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if !policy.ValidImageReference(p.Reference) {
		return nil, errors.New("invalid image reference")
	}
	return []jobs.Step{{Name: "pull " + p.Reference, Run: func(ctx context.Context, sc *jobs.StepContext) error {
		if s.agent == nil {
			return jobs.Permanent(errors.New("no host agent is configured"))
		}
		ctx, cancel := context.WithTimeout(ctx, s.pullBudget)
		defer cancel()
		var res agentproto.PullResult
		err := s.agent.Do(ctx, agentclient.Call{Op: agentproto.OpImagesPull, Params: agentproto.ImageRef{Reference: p.Reference},
			Actor: p.Actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}, &res)
		var ae *agentclient.Error
		if errors.As(err, &ae) && (ae.Code == agentproto.CodeNotFound || ae.Code == agentproto.CodeInvalidParams) {
			return jobs.Permanent(err)
		}
		if err != nil {
			return err
		}
		sc.Logf("pulled %s → %s (image %s)", p.Reference, res.Digest, res.ID)
		return sc.SetOutput("digest", res.Digest)
	}}}, nil
}

// --- request helpers ---

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

// call runs an agent operation and writes an error response on failure.
func (q *request) call(op string, params, out any) bool {
	if q.svc.agent == nil {
		httpserver.WriteError(q.w, q.r, http.StatusServiceUnavailable, "agent_unavailable", "no host agent is configured")
		return false
	}
	ctx, cancel := context.WithTimeout(q.r.Context(), q.svc.opTimeout)
	defer cancel()
	err := q.svc.agent.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: q.actor(), RequestID: q.m.RequestID}, out)
	if err != nil {
		writeAgentError(q.w, q.r, err)
		return false
	}
	return true
}

func writeAgentError(w http.ResponseWriter, r *http.Request, err error) {
	var ae *agentclient.Error
	switch {
	case errors.Is(err, agentclient.ErrUnavailable):
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "agent_unavailable", "the host agent is not running or not reachable")
	case errors.As(err, &ae):
		switch ae.Code {
		case agentproto.CodeNotFound:
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", ae.Message)
		case agentproto.CodeConflict:
			httpserver.WriteError(w, r, http.StatusConflict, "conflict", ae.Message)
		case agentproto.CodeInvalidParams:
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", ae.Message)
		case agentproto.CodePolicyViolation:
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "policy_violation", ae.Message)
		case agentproto.CodeDockerUnavailable:
			httpserver.WriteError(w, r, http.StatusServiceUnavailable, "docker_unavailable", ae.Message)
		default:
			httpserver.InternalError(w, r, err)
		}
	default:
		httpserver.InternalError(w, r, err)
	}
}

// record writes an audit event; outcome failure if err != nil.
func (q *request) record(action, target string, err error, kv ...string) {
	ev := audit.Event{Action: action, Target: target, Result: audit.Success, RequestID: q.m.RequestID, IP: q.m.IP, Details: map[string]string{}}
	if q.p != nil {
		ev.ActorID, ev.Actor = q.p.User.ID, q.p.User.Username
	}
	if err != nil {
		ev.Result = audit.Failure
		ev.Details["error"] = err.Error()
	}
	for i := 0; i+1 < len(kv); i += 2 {
		ev.Details[kv[i]] = kv[i+1]
	}
	_ = q.svc.audit.Record(context.WithoutCancel(q.r.Context()), ev)
}

// callAudited runs a state-changing operation and audits its outcome.
func (q *request) callAudited(action, target, op string, params, out any, kv ...string) bool {
	if q.svc.agent == nil {
		httpserver.WriteError(q.w, q.r, http.StatusServiceUnavailable, "agent_unavailable", "no host agent is configured")
		return false
	}
	ctx, cancel := context.WithTimeout(q.r.Context(), q.svc.opTimeout)
	defer cancel()
	err := q.svc.agent.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: q.actor(), RequestID: q.m.RequestID}, out)
	q.record(action, target, err, kv...)
	if err != nil {
		writeAgentError(q.w, q.r, err)
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	return httpserver.DecodeJSON(w, r, v) == nil
}

// --- container creation with policy ---

// Exception is an owner-approved policy exception.
type Exception struct {
	Rule   string `json:"rule"`
	Reason string `json:"reason"`
}

// CreateRequest is the API body for container creation.
type CreateRequest struct {
	Spec       agentproto.ContainerSpec `json:"spec"`
	Exceptions []Exception              `json:"exceptions"`
	Start      bool                     `json:"start"`
}

// Evaluation is the policy preview.
type Evaluation struct {
	Valid      bool             `json:"valid"`
	Errors     []string         `json:"errors"`
	Violations []policy.Finding `json:"violations"`
	Warnings   []policy.Finding `json:"warnings"`
}

func (s *Service) evaluate(spec agentproto.ContainerSpec) Evaluation {
	ev := Evaluation{Errors: []string{}, Violations: []policy.Finding{}, Warnings: []policy.Finding{}}
	if err := policy.Validate(spec); err != nil {
		ev.Errors = append(ev.Errors, strings.Split(err.Error(), "\n")...)
		return ev
	}
	res := policy.Evaluate(spec, policy.Options{AllowedBindRoots: s.bindRoots})
	ev.Violations, ev.Warnings = res.Violations, res.Warnings
	ev.Valid = true
	return ev
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	q := s.req(w, r)
	var in CreateRequest
	if !decode(w, r, &in) {
		return
	}
	ev := s.evaluate(in.Spec)
	if !ev.Valid {
		httpserver.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": map[string]string{"code": "validation_failed", "message": strings.Join(ev.Errors, "; "), "request_id": q.m.RequestID},
		})
		return
	}
	rules := make([]string, 0, len(in.Exceptions))
	for _, x := range in.Exceptions {
		if utf8.RuneCountInString(strings.TrimSpace(x.Reason)) < 10 || len(x.Reason) > 500 {
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", "each exception needs a reason of 10 to 500 characters")
			return
		}
		rules = append(rules, x.Rule)
	}
	// Approving policy exceptions is security-relevant (AT-F09-04).
	if len(in.Exceptions) > 0 && identity.CheckStepUp(q.r.Context()) != nil {
		httpserver.WriteError(q.w, q.r, http.StatusForbidden, "step_up_required", identity.ErrStepUpRequired.Error())
		return
	}
	if len(in.Exceptions) > 0 && !q.p.Has(authz.PolicyExceptions) {
		q.record("policy.exception", "container:"+in.Spec.Name, errors.New("only owners may approve policy exceptions"), "rules", strings.Join(rules, ","))
		httpserver.WriteError(w, r, http.StatusForbidden, "forbidden", "only owners may approve policy exceptions")
		return
	}
	if _, err := policy.Check(in.Spec, rules, policy.Options{AllowedBindRoots: s.bindRoots}); err != nil {
		q.record("container.create", "container:"+in.Spec.Name, err)
		httpserver.WriteJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error":      map[string]string{"code": "policy_violation", "message": err.Error(), "request_id": q.m.RequestID},
			"violations": ev.Violations,
		})
		return
	}
	for _, x := range in.Exceptions {
		q.record("policy.exception", "container:"+in.Spec.Name, nil, "rule", x.Rule, "reason", x.Reason)
	}
	var res agentproto.CreateResult
	if q.callAudited("container.create", "container:"+in.Spec.Name, agentproto.OpContainersCreate,
		agentproto.CreateContainer{Spec: in.Spec, Exceptions: rules, Start: in.Start}, &res,
		"image", in.Spec.Image, "exceptions", strings.Join(rules, ",")) {
		httpserver.WriteJSON(w, http.StatusCreated, res)
	}
}

// --- routes ---

// Register adds the container, image, volume and network routes.
func (s *Service) Register(rt *httpserver.Router) {
	read := httpserver.RequirePermission(string(authz.ContainersRead))
	operate := httpserver.RequirePermission(string(authz.ContainersOperate))
	manage := httpserver.RequirePermission(string(authz.ContainersManage))

	rt.HandleFunc("GET /api/v1/containers", read, func(w http.ResponseWriter, r *http.Request) {
		var out []agentproto.ContainerSummary
		if s.req(w, r).call(agentproto.OpContainersList, agentproto.ContainersList{All: r.URL.Query().Get("all") != "false"}, &out) {
			httpserver.WriteJSON(w, http.StatusOK, map[string]any{"containers": out})
		}
	})
	rt.HandleFunc("POST /api/v1/containers/validate", manage, func(w http.ResponseWriter, r *http.Request) {
		var spec agentproto.ContainerSpec
		if !decode(w, r, &spec) {
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, s.evaluate(spec))
	})
	rt.HandleFunc("POST /api/v1/containers", manage, s.create)
	rt.HandleFunc("GET /api/v1/containers/{id}", read, func(w http.ResponseWriter, r *http.Request) {
		var out agentproto.ContainerDetail
		if s.req(w, r).call(agentproto.OpContainersInspect, agentproto.ContainerRef{ID: r.PathValue("id")}, &out) {
			httpserver.WriteJSON(w, http.StatusOK, out)
		}
	})
	rt.HandleFunc("DELETE /api/v1/containers/{id}", manage, func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		q := r.URL.Query()
		p := agentproto.RemoveContainer{ID: id, Force: q.Get("force") == "true", RemoveVolumes: q.Get("volumes") == "true"}
		if s.req(w, r).callAudited("container.remove", "container:"+id, agentproto.OpContainersRemove, p, nil,
			"force", strconv.FormatBool(p.Force), "volumes", strconv.FormatBool(p.RemoveVolumes)) {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	for _, a := range []struct{ name, op string }{
		{"start", agentproto.OpContainersStart}, {"stop", agentproto.OpContainersStop}, {"restart", agentproto.OpContainersRestart},
		{"pause", agentproto.OpContainersPause}, {"unpause", agentproto.OpContainersUnpause},
	} {
		a := a
		rt.HandleFunc("POST /api/v1/containers/{id}/"+a.name, operate, func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var params any = agentproto.ContainerRef{ID: id}
			if a.name == "stop" || a.name == "restart" {
				var in struct {
					TimeoutSeconds int `json:"timeout_seconds"`
				}
				if r.ContentLength != 0 && !decode(w, r, &in) {
					return
				}
				params = agentproto.ContainerStop{ID: id, TimeoutSeconds: in.TimeoutSeconds}
			}
			var out agentproto.ActionResult
			if s.req(w, r).callAudited("container."+a.name, "container:"+id, a.op, params, &out) {
				httpserver.WriteJSON(w, http.StatusOK, out)
			}
		})
	}
	rt.HandleFunc("GET /api/v1/containers/{id}/logs", operate, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		p := agentproto.LogsRequest{ID: r.PathValue("id"), Timestamps: q.Get("timestamps") == "true"}
		for name, dst := range map[string]*int64{"since": &p.Since, "until": &p.Until} {
			if v := q.Get(name); v != "" {
				n, err := strconv.ParseInt(v, 10, 64)
				if err != nil {
					httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", name+" must be Unix seconds")
					return
				}
				*dst = n
			}
		}
		if v := q.Get("tail"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				httpserver.WriteError(w, r, http.StatusBadRequest, "invalid_parameter", "tail must be a number")
				return
			}
			p.Tail = n
		}
		var out agentproto.Logs
		if s.req(w, r).call(agentproto.OpContainersLogs, p, &out) {
			httpserver.WriteJSON(w, http.StatusOK, out)
		}
	})

	rt.HandleFunc("GET /api/v1/images", read, func(w http.ResponseWriter, r *http.Request) {
		var out []agentproto.ImageSummary
		if s.req(w, r).call(agentproto.OpImagesList, nil, &out) {
			httpserver.WriteJSON(w, http.StatusOK, map[string]any{"images": out})
		}
	})
	rt.HandleFunc("POST /api/v1/images/pull", manage, func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		var in agentproto.ImageRef
		if !decode(w, r, &in) {
			return
		}
		if !policy.ValidImageReference(in.Reference) {
			httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", "not a valid image reference")
			return
		}
		if s.agent == nil {
			httpserver.WriteError(w, r, http.StatusServiceUnavailable, "agent_unavailable", "no host agent is configured")
			return
		}
		id, err := s.jobs.Enqueue(r.Context(), jobs.Request{Kind: KindImagePull, Payload: pullPayload{Reference: in.Reference, Actor: q.actor()},
			CreatedBy: q.p.User.ID, DedupeKey: KindImagePull + ":" + in.Reference})
		if errors.Is(err, jobs.ErrDuplicate) {
			httpserver.WriteError(w, r, http.StatusConflict, "conflict", "a pull of this image is already queued or running")
			return
		}
		q.record("image.pull", "image:"+in.Reference, err, "job", strconv.FormatInt(id, 10))
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		if s.wake != nil {
			s.wake()
		}
		httpserver.WriteJSON(w, http.StatusAccepted, map[string]int64{"job_id": id})
	})
	rt.HandleFunc("POST /api/v1/images/remove", manage, func(w http.ResponseWriter, r *http.Request) {
		var in agentproto.ImageRef
		if !decode(w, r, &in) {
			return
		}
		if s.req(w, r).callAudited("image.remove", "image:"+in.Reference, agentproto.OpImagesRemove, in, nil, "force", strconv.FormatBool(in.Force)) {
			w.WriteHeader(http.StatusNoContent)
		}
	})
	rt.HandleFunc("POST /api/v1/images/prune", manage, func(w http.ResponseWriter, r *http.Request) {
		var out agentproto.PruneResult
		if s.req(w, r).callAudited("image.prune", "images", agentproto.OpImagesPrune, nil, &out) {
			httpserver.WriteJSON(w, http.StatusOK, out)
		}
	})

	rt.HandleFunc("GET /api/v1/volumes", read, func(w http.ResponseWriter, r *http.Request) {
		var out []agentproto.VolumeSummary
		if s.req(w, r).call(agentproto.OpVolumesList, nil, &out) {
			httpserver.WriteJSON(w, http.StatusOK, map[string]any{"volumes": out})
		}
	})
	rt.HandleFunc("POST /api/v1/volumes", manage, func(w http.ResponseWriter, r *http.Request) {
		var in agentproto.VolumeCreate
		if !decode(w, r, &in) {
			return
		}
		if s.req(w, r).callAudited("volume.create", "volume:"+in.Name, agentproto.OpVolumesCreate, in, nil) {
			httpserver.WriteJSON(w, http.StatusCreated, agentproto.NamedObject{Name: in.Name})
		}
	})
	rt.HandleFunc("DELETE /api/v1/volumes/{name}", manage, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if s.req(w, r).callAudited("volume.remove", "volume:"+name, agentproto.OpVolumesRemove, agentproto.NamedObject{Name: name}, nil) {
			w.WriteHeader(http.StatusNoContent)
		}
	})

	rt.HandleFunc("GET /api/v1/networks", read, func(w http.ResponseWriter, r *http.Request) {
		var out []agentproto.NetworkSummary
		if s.req(w, r).call(agentproto.OpNetworksList, nil, &out) {
			httpserver.WriteJSON(w, http.StatusOK, map[string]any{"networks": out})
		}
	})
	rt.HandleFunc("POST /api/v1/networks", manage, func(w http.ResponseWriter, r *http.Request) {
		var in agentproto.NetworkCreate
		if !decode(w, r, &in) {
			return
		}
		var out agentproto.NetworkSummary
		if s.req(w, r).callAudited("network.create", "network:"+in.Name, agentproto.OpNetworksCreate, in, &out, "internal", strconv.FormatBool(in.Internal)) {
			httpserver.WriteJSON(w, http.StatusCreated, out)
		}
	})
	rt.HandleFunc("DELETE /api/v1/networks/{name}", manage, func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if s.req(w, r).callAudited("network.remove", "network:"+name, agentproto.OpNetworksRemove, agentproto.NamedObject{Name: name}, nil) {
			w.WriteHeader(http.StatusNoContent)
		}
	})
}
