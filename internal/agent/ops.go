package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/platform/version"
)

// Docker is the subset of the Docker client the operations use.
type Docker interface {
	Info(ctx context.Context) (agentproto.DockerInfo, error)
	ListContainers(ctx context.Context, all bool) ([]agentproto.ContainerSummary, error)
	Inspect(ctx context.Context, ref string) (agentproto.ContainerDetail, error)
	Start(ctx context.Context, ref string) (bool, error)
	Stop(ctx context.Context, ref string, timeout time.Duration) (bool, error)
	Restart(ctx context.Context, ref string, timeout time.Duration) (bool, error)
}

// errInvalidParams marks parameter validation failures.
type errInvalidParams struct{ msg string }

func (e *errInvalidParams) Error() string { return e.msg }

func invalid(format string, a ...any) error { return &errInvalidParams{fmt.Sprintf(format, a...)} }

// handler runs one operation with its raw (already hash-verified) params.
type handler func(ctx context.Context, raw json.RawMessage) (any, error)

// decode parses params strictly into P: unknown fields and trailing data are
// rejected; null or empty means the zero value.
func decode[P any](raw json.RawMessage) (P, error) {
	var p P
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return p, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, invalid("invalid parameters: %v", err)
	}
	if dec.More() {
		return p, invalid("invalid parameters: trailing data")
	}
	return p, nil
}

func typed[P any](run func(ctx context.Context, p P) (any, error)) handler {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		p, err := decode[P](raw)
		if err != nil {
			return nil, err
		}
		return run(ctx, p)
	}
}

var containerRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

func validRef(id string) error {
	if !containerRef.MatchString(id) {
		return invalid("id must be a container ID or name (1-128 characters: letters, digits, _ . -)")
	}
	return nil
}

func stopTimeout(s int) (time.Duration, error) {
	if s < 0 || s > 300 {
		return 0, invalid("timeout_seconds must be 0..300")
	}
	if s == 0 {
		s = 10
	}
	return time.Duration(s) * time.Second, nil
}

// operations builds the allow-list. Nothing outside this map can be invoked.
func operations(d Docker, started time.Time) map[string]handler {
	return map[string]handler{
		agentproto.OpAgentInfo: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			v := version.Get()
			return agentproto.AgentInfo{Version: v.Version, Commit: v.Commit, UptimeSeconds: int64(time.Since(started).Seconds())}, nil
		}),
		agentproto.OpDockerInfo: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			return d.Info(ctx)
		}),
		agentproto.OpContainersList: typed(func(ctx context.Context, p agentproto.ContainersList) (any, error) {
			return d.ListContainers(ctx, p.All)
		}),
		agentproto.OpContainersInspect: typed(func(ctx context.Context, p agentproto.ContainerRef) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			return d.Inspect(ctx, p.ID)
		}),
		agentproto.OpContainersStart: typed(func(ctx context.Context, p agentproto.ContainerRef) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			changed, err := d.Start(ctx, p.ID)
			return agentproto.ActionResult{ID: p.ID, Changed: changed}, err
		}),
		agentproto.OpContainersStop: typed(func(ctx context.Context, p agentproto.ContainerStop) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			t, err := stopTimeout(p.TimeoutSeconds)
			if err != nil {
				return nil, err
			}
			changed, err := d.Stop(ctx, p.ID, t)
			return agentproto.ActionResult{ID: p.ID, Changed: changed}, err
		}),
		agentproto.OpContainersRestart: typed(func(ctx context.Context, p agentproto.ContainerStop) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			t, err := stopTimeout(p.TimeoutSeconds)
			if err != nil {
				return nil, err
			}
			changed, err := d.Restart(ctx, p.ID, t)
			return agentproto.ActionResult{ID: p.ID, Changed: changed}, err
		}),
	}
}

// OperationNames lists the allow-listed operations (sorted).
func OperationNames() []string {
	ops := operations(nil, time.Time{})
	names := make([]string, 0, len(ops))
	for n := range ops {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// errorCode maps an operation error to the protocol code and HTTP status.
func errorCode(err error) (string, int) {
	var ip *errInvalidParams
	switch {
	case errors.As(err, &ip):
		return agentproto.CodeInvalidParams, 400
	case errors.Is(err, docker.ErrNotFound):
		return agentproto.CodeNotFound, 404
	case errors.Is(err, docker.ErrConflict):
		return agentproto.CodeConflict, 409
	case errors.Is(err, docker.ErrUnavailable), errors.Is(err, context.DeadlineExceeded):
		return agentproto.CodeDockerUnavailable, 503
	default:
		return agentproto.CodeInternal, 500
	}
}
