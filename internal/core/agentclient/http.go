package agentclient

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// Status is the API view of the agent and Docker Engine.
type Status struct {
	Agent  ComponentStatus[agentproto.AgentInfo]  `json:"agent"`
	Docker ComponentStatus[agentproto.DockerInfo] `json:"docker"`
}

// ComponentStatus reports availability and details or an error.
type ComponentStatus[T any] struct {
	Available bool   `json:"available"`
	Error     string `json:"error,omitempty"`
	Info      *T     `json:"info,omitempty"`
}

// describe turns client errors into short, non-sensitive status messages.
func describe(err error) string {
	var ae *Error
	switch {
	case errors.Is(err, ErrUnavailable):
		return "the host agent is not running or not reachable"
	case errors.As(err, &ae) && ae.Code == agentproto.CodeDockerUnavailable:
		return "Docker Engine is not reachable: " + ae.Message
	case errors.As(err, &ae):
		return ae.Message
	default:
		return "unexpected error"
	}
}

// QueryStatus asks the agent for its own and Docker's status.
func (cl *Client) QueryStatus(ctx context.Context, actor, requestID string) Status {
	var st Status
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var a agentproto.AgentInfo
	if err := cl.Do(ctx, Call{Op: agentproto.OpAgentInfo, Actor: actor, RequestID: requestID}, &a); err != nil {
		st.Agent.Error = describe(err)
		st.Docker.Error = "unknown while the host agent is unavailable"
		return st
	}
	st.Agent = ComponentStatus[agentproto.AgentInfo]{Available: true, Info: &a}
	var d agentproto.DockerInfo
	if err := cl.Do(ctx, Call{Op: agentproto.OpDockerInfo, Actor: actor, RequestID: requestID}, &d); err != nil {
		st.Docker.Error = describe(err)
		return st
	}
	st.Docker = ComponentStatus[agentproto.DockerInfo]{Available: true, Info: &d}
	return st
}

// RegisterRoutes adds GET /api/v1/system/agent. cl may be nil when no agent
// is configured.
func RegisterRoutes(rt *httpserver.Router, cl *Client) {
	rt.HandleFunc("GET /api/v1/system/agent", httpserver.RequirePermission(string(authz.SystemRead)), func(w http.ResponseWriter, r *http.Request) {
		if cl == nil {
			var st Status
			st.Agent.Error = "no host agent is configured"
			st.Docker.Error = "unknown while the host agent is unavailable"
			httpserver.WriteJSON(w, http.StatusOK, st)
			return
		}
		actor := "system"
		if p, ok := identity.FromContext(r.Context()); ok {
			actor = p.User.Username
		}
		httpserver.WriteJSON(w, http.StatusOK, cl.QueryStatus(r.Context(), actor, httpserver.RequestID(r.Context())))
	})
}
