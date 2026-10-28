package agent

import (
	"context"

	"github.com/devthoko/KERNHAVEN/internal/agent/network"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// proxyOperations are the M12 operations. The Caddy configuration is built
// and validated in package proxy on every request (ADR-0025).
func proxyOperations(s *network.Service) map[string]handler {
	return map[string]handler{
		agentproto.OpProxyApply: typed(func(ctx context.Context, p agentproto.ProxyApply) (any, error) {
			return s.Apply(ctx, p)
		}),
		agentproto.OpProxyStatus: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			return s.Status(ctx)
		}),
		agentproto.OpNetworkOverview: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			return s.Overview(ctx)
		}),
	}
}
