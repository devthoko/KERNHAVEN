package metrics

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/platform/version"
)

// Service states (AT-F13-04).
const (
	StatusOK            = "ok"
	StatusDown          = "down"
	StatusNotConfigured = "not_configured"
)

// Check is the health of one service.
type Check struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// CaddyState reports the reverse proxy (M12): configured, reachable, in sync.
type CaddyState func(ctx context.Context) (configured, reachable, inSync bool, lastError string)

// HealthDeps are the services the health check looks at.
type HealthDeps struct {
	DB      *sql.DB
	Started time.Time
	Docker  *agentclient.Client
	Storage *agentclient.Client
	Files   *agentclient.Client
	Proxy   *agentclient.Client
	Monitor *agentclient.Client
	Caddy   CaddyState
}

func agentCheck(ctx context.Context, name, label string, cl *agentclient.Client) Check {
	c := Check{Name: name, Label: label, Status: StatusNotConfigured}
	if cl == nil {
		return c
	}
	var info agentproto.AgentInfo
	if err := cl.Do(ctx, agentclient.Call{Op: agentproto.OpAgentInfo, Actor: "system", RequestID: "health"}, &info); err != nil {
		c.Status, c.Detail = StatusDown, unavailable(err)
		return c
	}
	c.Status, c.Detail = StatusOK, fmt.Sprintf("version %s, up %s", info.Version, (time.Duration(info.UptimeSeconds)*time.Second).String())
	return c
}

// Health checks every service in parallel, each within 5 seconds.
func Health(ctx context.Context, d HealthDeps, now time.Time) []Check {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	checks := make([]Check, 8)
	var wg sync.WaitGroup
	run := func(i int, f func() Check) {
		wg.Add(1)
		go func() { defer wg.Done(); checks[i] = f() }()
	}
	run(0, func() Check {
		c := Check{Name: "core", Label: "Kernhaven Core", Status: StatusOK, Detail: fmt.Sprintf("version %s, up %s", version.Get().Version, now.Sub(d.Started).Truncate(time.Second))}
		if err := d.DB.PingContext(ctx); err != nil {
			c.Status, c.Detail = StatusDown, "database: "+err.Error()
		}
		return c
	})
	run(1, func() Check { return agentCheck(ctx, "agent", "Host agent", d.Docker) })
	run(2, func() Check {
		c := Check{Name: "docker", Label: "Docker Engine", Status: StatusNotConfigured}
		if d.Docker == nil {
			return c
		}
		var info agentproto.DockerInfo
		if err := d.Docker.Do(ctx, agentclient.Call{Op: agentproto.OpDockerInfo, Actor: "system", RequestID: "health"}, &info); err != nil {
			c.Status, c.Detail = StatusDown, unavailable(err)
			return c
		}
		c.Status, c.Detail = StatusOK, fmt.Sprintf("version %s, %d of %d containers running", info.ServerVersion, info.Running, info.Containers)
		return c
	})
	run(3, func() Check { return agentCheck(ctx, "storage", "Storage service", d.Storage) })
	run(4, func() Check { return agentCheck(ctx, "files", "File service", d.Files) })
	run(5, func() Check { return agentCheck(ctx, "proxy", "Proxy service", d.Proxy) })
	run(6, func() Check {
		c := Check{Name: "caddy", Label: "Caddy", Status: StatusNotConfigured}
		if d.Caddy == nil {
			return c
		}
		configured, reachable, inSync, lastErr := d.Caddy(ctx)
		switch {
		case !configured:
		case !reachable:
			c.Status, c.Detail = StatusDown, "not reachable through the proxy service"
		case !inSync:
			c.Status, c.Detail = StatusDown, "runs a configuration other than the stored routes"
		default:
			c.Status, c.Detail = StatusOK, "configuration in sync"
		}
		if lastErr != "" && c.Status == StatusOK {
			c.Detail += "; last change refused: " + lastErr
		}
		return c
	})
	run(7, func() Check { return agentCheck(ctx, "monitor", "Monitor service", d.Monitor) })
	wg.Wait()
	return checks
}
