// Package live pushes change notifications to browsers over server-sent
// events (M6b, AT-F01-05): container states, jobs and alerts. One poller
// runs while anyone listens and sends only that something changed; pages
// then reload what they show through the normal API and its permissions.
package live

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// Event types and the permission a listener needs for each.
var eventPermission = map[string]authz.Permission{
	"containers": authz.ContainersRead,
	"jobs":       authz.JobsRead,
	"alerts":     authz.AlertsRead,
}

// Limits.
const (
	MaxConnection = 5 * time.Minute // the browser reconnects; the session is checked again
	Heartbeat     = 25 * time.Second
	MaxListeners  = 200
)

// Event says that something of a kind changed.
type Event struct {
	Type string `json:"type"`
}

// Hub fans out events.
type Hub struct {
	db       *sql.DB
	agent    *agentclient.Client
	log      *slog.Logger
	interval time.Duration

	mu      sync.Mutex
	subs    map[chan Event]map[string]bool // allowed types per listener
	running bool
	last    map[string]string
}

// New returns a hub polling every interval while listeners exist.
func New(db *sql.DB, agent *agentclient.Client, log *slog.Logger, interval time.Duration) *Hub {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &Hub{db: db, agent: agent, log: log, interval: interval, subs: map[chan Event]map[string]bool{}, last: map[string]string{}}
}

// ErrBusy means too many listeners.
var ErrBusy = fmt.Errorf("too many live connections")

func (h *Hub) subscribe(allowed map[string]bool) (chan Event, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) >= MaxListeners {
		return nil, ErrBusy
	}
	ch := make(chan Event, 16)
	h.subs[ch] = allowed
	if !h.running {
		h.running = true
		go h.poll()
	}
	return ch, nil
}

func (h *Hub) unsubscribe(ch chan Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.subs, ch)
}

// Publish sends an event to the listeners allowed to see it; slow
// listeners miss events rather than block others.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch, allowed := range h.subs {
		if !allowed[e.Type] {
			continue
		}
		select {
		case ch <- e:
		default:
		}
	}
}

func (h *Hub) listening() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.subs) == 0 {
		h.running = false
		h.last = map[string]string{}
		return false
	}
	return true
}

func (h *Hub) poll() {
	t := time.NewTicker(h.interval)
	defer t.Stop()
	h.check()
	for range t.C {
		if !h.listening() {
			return
		}
		h.check()
	}
}

// check compares fingerprints of each kind with the last round.
func (h *Hub) check() {
	ctx, cancel := context.WithTimeout(context.Background(), h.interval*2)
	defer cancel()
	for kind, f := range map[string]func(context.Context) (string, error){
		"containers": h.containers,
		// States of the latest jobs, so every transition counts even when
		// timestamps do not move.
		"jobs":   h.query(`SELECT coalesce(max(updated_ms), 0) || ':' || coalesce((SELECT group_concat(id || state, ',') FROM (SELECT id, state FROM jobs ORDER BY id DESC LIMIT 50)), '') FROM jobs`),
		"alerts": h.query(`SELECT coalesce(max(id), 0) || ':' || (SELECT count(*) FROM alerts WHERE state = 'firing') FROM alerts`),
	} {
		fp, err := f(ctx)
		if err != nil {
			continue
		}
		h.mu.Lock()
		prev, seen := h.last[kind]
		h.last[kind] = fp
		h.mu.Unlock()
		if seen && prev != fp {
			h.Publish(Event{Type: kind})
		}
	}
}

func (h *Hub) query(q string) func(context.Context) (string, error) {
	return func(ctx context.Context) (string, error) {
		var fp string
		err := h.db.QueryRowContext(ctx, q).Scan(&fp)
		return fp, err
	}
}

func (h *Hub) containers(ctx context.Context) (string, error) {
	if h.agent == nil {
		return "", fmt.Errorf("no agent")
	}
	var list []agentproto.ContainerSummary
	if err := h.agent.Do(ctx, agentclient.Call{Op: agentproto.OpContainersList, Params: agentproto.ContainersList{All: true}, Actor: "live", RequestID: "live"}, &list); err != nil {
		return "", err
	}
	lines := make([]string, 0, len(list))
	for _, c := range list {
		lines = append(lines, c.ID+" "+c.State+" "+healthOf(c.Status))
	}
	sort.Strings(lines)
	sum := sha256.New()
	for _, l := range lines {
		fmt.Fprintln(sum, l)
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

// healthOf keeps the health part of Docker's status text ("Up 3 minutes
// (healthy)" → "healthy"); the uptime changes every second and is not a
// change worth announcing.
func healthOf(status string) string {
	i, j := strings.LastIndex(status, "("), strings.LastIndex(status, ")")
	if i < 0 || j < i {
		return ""
	}
	return status[i+1 : j]
}

// Register adds GET /api/v1/events.
func (h *Hub) Register(rt *httpserver.Router) {
	rt.HandleFunc("GET /api/v1/events", httpserver.RequirePermission(string(authz.SystemRead)), func(w http.ResponseWriter, r *http.Request) {
		p, ok := identity.FromContext(r.Context())
		if !ok {
			httpserver.WriteError(w, r, http.StatusUnauthorized, "unauthenticated", "authentication required")
			return
		}
		allowed := map[string]bool{}
		var types []string
		for kind, perm := range eventPermission {
			if p.Has(perm) {
				allowed[kind] = true
				types = append(types, kind)
			}
		}
		sort.Strings(types)
		ch, err := h.subscribe(allowed)
		if err != nil {
			httpserver.WriteError(w, r, http.StatusServiceUnavailable, "busy", err.Error())
			return
		}
		defer h.unsubscribe(ch)
		sse, err := httpserver.StartSSE(w)
		if err != nil {
			return
		}
		if sse.Event("hello", map[string]any{"types": types}) != nil {
			return
		}
		end := time.After(MaxConnection)
		beat := time.NewTicker(Heartbeat)
		defer beat.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-end:
				_ = sse.Event("reconnect", map[string]any{})
				return
			case <-beat.C:
				if sse.Comment("keep-alive") != nil {
					return
				}
			case e := <-ch:
				if sse.Event("change", e) != nil {
					return
				}
			}
		}
	})
}
