// Package network manages reverse proxy routes and the Kernhaven sign-in gate
// (M12, ADR-0025). Caddy's configuration is built and loaded by the proxy
// service; the Core stores routes, authorizes, audits and runs the gate.
// A route is written to the database only after Caddy has accepted the
// configuration that contains it (AT-F11-03).
package network

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
)

// Errors of the route service.
var (
	ErrNotFound    = errors.New("route not found")
	ErrExists      = errors.New("a route for this host and path prefix exists")
	ErrUnavailable = errors.New("the reverse proxy is not configured")
)

// ValidationError is invalid route input.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Route is a stored route.
type Route struct {
	ID           int64      `json:"id"`
	Host         string     `json:"host"`
	PathPrefix   string     `json:"path_prefix"`
	StripPrefix  bool       `json:"strip_prefix"`
	UpstreamPort int        `json:"upstream_port"`
	App          string     `json:"app,omitempty"`
	SSO          bool       `json:"sso"`
	SSOMinRole   authz.Role `json:"sso_min_role"`
	LANOnly      bool       `json:"lan_only"`
	AllowCIDRs   []string   `json:"allow_cidrs"`
	URL          string     `json:"url"`
	CreatedBy    string     `json:"created_by"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

// RouteInput creates or replaces a route.
type RouteInput struct {
	Host         string   `json:"host"`
	PathPrefix   string   `json:"path_prefix"`
	StripPrefix  bool     `json:"strip_prefix"`
	UpstreamPort int      `json:"upstream_port"`
	SSO          bool     `json:"sso"`
	SSOMinRole   string   `json:"sso_min_role"`
	LANOnly      bool     `json:"lan_only"`
	AllowCIDRs   []string `json:"allow_cidrs"`
}

// AppRoute is the web address requested when installing an app (AT-F05-01).
type AppRoute struct {
	Host       string `json:"host"`
	PathPrefix string `json:"path_prefix"`
	LANOnly    bool   `json:"lan_only"`
	SSO        bool   `json:"sso"`
}

// Actor performs a change.
type Actor struct {
	ID        int64
	Name      string
	RequestID string
	IP        string
}

// State is the proxy state shown with the routes.
type State struct {
	Configured bool      `json:"configured"`
	Reachable  bool      `json:"reachable"`
	InSync     bool      `json:"in_sync"`
	AppliedAt  time.Time `json:"applied_at,omitzero"`
	Error      string    `json:"error,omitempty"`
	ErrorAt    time.Time `json:"error_at,omitzero"`
	HTTPSPort  int       `json:"https_port"`
}

// Service implements routes, the gate and the overview.
type Service struct {
	db       *sql.DB
	client   *agentclient.Client // proxy service; nil when not configured
	audit    *audit.Log
	ids      *identity.Service
	origin   string
	khHost   string
	corePort int
	now      func() time.Time
	log      *slog.Logger
	mu       sync.Mutex // serializes changes, so the route set sent to Caddy is the one committed
}

// New returns the service. origin is the Core's public origin, listen its
// loopback address.
func New(db *sql.DB, client *agentclient.Client, auditLog *audit.Log, ids *identity.Service, origin, listen string, log *slog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	u, _ := url.Parse(origin)
	_, p, _ := net.SplitHostPort(listen)
	port, _ := strconv.Atoi(p)
	return &Service{db: db, client: client, audit: auditLog, ids: ids, origin: strings.TrimRight(origin, "/"), khHost: strings.ToLower(u.Hostname()),
		corePort: port, now: now, log: log}
}

// Configured reports whether a proxy service is configured.
func (s *Service) Configured() bool { return s.client != nil }

const routeColumns = `id, host, path_prefix, strip_prefix, upstream_port, COALESCE(app, ''), sso, sso_min_role, lan_only, allow_cidrs, created_by, created_ms, updated_ms`

type rowScanner interface{ Scan(...any) error }

func scanRoute(row rowScanner) (Route, error) {
	var r Route
	var cidrs string
	var created, updated int64
	err := row.Scan(&r.ID, &r.Host, &r.PathPrefix, &r.StripPrefix, &r.UpstreamPort, &r.App, &r.SSO, &r.SSOMinRole, &r.LANOnly, &cidrs, &r.CreatedBy, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	r.AllowCIDRs = []string{}
	_ = json.Unmarshal([]byte(cidrs), &r.AllowCIDRs)
	r.CreatedAt, r.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	return r, nil
}

type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

func (s *Service) list(ctx context.Context, q querier) ([]Route, error) {
	rows, err := q.QueryContext(ctx, `SELECT `+routeColumns+` FROM proxy_routes ORDER BY host, path_prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Route{}
	for rows.Next() {
		r, err := scanRoute(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// List returns all routes with their URLs.
func (s *Service) List(ctx context.Context) ([]Route, error) {
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return nil, err
	}
	port := s.httpsPort(ctx)
	for i := range routes {
		routes[i].URL = routeURL(routes[i], port)
	}
	return routes, nil
}

// Get returns one route.
func (s *Service) Get(ctx context.Context, id int64) (Route, error) {
	r, err := scanRoute(s.db.QueryRowContext(ctx, `SELECT `+routeColumns+` FROM proxy_routes WHERE id = ?`, id))
	if err == nil {
		r.URL = routeURL(r, s.httpsPort(ctx))
	}
	return r, err
}

func (s *Service) httpsPort(ctx context.Context) int {
	port := 443
	_ = s.db.QueryRowContext(ctx, `SELECT https_port FROM proxy_state WHERE id = 1`).Scan(&port)
	return port
}

func routeURL(r Route, port int) string {
	host := r.Host
	if port != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return "https://" + host + r.PathPrefix + "/"
}

// normalize validates input and returns the route it describes.
func (s *Service) normalize(in RouteInput) (Route, error) {
	r := Route{
		Host: strings.ToLower(strings.TrimSpace(in.Host)), PathPrefix: strings.TrimSpace(in.PathPrefix), StripPrefix: in.StripPrefix,
		UpstreamPort: in.UpstreamPort, SSO: in.SSO, SSOMinRole: authz.Role(in.SSOMinRole), LANOnly: in.LANOnly, AllowCIDRs: []string{},
	}
	if r.SSOMinRole == "" {
		r.SSOMinRole = authz.Viewer
	}
	if !r.SSOMinRole.Valid() {
		return r, &ValidationError{fmt.Sprintf("sso_min_role %q is not a role", in.SSOMinRole)}
	}
	seen := map[string]bool{}
	for _, c := range in.AllowCIDRs {
		if strings.TrimSpace(c) == "" {
			continue
		}
		n, err := proxy.NormalizeCIDR(c)
		if err != nil {
			return r, &ValidationError{err.Error()}
		}
		if !seen[n] {
			seen[n] = true
			r.AllowCIDRs = append(r.AllowCIDRs, n)
		}
	}
	if err := proxy.ValidateRoute(toProto(Route{ID: 1, Host: r.Host, PathPrefix: r.PathPrefix, StripPrefix: r.StripPrefix, UpstreamPort: r.UpstreamPort, AllowCIDRs: r.AllowCIDRs})); err != nil {
		return r, &ValidationError{err.Error()}
	}
	if r.Host == s.khHost {
		return r, &ValidationError{fmt.Sprintf("%s is Kernhaven's own host; use another host name for apps", r.Host)}
	}
	if r.UpstreamPort == s.corePort {
		return r, &ValidationError{fmt.Sprintf("port %d is Kernhaven's own port", r.UpstreamPort)}
	}
	return r, nil
}

func toProto(r Route) agentproto.ProxyRoute {
	return agentproto.ProxyRoute{ID: r.ID, Host: r.Host, PathPrefix: r.PathPrefix, StripPrefix: r.StripPrefix, UpstreamPort: r.UpstreamPort,
		SSO: r.SSO, LANOnly: r.LANOnly, AllowCIDRs: r.AllowCIDRs}
}

func conflict(routes []Route, r Route) bool {
	for _, x := range routes {
		if x.ID != r.ID && x.Host == r.Host && x.PathPrefix == r.PathPrefix {
			return true
		}
	}
	return false
}

// push sends the complete route set to the proxy service.
func (s *Service) push(ctx context.Context, a Actor, routes []Route) (agentproto.ProxyApplied, error) {
	if s.client == nil {
		return agentproto.ProxyApplied{}, ErrUnavailable
	}
	in := agentproto.ProxyApply{KernhavenHost: s.khHost, Routes: make([]agentproto.ProxyRoute, len(routes))}
	for i, r := range routes {
		in.Routes[i] = toProto(r)
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var res agentproto.ProxyApplied
	err := s.client.Do(ctx, agentclient.Call{Op: agentproto.OpProxyApply, Params: in, Actor: a.Name, RequestID: a.RequestID}, &res)
	if err != nil {
		_, _ = s.db.ExecContext(context.WithoutCancel(ctx), `UPDATE proxy_state SET error = ?, error_ms = ? WHERE id = 1`, truncate(Message(err), 1000), s.now().UnixMilli())
	}
	return res, err
}

// applied records a successful apply inside the transaction of the change.
func (s *Service) applied(ctx context.Context, tx *sql.Tx, res agentproto.ProxyApplied) error {
	_, err := tx.ExecContext(ctx, `UPDATE proxy_state SET hash = ?, kh_host = ?, applied_ms = ?, https_port = ?, error = '', error_ms = 0 WHERE id = 1`,
		res.Hash, s.khHost, s.now().UnixMilli(), res.HTTPSPort)
	return err
}

func (s *Service) withTx(ctx context.Context, f func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := f(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func (s *Service) event(a Actor, action, target string, err error, kv ...string) audit.Event {
	ev := audit.Event{ActorID: a.ID, Actor: a.Name, Action: action, Target: target, RequestID: a.RequestID, IP: a.IP, Result: audit.Success, Details: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			ev.Details[kv[i]] = kv[i+1]
		}
	}
	if err != nil {
		ev.Result, ev.Details["error"] = audit.Failure, truncate(err.Error(), 500)
	}
	return ev
}

func routeDetails(r Route) []string {
	return []string{"host", r.Host, "path_prefix", r.PathPrefix, "upstream_port", strconv.Itoa(r.UpstreamPort), "app", r.App,
		"sso", strconv.FormatBool(r.SSO), "sso_min_role", string(r.SSOMinRole), "lan_only", strconv.FormatBool(r.LANOnly),
		"allow_cidrs", strings.Join(r.AllowCIDRs, ",")}
}

// change applies next to Caddy and, only if Caddy accepted it, runs write and
// the audit entry in one transaction. Failures are audited too.
func (s *Service) change(ctx context.Context, a Actor, action string, r Route, next []Route, write func(tx *sql.Tx) error) error {
	res, err := s.push(ctx, a, next)
	if err != nil {
		_ = s.audit.Record(context.WithoutCancel(ctx), s.event(a, action, "route:"+strconv.FormatInt(r.ID, 10), err, routeDetails(r)...))
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if err := write(tx); err != nil {
			return err
		}
		if err := s.applied(ctx, tx, res); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), s.event(a, action, "route:"+strconv.FormatInt(r.ID, 10), nil, routeDetails(r)...))
		return err
	})
}

func (s *Service) nextID(ctx context.Context) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx, `UPDATE proxy_state SET next_id = next_id + 1 WHERE id = 1 RETURNING next_id - 1`).Scan(&id)
	return id, err
}

// Create adds a route.
func (s *Service) Create(ctx context.Context, a Actor, in RouteInput) (Route, error) {
	r, err := s.normalize(in)
	if err != nil {
		return Route{}, err
	}
	return s.create(ctx, a, r)
}

func (s *Service) create(ctx context.Context, a Actor, r Route) (Route, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return Route{}, err
	}
	if conflict(routes, r) {
		return Route{}, ErrExists
	}
	if r.ID, err = s.nextID(ctx); err != nil {
		return Route{}, err
	}
	now := s.now().UnixMilli()
	cidrs, _ := json.Marshal(r.AllowCIDRs)
	err = s.change(ctx, a, "network.route_create", r, append(routes, r), func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO proxy_routes (id, host, path_prefix, strip_prefix, upstream_port, app, sso, sso_min_role, lan_only, allow_cidrs, created_by, created_ms, updated_ms)
			VALUES (?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)`,
			r.ID, r.Host, r.PathPrefix, r.StripPrefix, r.UpstreamPort, r.App, r.SSO, r.SSOMinRole, r.LANOnly, string(cidrs), a.Name, now, now)
		return err
	})
	if err != nil {
		return Route{}, err
	}
	return s.Get(ctx, r.ID)
}

// Update replaces a route's settings; its app link stays.
func (s *Service) Update(ctx context.Context, a Actor, id int64, in RouteInput) (Route, error) {
	r, err := s.normalize(in)
	if err != nil {
		return Route{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return Route{}, err
	}
	idx := -1
	for i, x := range routes {
		if x.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return Route{}, ErrNotFound
	}
	r.ID, r.App = id, routes[idx].App
	if conflict(routes, r) {
		return Route{}, ErrExists
	}
	routes[idx] = r
	cidrs, _ := json.Marshal(r.AllowCIDRs)
	err = s.change(ctx, a, "network.route_update", r, routes, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE proxy_routes SET host = ?, path_prefix = ?, strip_prefix = ?, upstream_port = ?, sso = ?, sso_min_role = ?,
			lan_only = ?, allow_cidrs = ?, updated_ms = ? WHERE id = ?`,
			r.Host, r.PathPrefix, r.StripPrefix, r.UpstreamPort, r.SSO, r.SSOMinRole, r.LANOnly, string(cidrs), s.now().UnixMilli(), id)
		return err
	})
	if err != nil {
		return Route{}, err
	}
	return s.Get(ctx, id)
}

// remove deletes the routes for which drop is true, Caddy first.
func (s *Service) remove(ctx context.Context, a Actor, drop func(Route) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return err
	}
	var next, gone []Route
	for _, r := range routes {
		if drop(r) {
			gone = append(gone, r)
		} else {
			next = append(next, r)
		}
	}
	if len(gone) == 0 {
		return ErrNotFound
	}
	if next == nil {
		next = []Route{}
	}
	res, err := s.push(ctx, a, next)
	if err != nil {
		for _, r := range gone {
			_ = s.audit.Record(context.WithoutCancel(ctx), s.event(a, "network.route_delete", "route:"+strconv.FormatInt(r.ID, 10), err, routeDetails(r)...))
		}
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		for _, r := range gone {
			if _, err := tx.ExecContext(ctx, `DELETE FROM proxy_routes WHERE id = ?`, r.ID); err != nil {
				return err
			}
			if _, err := audit.Append(ctx, tx, s.now(), s.event(a, "network.route_delete", "route:"+strconv.FormatInt(r.ID, 10), nil, routeDetails(r)...)); err != nil {
				return err
			}
		}
		return s.applied(ctx, tx, res)
	})
}

// Delete removes a route.
func (s *Service) Delete(ctx context.Context, a Actor, id int64) error {
	return s.remove(ctx, a, func(r Route) bool { return r.ID == id })
}

// Apply loads the stored routes again (after a lost or foreign configuration).
func (s *Service) Apply(ctx context.Context, a Actor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return err
	}
	res, err := s.push(ctx, a, routes)
	_ = s.audit.Record(context.WithoutCancel(ctx), s.event(a, "network.apply", "proxy", err, "routes", strconv.Itoa(len(routes))))
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error { return s.applied(ctx, tx, res) })
}

// Reconcile re-applies the stored routes when Caddy runs a configuration
// other than the last applied one, or one built for another Kernhaven host.
func (s *Service) Reconcile(ctx context.Context) (bool, error) {
	if s.client == nil {
		return false, nil
	}
	st, err := s.status(ctx)
	if err != nil {
		return false, err
	}
	if !st.Reachable {
		return false, errors.New("caddy is not reachable")
	}
	var hash, host string
	if err := s.db.QueryRowContext(ctx, `SELECT hash, kh_host FROM proxy_state WHERE id = 1`).Scan(&hash, &host); err != nil {
		return false, err
	}
	if st.Hash == hash && hash != "" && host == s.khHost {
		return false, nil
	}
	return true, s.Apply(ctx, Actor{Name: "system", RequestID: "reconcile"})
}

func (s *Service) status(ctx context.Context) (agentproto.ProxyStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var st agentproto.ProxyStatus
	err := s.client.Do(ctx, agentclient.Call{Op: agentproto.OpProxyStatus, Actor: "system", RequestID: "status"}, &st)
	return st, err
}

// State returns the proxy state; reachability is checked live.
func (s *Service) State(ctx context.Context) State {
	st := State{Configured: s.client != nil, HTTPSPort: 443}
	var hash string
	var applied, errMS int64
	_ = s.db.QueryRowContext(ctx, `SELECT hash, applied_ms, https_port, error, error_ms FROM proxy_state WHERE id = 1`).Scan(&hash, &applied, &st.HTTPSPort, &st.Error, &errMS)
	if applied > 0 {
		st.AppliedAt = time.UnixMilli(applied).UTC()
	}
	if errMS > 0 {
		st.ErrorAt = time.UnixMilli(errMS).UTC()
	}
	if s.client != nil {
		if live, err := s.status(ctx); err == nil {
			st.Reachable, st.InSync = live.Reachable, live.Reachable && hash != "" && live.Hash == hash
		}
	}
	return st
}

// Overview returns the host's interfaces and listening sockets.
func (s *Service) Overview(ctx context.Context, a Actor) (agentproto.NetworkOverview, error) {
	if s.client == nil {
		return agentproto.NetworkOverview{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var ov agentproto.NetworkOverview
	err := s.client.Do(ctx, agentclient.Call{Op: agentproto.OpNetworkOverview, Actor: a.Name, RequestID: a.RequestID}, &ov)
	return ov, err
}

// ---- apps (AT-F05-01) ----

// CheckAppRoute validates an app's web address before the app is installed.
func (s *Service) CheckAppRoute(in AppRoute) error {
	if s.client == nil {
		return ErrUnavailable
	}
	_, err := s.normalize(RouteInput{Host: in.Host, PathPrefix: in.PathPrefix, UpstreamPort: proxy.MaxUpstreamPort})
	return err
}

// CreateAppRoute publishes an installed app's web port.
func (s *Service) CreateAppRoute(ctx context.Context, a Actor, app string, port int, in AppRoute) (Route, error) {
	r, err := s.normalize(RouteInput{Host: in.Host, PathPrefix: in.PathPrefix, StripPrefix: in.PathPrefix != "", UpstreamPort: port, SSO: in.SSO, LANOnly: in.LANOnly})
	if err != nil {
		return Route{}, err
	}
	r.App = app
	return s.create(ctx, a, r)
}

// RemoveAppRoutes removes the routes of a removed app.
func (s *Service) RemoveAppRoutes(ctx context.Context, a Actor, app string) error {
	err := s.remove(ctx, a, func(r Route) bool { return r.App == app })
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// MoveAppRoutes points an app's routes to its new web port.
func (s *Service) MoveAppRoutes(ctx context.Context, a Actor, app string, port int) error {
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if r.App != app || r.UpstreamPort == port {
			continue
		}
		in := RouteInput{Host: r.Host, PathPrefix: r.PathPrefix, StripPrefix: r.StripPrefix, UpstreamPort: port, SSO: r.SSO,
			SSOMinRole: string(r.SSOMinRole), LANOnly: r.LANOnly, AllowCIDRs: r.AllowCIDRs}
		if _, err := s.Update(ctx, a, r.ID, in); err != nil {
			return err
		}
	}
	return nil
}

// AppURLs maps app names to the URL of their first route.
func (s *Service) AppURLs(ctx context.Context) map[string]string {
	out := map[string]string{}
	routes, err := s.List(ctx)
	if err != nil {
		return out
	}
	for _, r := range routes {
		if r.App != "" && out[r.App] == "" {
			out[r.App] = r.URL
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
