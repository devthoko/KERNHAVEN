// Package security assembles the security dashboard (M17, AT-F10-04): MFA
// coverage, exposed apps, policy exceptions, outdated apps and images,
// failed sign-ins, certificate expiry, audit chain and backup state. It only
// reads; each section links to the page where the finding is fixed.
package security

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/apps"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/certs"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// Thresholds of the findings.
const (
	FailedLoginWarn = 10                   // failed sign-ins in 24 hours
	CertWarn        = 14 * 24 * time.Hour  // certificate expiry
	ImageAge        = 180 * 24 * time.Hour // images of running containers
	BackupAge       = 7 * 24 * time.Hour   // last successful backup
)

// Sources are the modules the dashboard reads.
type Sources struct {
	DB           *sql.DB
	Audit        *audit.Log
	Apps         func(context.Context) ([]apps.App, error)
	Certificates func(context.Context) ([]certs.Certificate, error)
	Agent        *agentclient.Client // nil without a Docker agent
}

// Service builds the overview.
type Service struct {
	src Sources
	now func() time.Time
}

// New returns the service.
func New(src Sources, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{src: src, now: now}
}

// Finding is one thing to look at.
type Finding struct {
	Severity string `json:"severity"` // critical, warning, info
	Area     string `json:"area"`
	Title    string `json:"title"`
	Link     string `json:"link"`
}

// UserMFA is a user's second factor.
type UserMFA struct {
	Username string `json:"username"`
	Role     string `json:"role"`
	Passkeys int    `json:"passkeys"`
	TOTP     bool   `json:"totp"`
	Required bool   `json:"required"`
}

// Route is a published route and how it is protected.
type Route struct {
	Host        string `json:"host"`
	Path        string `json:"path"`
	App         string `json:"app,omitempty"`
	SignIn      bool   `json:"sign_in"`
	LANOnly     bool   `json:"lan_only"`
	AllowList   bool   `json:"allow_list"`
	Unprotected bool   `json:"unprotected"`
}

// Exception is an approved policy exception of a deployed revision.
type Exception struct {
	Stack      string `json:"stack"`
	Revision   int    `json:"revision"`
	Service    string `json:"service"`
	Rule       string `json:"rule"`
	Reason     string `json:"reason"`
	ApprovedBy string `json:"approved_by"`
}

// Image is an image used by a running container.
type Image struct {
	Image      string    `json:"image"`
	Created    time.Time `json:"created"`
	Containers int       `json:"containers"`
}

// Overview is the dashboard.
type Overview struct {
	GeneratedAt time.Time `json:"generated_at"`
	Findings    []Finding `json:"findings"`
	MFA         struct {
		Users    int             `json:"users"`
		Covered  int             `json:"covered"`
		Policy   map[string]bool `json:"policy"`
		Accounts []UserMFA       `json:"accounts"`
	} `json:"mfa"`
	Routes     []Route     `json:"routes"`
	Exceptions []Exception `json:"exceptions"`
	Updates    []apps.App  `json:"updates"`
	OldImages  []Image     `json:"old_images"`
	// ImagesChecked is false when the Docker agent could not be asked.
	ImagesChecked bool `json:"images_checked"`
	Logins        struct {
		Failed24h   int            `json:"failed_24h"`
		Lockouts24h int            `json:"lockouts_24h"`
		BySource    map[string]int `json:"by_source"`
		Recent      []audit.Record `json:"recent"`
	} `json:"logins"`
	Certificates []certs.Certificate `json:"certificates"`
	Audit        audit.VerifyResult  `json:"audit"`
	Backup       struct {
		Plans         int        `json:"plans"`
		LastSucceeded *time.Time `json:"last_succeeded,omitempty"`
	} `json:"backup"`
}

func (o *Overview) add(sev, area, link, format string, a ...any) {
	o.Findings = append(o.Findings, Finding{Severity: sev, Area: area, Title: fmt.Sprintf(format, a...), Link: link})
}

// Build computes the overview now.
func (s *Service) Build(ctx context.Context) (Overview, error) {
	var o Overview
	now := s.now()
	o.GeneratedAt = now
	steps := []func(context.Context, *Overview, time.Time) error{s.mfa, s.routes, s.exceptions, s.outdated, s.logins, s.certificates, s.auditChain, s.backups}
	for _, f := range steps {
		if err := f(ctx, &o, now); err != nil {
			return o, err
		}
	}
	rank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.SliceStable(o.Findings, func(i, j int) bool { return rank[o.Findings[i].Severity] < rank[o.Findings[j].Severity] })
	if o.Findings == nil {
		o.Findings = []Finding{}
	}
	return o, nil
}

func (s *Service) mfa(ctx context.Context, o *Overview, _ time.Time) error {
	o.MFA.Policy = map[string]bool{"owner": false, "admin": false, "operator": false, "viewer": false}
	rows, err := s.src.DB.QueryContext(ctx, `SELECT role, required FROM mfa_policy`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var role string
		var req bool
		if err := rows.Scan(&role, &req); err != nil {
			rows.Close()
			return err
		}
		o.MFA.Policy[role] = req
	}
	rows.Close()
	rows, err = s.src.DB.QueryContext(ctx, `SELECT u.username, u.role,
		(SELECT count(*) FROM user_passkeys p WHERE p.user_id = u.id),
		EXISTS (SELECT 1 FROM user_totp t WHERE t.user_id = u.id AND t.confirmed = 1)
		FROM users u WHERE u.disabled = 0 ORDER BY u.username`)
	if err != nil {
		return err
	}
	defer rows.Close()
	o.MFA.Accounts = []UserMFA{}
	for rows.Next() {
		var u UserMFA
		if err := rows.Scan(&u.Username, &u.Role, &u.Passkeys, &u.TOTP); err != nil {
			return err
		}
		u.Required = o.MFA.Policy[u.Role]
		o.MFA.Users++
		if u.Passkeys > 0 || u.TOTP {
			o.MFA.Covered++
		} else if u.Role == "owner" || u.Role == "admin" {
			o.add("critical", "mfa", "/users", "%s (%s) signs in with a password only", u.Username, u.Role)
		} else if u.Required {
			o.add("warning", "mfa", "/users", "%s (%s) has no second factor although the policy requires one", u.Username, u.Role)
		}
		o.MFA.Accounts = append(o.MFA.Accounts, u)
	}
	for _, role := range []string{"owner", "admin"} {
		if !o.MFA.Policy[role] {
			o.add("warning", "mfa", "/account", "A second factor is not required for the %s role", role)
		}
	}
	return rows.Err()
}

func (s *Service) routes(ctx context.Context, o *Overview, _ time.Time) error {
	rows, err := s.src.DB.QueryContext(ctx, `SELECT host, path_prefix, coalesce(app, ''), sso, lan_only, allow_cidrs FROM proxy_routes ORDER BY host, path_prefix`)
	if err != nil {
		return err
	}
	defer rows.Close()
	o.Routes = []Route{}
	for rows.Next() {
		var r Route
		var cidrs string
		if err := rows.Scan(&r.Host, &r.Path, &r.App, &r.SignIn, &r.LANOnly, &cidrs); err != nil {
			return err
		}
		var list []string
		_ = json.Unmarshal([]byte(cidrs), &list)
		r.AllowList = len(list) > 0
		r.Unprotected = !r.SignIn && !r.LANOnly && !r.AllowList
		if r.Unprotected {
			o.add("warning", "exposure", "/proxy", "%s%s is reachable from anywhere without Kernhaven sign-in", r.Host, r.Path)
		}
		o.Routes = append(o.Routes, r)
	}
	return rows.Err()
}

func (s *Service) exceptions(ctx context.Context, o *Overview, _ time.Time) error {
	rows, err := s.src.DB.QueryContext(ctx, `SELECT s.name, r.number, r.exceptions FROM stacks s JOIN stack_revisions r ON r.stack_id = s.id AND r.number = s.deployed_revision
		WHERE s.deployed_revision > 0 ORDER BY s.name`)
	if err != nil {
		return err
	}
	defer rows.Close()
	o.Exceptions = []Exception{}
	for rows.Next() {
		var stack, raw string
		var rev int
		if err := rows.Scan(&stack, &rev, &raw); err != nil {
			return err
		}
		var list []struct {
			Service    string `json:"service"`
			Rule       string `json:"rule"`
			Reason     string `json:"reason"`
			ApprovedBy string `json:"approved_by"`
		}
		_ = json.Unmarshal([]byte(raw), &list)
		for _, e := range list {
			o.Exceptions = append(o.Exceptions, Exception{Stack: stack, Revision: rev, Service: e.Service, Rule: e.Rule, Reason: e.Reason, ApprovedBy: e.ApprovedBy})
			sev := "info"
			switch e.Rule {
			case policy.RulePrivileged, policy.RuleDockerSocket, policy.RuleHostNetwork, policy.RuleHostPID, policy.RuleDevice, policy.RuleSensitivePath:
				sev = "warning" // close to host access
			}
			o.add(sev, "policy", "/stacks/"+stack, "%s/%s runs with an exception to %q: %s", stack, e.Service, e.Rule, e.Reason)
		}
	}
	return rows.Err()
}

func (s *Service) outdated(ctx context.Context, o *Overview, now time.Time) error {
	o.Updates, o.OldImages = []apps.App{}, []Image{}
	if s.src.Apps != nil {
		list, err := s.src.Apps(ctx)
		if err != nil {
			return err
		}
		for _, a := range list {
			if a.UpdateAvailable {
				o.Updates = append(o.Updates, a)
				o.add("warning", "updates", "/apps/"+a.Name, "%s runs %s; %s is available", a.Name, a.Version, a.LatestVersion)
			}
		}
	}
	if s.src.Agent == nil {
		return nil
	}
	call := func(op string, params, out any) error {
		return s.src.Agent.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: "security-dashboard", RequestID: httpserver.RequestID(ctx)}, out)
	}
	var images []agentproto.ImageSummary
	var containers []agentproto.ContainerSummary
	if call(agentproto.OpImagesList, nil, &images) != nil || call(agentproto.OpContainersList, agentproto.ContainersList{All: false}, &containers) != nil {
		return nil // the dashboard shows that images were not checked
	}
	o.ImagesChecked = true
	running := map[string]int{}
	for _, c := range containers {
		running[c.Image]++
	}
	for _, im := range images {
		n := 0
		for _, ref := range append(append([]string{im.ID}, im.RepoTags...), im.RepoDigests...) {
			n += running[ref]
		}
		created := time.Unix(im.Created, 0)
		if n == 0 || now.Sub(created) < ImageAge {
			continue
		}
		name := im.ID
		if len(im.RepoTags) > 0 {
			name = im.RepoTags[0]
		}
		o.OldImages = append(o.OldImages, Image{Image: name, Created: created, Containers: n})
		o.add("info", "updates", "/images", "%s is %d days old and used by %d running containers", name, int(now.Sub(created).Hours()/24), n)
	}
	return nil
}

func (s *Service) logins(ctx context.Context, o *Overview, now time.Time) error {
	since := now.Add(-24 * time.Hour).UnixMilli()
	db := s.src.DB
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = 'auth.login' AND result = 'failure' AND ts_ms >= ?`, since).Scan(&o.Logins.Failed24h); err != nil {
		return err
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = 'auth.lockout' AND ts_ms >= ?`, since).Scan(&o.Logins.Lockouts24h); err != nil {
		return err
	}
	o.Logins.BySource = map[string]int{}
	rows, err := db.QueryContext(ctx, `SELECT ip, count(*) FROM audit_events WHERE action = 'auth.login' AND result = 'failure' AND ts_ms >= ? GROUP BY ip ORDER BY count(*) DESC LIMIT 5`, since)
	if err != nil {
		return err
	}
	for rows.Next() {
		var ip string
		var n int
		if err := rows.Scan(&ip, &n); err != nil {
			rows.Close()
			return err
		}
		o.Logins.BySource[ip] = n
	}
	rows.Close()
	recent, err := s.src.Audit.List(ctx, audit.Filter{Action: "auth.login", Result: audit.Failure, Limit: 10})
	if err != nil {
		return err
	}
	o.Logins.Recent = recent
	if o.Logins.Failed24h >= FailedLoginWarn {
		o.add("warning", "sign-in", "/audit", "%d failed sign-ins in the last 24 hours", o.Logins.Failed24h)
	}
	if o.Logins.Lockouts24h > 0 {
		o.add("warning", "sign-in", "/audit", "%d accounts were locked in the last 24 hours", o.Logins.Lockouts24h)
	}
	return nil
}

func (s *Service) certificates(ctx context.Context, o *Overview, now time.Time) error {
	o.Certificates = []certs.Certificate{}
	if s.src.Certificates == nil {
		return nil
	}
	list, err := s.src.Certificates(ctx)
	if err != nil {
		return err
	}
	for _, c := range list {
		o.Certificates = append(o.Certificates, c)
		if len(c.Hosts) == 0 {
			continue
		}
		left := c.NotAfter.Sub(now)
		switch {
		case left <= 0:
			o.add("critical", "certificates", "/certificates", "The certificate for %s has expired", strings.Join(c.Names, ", "))
		case left < CertWarn:
			o.add("warning", "certificates", "/certificates", "The certificate for %s expires in %d days", strings.Join(c.Names, ", "), int(left.Hours()/24))
		}
	}
	return nil
}

func (s *Service) auditChain(ctx context.Context, o *Overview, _ time.Time) error {
	res, err := s.src.Audit.Verify(ctx)
	if err != nil {
		return err
	}
	o.Audit = res
	if !res.OK {
		o.add("critical", "audit", "/audit", "The audit log fails verification at record %d: %s", res.BrokenAt, res.Reason)
	}
	return nil
}

func (s *Service) backups(ctx context.Context, o *Overview, now time.Time) error {
	if err := s.src.DB.QueryRowContext(ctx, `SELECT count(*) FROM backup_plans WHERE enabled = 1`).Scan(&o.Backup.Plans); err != nil {
		return err
	}
	var last sql.NullInt64
	if err := s.src.DB.QueryRowContext(ctx, `SELECT max(finished_ms) FROM jobs WHERE kind = 'backup.run' AND state = 'succeeded'`).Scan(&last); err != nil {
		return err
	}
	if last.Valid {
		t := time.UnixMilli(last.Int64)
		o.Backup.LastSucceeded = &t
	}
	switch {
	case o.Backup.Plans == 0:
		o.add("warning", "backup", "/backups", "No backup plan is enabled")
	case o.Backup.LastSucceeded == nil || now.Sub(*o.Backup.LastSucceeded) > BackupAge:
		o.add("warning", "backup", "/backups", "No backup succeeded in the last 7 days")
	}
	return nil
}

// Register adds the dashboard route.
func (s *Service) Register(rt *httpserver.Router) {
	rt.HandleFunc("GET /api/v1/security/overview", httpserver.RequirePermission(string(authz.SecurityRead)), func(w http.ResponseWriter, r *http.Request) {
		o, err := s.Build(r.Context())
		if err != nil {
			httpserver.InternalError(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, o)
	})
}
