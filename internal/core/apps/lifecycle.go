package apps

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/catalog"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
)

// Lifecycle errors.
var (
	ErrApproval = errors.New("this app needs policy exceptions; an owner must approve them explicitly")
	ErrUpToDate = errors.New("the app already runs the catalog's version")
	ErrExpired  = errors.New("the source's catalog has expired; sync the source first")
)

// App is an installed app.
type App struct {
	Name            string `json:"name"`
	AppID           string `json:"app_id"`
	AppName         string `json:"app_name"`
	SourceID        *int64 `json:"source_id"`
	SourceName      string `json:"source_name"`
	Version         string `json:"version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	Status          string `json:"status"`
	StatusMessage   string `json:"status_message"`
	Revision        int    `json:"deployed_revision"`
	WebPort         int    `json:"web_port"`
	// URL is the app's address through the reverse proxy (M12), if it has a route.
	URL       string    `json:"url,omitempty"`
	CreatedAt time.Time `json:"created_at"`

	stackID   int64
	latestRev int
	entry     catalog.App
}

const appQuery = `SELECT st.id, st.name, a.app_id, a.app_name, a.source_id, a.source_name, st.status, st.status_message,
	st.deployed_revision, st.latest_revision, a.created_ms,
	COALESCE((SELECT version FROM app_versions v WHERE v.stack_id = st.id AND v.revision = st.deployed_revision), ''),
	COALESCE((SELECT version FROM app_versions v WHERE v.stack_id = st.id AND v.revision = st.latest_revision), ''),
	COALESCE((SELECT entry FROM app_versions v WHERE v.stack_id = st.id AND v.revision = st.latest_revision), '{}'),
	COALESCE((SELECT version FROM catalog_apps c WHERE c.source_id = a.source_id AND c.app_id = a.app_id), '')
	FROM apps a JOIN stacks st ON st.id = a.stack_id`

func (s *Service) scanApp(row rowScanner) (App, error) {
	var a App
	var src sql.NullInt64
	var created int64
	var latestRevVersion, entry string
	err := row.Scan(&a.stackID, &a.Name, &a.AppID, &a.AppName, &src, &a.SourceName, &a.Status, &a.StatusMessage,
		&a.Revision, &a.latestRev, &created, &a.Version, &latestRevVersion, &entry, &a.LatestVersion)
	if errors.Is(err, sql.ErrNoRows) {
		return a, ErrNotFound
	}
	if err != nil {
		return a, err
	}
	if src.Valid {
		a.SourceID = &src.Int64
	}
	a.CreatedAt = time.UnixMilli(created).UTC()
	_ = json.Unmarshal([]byte(entry), &a.entry)
	current := a.Version
	if current == "" {
		current = latestRevVersion // never deployed successfully
	}
	busy := a.Status == "deploying" || a.Status == "stopping"
	a.UpdateAvailable = a.LatestVersion != "" && a.LatestVersion != current && !busy
	return a, nil
}

func (s *Service) withWeb(ctx context.Context, a App) App {
	if w := a.entry.Web; w != nil {
		rev := a.Revision
		if rev == 0 {
			rev = a.latestRev
		}
		a.WebPort = s.stacks.PublishedPort(ctx, a.stackID, rev, w.Service, w.Port)
	}
	return a
}

func (s *Service) appURLs(ctx context.Context) map[string]string {
	if s.routes == nil {
		return map[string]string{}
	}
	return s.routes.AppURLs(ctx)
}

// latestWebPort is the web port of the newest revision (after an update).
func (s *Service) latestWebPort(ctx context.Context, a App) int {
	if w := a.entry.Web; w != nil {
		return s.stacks.PublishedPort(ctx, a.stackID, a.latestRev, w.Service, w.Port)
	}
	return 0
}

// List returns the installed apps.
func (s *Service) List(ctx context.Context) ([]App, error) {
	rows, err := s.db.QueryContext(ctx, appQuery+` ORDER BY st.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []App{}
	for rows.Next() {
		a, err := s.scanApp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	urls := s.appURLs(ctx)
	for i := range out {
		out[i] = s.withWeb(ctx, out[i])
		out[i].URL = urls[out[i].Name]
	}
	return out, nil
}

func (s *Service) app(ctx context.Context, q querier, name string) (App, error) {
	return s.scanApp(q.QueryRowContext(ctx, appQuery+` WHERE st.name = ?`, name))
}

// Version is one revision of an installed app.
type Version struct {
	Revision  int       `json:"revision"`
	Version   string    `json:"version"`
	Comment   string    `json:"comment"`
	Deployed  bool      `json:"deployed"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// ImageChange is an image that differs between two versions (TH-41).
type ImageChange struct {
	Service string `json:"service"`
	From    string `json:"from"`
	To      string `json:"to"`
}

// UpdatePreview describes the update the catalog offers.
type UpdatePreview struct {
	From          string              `json:"from"`
	To            string              `json:"to"`
	Images        []ImageChange       `json:"images"`
	NewFields     []catalog.Field     `json:"new_fields"`
	NewExceptions []catalog.Exception `json:"new_exceptions"`
	Disclosure    Disclosure          `json:"disclosure"`
}

// AppDetail is an installed app with history, configuration and update.
type AppDetail struct {
	App
	Versions []Version         `json:"versions"`
	Fields   []catalog.Field   `json:"fields"`
	Config   []stacks.Variable `json:"config"`
	Update   *UpdatePreview    `json:"update"`
	Homepage string            `json:"homepage"`
	Summary  string            `json:"summary"`
	Web      *catalog.Web      `json:"web"`
}

// Get returns an installed app.
func (s *Service) Get(ctx context.Context, name string) (AppDetail, error) {
	a, err := s.app(ctx, s.db, name)
	if err != nil {
		return AppDetail{}, err
	}
	a = s.withWeb(ctx, a)
	a.URL = s.appURLs(ctx)[a.Name]
	d := AppDetail{App: a, Versions: []Version{}, Fields: orFields(a.entry.Fields), Homepage: a.entry.Homepage, Summary: a.entry.Summary, Web: a.entry.Web}
	rows, err := s.db.QueryContext(ctx, `SELECT v.revision, v.version, r.comment, r.created_by_name, r.created_ms
		FROM app_versions v JOIN stack_revisions r ON r.stack_id = v.stack_id AND r.number = v.revision
		WHERE v.stack_id = ? ORDER BY v.revision DESC`, a.stackID)
	if err != nil {
		return d, err
	}
	defer rows.Close()
	for rows.Next() {
		var v Version
		var created int64
		if err := rows.Scan(&v.Revision, &v.Version, &v.Comment, &v.CreatedBy, &created); err != nil {
			return d, err
		}
		v.CreatedAt, v.Deployed = time.UnixMilli(created).UTC(), v.Revision == a.Revision
		d.Versions = append(d.Versions, v)
	}
	if err := rows.Err(); err != nil {
		return d, err
	}
	if d.Config, err = s.stacks.PublicVariables(ctx, a.stackID); err != nil {
		return d, err
	}
	if a.UpdateAvailable && a.SourceID != nil {
		if _, next, err := s.entry(ctx, s.db, *a.SourceID, a.AppID); err == nil {
			d.Update = s.preview(ctx, a, next, d.Config)
		}
	}
	return d, nil
}

func orFields(f []catalog.Field) []catalog.Field {
	if f == nil {
		return []catalog.Field{}
	}
	return f
}

// knownValues returns stored non-secret values plus placeholders for secrets,
// for rendering Compose files in previews.
func knownValues(app catalog.App, config []stacks.Variable) map[string]string {
	m := app.Placeholders()
	for _, v := range config {
		if !v.Secret {
			m[v.Name] = v.Value
		}
	}
	return m
}

func (s *Service) images(name string, app catalog.App, values map[string]string) map[string]string {
	out := map[string]string{}
	proj, err := s.stacks.Project(name, app.Compose, values)
	if err != nil {
		return out
	}
	for _, svc := range proj.Services {
		out[svc.Name] = svc.Spec.Image
	}
	return out
}

func (s *Service) preview(ctx context.Context, a App, next catalog.App, config []stacks.Variable) *UpdatePreview {
	p := &UpdatePreview{From: a.Version, To: next.Version, Images: []ImageChange{}, NewFields: []catalog.Field{}, NewExceptions: []catalog.Exception{}}
	if p.From == "" {
		p.From = a.entry.Version
	}
	values := knownValues(next, config)
	p.Disclosure = s.disclose(a.Name, next, values)
	before := s.images(a.Name, a.entry, knownValues(a.entry, config))
	after := s.images(a.Name, next, values)
	names := map[string]bool{}
	for k := range before {
		names[k] = true
	}
	for k := range after {
		names[k] = true
	}
	for svc := range names {
		if before[svc] != after[svc] {
			p.Images = append(p.Images, ImageChange{Service: svc, From: before[svc], To: after[svc]})
		}
	}
	sort.Slice(p.Images, func(i, j int) bool { return p.Images[i].Service < p.Images[j].Service })
	have := map[string]bool{}
	for _, v := range config {
		have[v.Name] = true
	}
	for _, f := range next.Fields {
		if !have[f.Name] {
			p.NewFields = append(p.NewFields, f)
		}
	}
	prev := s.currentExceptions(ctx, a)
	for _, e := range p.Disclosure.Exceptions() {
		if !prev[e.Service+"/"+e.Rule] {
			p.NewExceptions = append(p.NewExceptions, e)
		}
	}
	return p
}

func (s *Service) currentExceptions(ctx context.Context, a App) map[string]bool {
	m := map[string]bool{}
	if rev, err := s.stacks.GetRevision(ctx, s.db, a.stackID, a.latestRev); err == nil {
		for _, e := range rev.Exceptions {
			m[e.Service+"/"+e.Rule] = true
		}
	}
	return m
}

// generate creates a random value for a generated field.
func generate(kind string) (string, error) {
	switch kind {
	case catalog.GenerateHex32:
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	default:
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return base64.RawURLEncoding.EncodeToString(b), nil
	}
}

// resolve turns form values into stack variables. existing holds the app's
// stored variables (secret values blank) on update; stored secrets that are
// not re-entered are kept. values is what the Compose file is rendered with,
// with placeholders for kept secrets.
func resolve(fields []catalog.Field, given map[string]string, existing []stacks.Variable) ([]stacks.VariableInput, map[string]string, error) {
	known := map[string]bool{}
	for _, f := range fields {
		known[f.Name] = true
	}
	for k := range given {
		if !known[k] {
			return nil, nil, &ValidationError{fmt.Sprintf("unknown field %s", k)}
		}
	}
	old := map[string]stacks.Variable{}
	for _, v := range existing {
		old[v.Name] = v
	}
	vars := []stacks.VariableInput{}
	values := map[string]string{}
	var problems []string
	for _, f := range fields {
		v := given[f.Name]
		if v == "" {
			if ex, ok := old[f.Name]; ok {
				if ex.Secret {
					if !f.Secret() {
						problems = append(problems, f.Label+" must be entered again")
						continue
					}
					vars = append(vars, stacks.VariableInput{Name: f.Name, Secret: true})
					values[f.Name] = catalog.App{Fields: []catalog.Field{f}}.Placeholders()[f.Name]
					continue
				}
				v = ex.Value
			}
		}
		if v == "" {
			switch {
			case f.Default != "":
				v = f.Default
			case f.Generate != "":
				g, err := generate(f.Generate)
				if err != nil {
					return nil, nil, err
				}
				v = g
			case f.Type == catalog.TypeBoolean:
				v = "false"
			case f.Required:
				problems = append(problems, f.Label+" is required")
				continue
			}
		}
		emptyOK := v == "" && (f.Type == catalog.TypeText || f.Type == catalog.TypePassword)
		if !emptyOK {
			if err := f.Check(v); err != nil {
				problems = append(problems, f.Label+" "+err.Error())
				continue
			}
		}
		val := v
		vars = append(vars, stacks.VariableInput{Name: f.Name, Value: &val, Secret: f.Secret()})
		values[f.Name] = v
	}
	if len(problems) > 0 {
		return nil, nil, &ValidationError{strings.Join(problems, "; ")}
	}
	return vars, values, nil
}

func stackExceptions(exc []catalog.Exception) []stacks.Exception {
	out := []stacks.Exception{}
	for _, e := range exc {
		reason := "catalog: " + e.Reason
		if r := []rune(reason); len(r) > 500 {
			reason = string(r[:500])
		}
		out = append(out, stacks.Exception{Service: e.Service, Rule: e.Rule, Reason: reason})
	}
	return out
}

// InstallInput installs an app from the store.
type InstallInput struct {
	SourceID          int64             `json:"source_id"`
	AppID             string            `json:"app_id"`
	Name              string            `json:"name"`
	Values            map[string]string `json:"values"`
	ApproveExceptions bool              `json:"approve_exceptions"`
	// Route publishes the app's web port under a host name (M12, optional).
	Route *network.AppRoute `json:"route,omitempty"`
}

// Install creates the app's stack and queues its deployment (AT-F05-01).
func (s *Service) Install(ctx context.Context, a stacks.Actor, in InstallInput) (App, int64, error) {
	src, app, err := s.entry(ctx, s.db, in.SourceID, in.AppID)
	if err != nil {
		return App{}, 0, err
	}
	if src.expired(s.now()) {
		return App{}, 0, ErrExpired
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = app.ID
	}
	vars, values, err := resolve(app.Fields, in.Values, nil)
	if err != nil {
		return App{}, 0, err
	}
	d := s.disclose(name, app, values)
	if !d.Installable {
		return App{}, 0, &ValidationError{"this app cannot be installed on this host: " + strings.Join(d.Problems, "; ")}
	}
	exc := d.Exceptions()
	if len(exc) > 0 && (!a.CanApprove || !in.ApproveExceptions) {
		return App{}, 0, ErrApproval
	}
	entry, _ := json.Marshal(app)
	var out App
	var job int64
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		st, _, err := s.stacks.CreateManaged(ctx, tx, a, stacks.RevisionInput{Name: name, Compose: app.Compose,
			Comment: fmt.Sprintf("install %s %s", app.Name, app.Version), Variables: vars, Exceptions: stackExceptions(exc)})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO apps (stack_id, source_id, source_name, app_id, app_name, created_by, created_ms) VALUES (?, ?, ?, ?, ?, ?, ?)`,
			st.ID, src.ID, src.Name, app.ID, app.Name, a.ID, s.nowMS()); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_versions (stack_id, revision, version, entry) VALUES (?, 1, ?, ?)`, st.ID, app.Version, string(entry)); err != nil {
			return err
		}
		if job, err = s.stacks.DeployManaged(ctx, tx, a, st, 1, false); err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, s.now(), event(a, "app.install", "app:"+name, audit.Success,
			"app", app.ID, "version", app.Version, "source", src.Name, "exceptions", fmt.Sprint(len(exc)), "job", fmt.Sprint(job))); err != nil {
			return err
		}
		out, err = s.app(ctx, tx, name)
		return err
	})
	if err != nil {
		return App{}, 0, err
	}
	s.stacks.Wake()
	return out, job, nil
}

// UpdateInput updates an app to the catalog's version.
type UpdateInput struct {
	Values            map[string]string `json:"values"`
	ApproveExceptions bool              `json:"approve_exceptions"`
}

// Update adds a revision with the catalog's version and deploys it with a
// pre-update snapshot (AT-F05-02).
func (s *Service) Update(ctx context.Context, a stacks.Actor, name string, in UpdateInput) (App, int64, error) {
	cur, err := s.app(ctx, s.db, name)
	if err != nil {
		return App{}, 0, err
	}
	if cur.SourceID == nil {
		return App{}, 0, &ValidationError{"the app's source was removed; it cannot be updated"}
	}
	src, next, err := s.entry(ctx, s.db, *cur.SourceID, cur.AppID)
	if errors.Is(err, ErrNotFound) {
		return App{}, 0, &ValidationError{"the app is no longer in its source's catalog"}
	}
	if err != nil {
		return App{}, 0, err
	}
	if src.expired(s.now()) {
		return App{}, 0, ErrExpired
	}
	if !cur.UpdateAvailable {
		return App{}, 0, ErrUpToDate
	}
	config, err := s.stacks.PublicVariables(ctx, cur.stackID)
	if err != nil {
		return App{}, 0, err
	}
	vars, values, err := resolve(next.Fields, in.Values, config)
	if err != nil {
		return App{}, 0, err
	}
	d := s.disclose(name, next, values)
	if !d.Installable {
		return App{}, 0, &ValidationError{"this version cannot be installed on this host: " + strings.Join(d.Problems, "; ")}
	}
	exc := d.Exceptions()
	prev := s.currentExceptions(ctx, cur)
	for _, e := range exc {
		if !prev[e.Service+"/"+e.Rule] && (!a.CanApprove || !in.ApproveExceptions) {
			return App{}, 0, ErrApproval
		}
	}
	entry, _ := json.Marshal(next)
	var out App
	var job int64
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		st, err := s.stacks.Get(ctx, tx, name)
		if err != nil {
			return err
		}
		rev, _, err := s.stacks.AddRevisionManaged(ctx, tx, a, st, stacks.RevisionInput{Compose: next.Compose,
			Comment: fmt.Sprintf("update %s to %s", next.Name, next.Version), Variables: vars, Exceptions: stackExceptions(exc)})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO app_versions (stack_id, revision, version, entry) VALUES (?, ?, ?, ?)`,
			st.ID, rev.Number, next.Version, string(entry)); err != nil {
			return err
		}
		if job, err = s.stacks.DeployManaged(ctx, tx, a, st, rev.Number, st.DeployedRevision > 0); err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, s.now(), event(a, "app.update", "app:"+name, audit.Success,
			"from", cur.Version, "to", next.Version, "revision", fmt.Sprint(rev.Number), "job", fmt.Sprint(job))); err != nil {
			return err
		}
		out, err = s.app(ctx, tx, name)
		return err
	})
	if err != nil {
		return App{}, 0, err
	}
	s.stacks.Wake()
	return out, job, nil
}

// Remove queues removing the app (AT-F05-03). The caller has re-authenticated
// the user when deleteData is set.
func (s *Service) Remove(ctx context.Context, a stacks.Actor, name string, deleteData bool) (int64, error) {
	var job int64
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		st, err := s.stacks.Get(ctx, tx, name)
		if errors.Is(err, stacks.ErrNotFound) || err == nil && st.ManagedBy != "app" {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if job, err = s.stacks.DownManaged(ctx, tx, a, st, deleteData, true); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), event(a, "app.remove", "app:"+name, audit.Success,
			"delete_data", fmt.Sprint(deleteData), "job", fmt.Sprint(job)))
		return err
	})
	if err != nil {
		return 0, err
	}
	s.stacks.Wake()
	return job, nil
}
