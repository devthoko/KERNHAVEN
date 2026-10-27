// Package apps implements the app store and app lifecycle (M8): catalog
// sources with signature verification, browsing with policy disclosure, and
// install, update and removal of apps as managed Compose stacks.
package apps

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devthoko/KERNHAVEN/internal/catalog"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
)

// Errors.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("a source with this name already exists")
	ErrNoURL    = errors.New("this source has no URL; upload a signed catalog instead")
)

// ValidationError is a client error.
type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

// RejectedError means a catalog failed verification; it is recorded on the
// source and nothing was changed.
type RejectedError struct{ Err error }

func (e *RejectedError) Error() string { return e.Err.Error() }
func (e *RejectedError) Unwrap() error { return e.Err }

// Service implements the app store.
type Service struct {
	db      *sql.DB
	audit   *audit.Log
	stacks  *stacks.Service
	fetcher *stacks.Fetcher
	now     func() time.Time
}

// New returns the service.
func New(db *sql.DB, auditLog *audit.Log, st *stacks.Service, fetcher *stacks.Fetcher, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if fetcher == nil {
		fetcher = stacks.NewFetcher(nil, nil)
	}
	return &Service{db: db, audit: auditLog, stacks: st, fetcher: fetcher, now: now}
}

func (s *Service) nowMS() int64 { return s.now().UnixMilli() }

func msTime(v int64) *time.Time {
	if v == 0 {
		return nil
	}
	t := time.UnixMilli(v).UTC()
	return &t
}

func (s *Service) withTx(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	if err := f(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Source is a catalog source.
type Source struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	PublicKey   string     `json:"public_key"`
	KeyID       string     `json:"key_id"`
	Serial      int64      `json:"serial"`
	CatalogName string     `json:"catalog_name"`
	ExpiresAt   *time.Time `json:"expires_at"`
	SyncedAt    *time.Time `json:"synced_at"`
	LastError   string     `json:"last_error"`
	AppCount    int        `json:"app_count"`

	payloadSHA256 string
}

// Expired reports whether the accepted catalog may no longer be used.
func (src Source) expired(now time.Time) bool {
	return src.ExpiresAt == nil || !src.ExpiresAt.After(now)
}

const sourceCols = `s.id, s.name, s.url, s.public_key, s.serial, s.payload_sha256, s.catalog_name, s.expires_ms, s.synced_ms, s.last_error,
	(SELECT COUNT(*) FROM catalog_apps a WHERE a.source_id = s.id)`

type rowScanner interface{ Scan(...any) error }

func scanSource(row rowScanner) (Source, error) {
	var src Source
	var expires, synced int64
	err := row.Scan(&src.ID, &src.Name, &src.URL, &src.PublicKey, &src.Serial, &src.payloadSHA256, &src.CatalogName, &expires, &synced, &src.LastError, &src.AppCount)
	if errors.Is(err, sql.ErrNoRows) {
		return src, ErrNotFound
	}
	src.ExpiresAt, src.SyncedAt = msTime(expires), msTime(synced)
	if pub, perr := catalog.ParsePublicKey(src.PublicKey); perr == nil {
		src.KeyID = catalog.KeyID(pub)
	}
	return src, err
}

type querier interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

func (s *Service) source(ctx context.Context, q querier, id int64) (Source, error) {
	return scanSource(q.QueryRowContext(ctx, `SELECT `+sourceCols+` FROM catalog_sources s WHERE s.id = ?`, id))
}

// Sources lists the catalog sources.
func (s *Service) Sources(ctx context.Context) ([]Source, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+sourceCols+` FROM catalog_sources s ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Source{}
	for rows.Next() {
		src, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, src)
	}
	return out, rows.Err()
}

// SourceInput adds a source.
type SourceInput struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	PublicKey string `json:"public_key"`
}

func printable(v string, max int) bool {
	if strings.TrimSpace(v) == "" || !utf8.ValidString(v) || utf8.RuneCountInString(v) > max {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// AddSource stores a new source; it is synced separately.
func (s *Service) AddSource(ctx context.Context, a stacks.Actor, in SourceInput) (Source, error) {
	in.Name, in.URL, in.PublicKey = strings.TrimSpace(in.Name), strings.TrimSpace(in.URL), strings.TrimSpace(in.PublicKey)
	if !printable(in.Name, 64) {
		return Source{}, &ValidationError{"name must be 1-64 printable characters"}
	}
	if in.URL != "" {
		u, err := url.Parse(in.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(in.URL) > 500 {
			return Source{}, &ValidationError{"url must be an https URL without credentials"}
		}
	}
	pub, err := catalog.ParsePublicKey(in.PublicKey)
	if err != nil {
		return Source{}, &ValidationError{err.Error()}
	}
	var src Source
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM catalog_sources WHERE name = ?`, in.Name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrExists
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO catalog_sources (name, url, public_key, created_by, created_ms) VALUES (?, ?, ?, ?, ?)`,
			in.Name, in.URL, in.PublicKey, a.ID, s.nowMS())
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		if _, err := audit.Append(ctx, tx, s.now(), event(a, "catalog.source.add", fmt.Sprintf("source:%d", id), audit.Success,
			"name", in.Name, "url", in.URL, "key_id", catalog.KeyID(pub))); err != nil {
			return err
		}
		src, err = s.source(ctx, tx, id)
		return err
	})
	return src, err
}

// DeleteSource removes a source and its catalog. Installed apps stay; they
// just no longer receive updates.
func (s *Service) DeleteSource(ctx context.Context, a stacks.Actor, id int64) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		src, err := s.source(ctx, tx, id)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM catalog_sources WHERE id = ?`, id); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), event(a, "catalog.source.remove", fmt.Sprintf("source:%d", id), audit.Success, "name", src.Name))
		return err
	})
}

// Sync downloads and verifies the source's catalog (AT-F04-01).
func (s *Service) Sync(ctx context.Context, a stacks.Actor, id int64) (Source, error) {
	src, err := s.source(ctx, s.db, id)
	if err != nil {
		return Source{}, err
	}
	if src.URL == "" {
		return src, ErrNoURL
	}
	fctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	data, err := s.fetcher.FetchLimit(fctx, src.URL, "application/json", catalog.MaxEnvelope)
	if err != nil {
		s.reject(ctx, a, src, err)
		return Source{}, &RejectedError{err}
	}
	return s.accept(ctx, a, src, data)
}

// Upload verifies and accepts a signed catalog for the source.
func (s *Service) Upload(ctx context.Context, a stacks.Actor, id int64, data []byte) (Source, error) {
	src, err := s.source(ctx, s.db, id)
	if err != nil {
		return Source{}, err
	}
	return s.accept(ctx, a, src, data)
}

func (s *Service) reject(ctx context.Context, a stacks.Actor, src Source, err error) {
	ctx = context.WithoutCancel(ctx)
	msg := err.Error()
	if len(msg) > 1000 {
		msg = msg[:1000]
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE catalog_sources SET last_error = ? WHERE id = ?`, msg, src.ID)
	_ = s.audit.Record(ctx, event(a, "catalog.sync", fmt.Sprintf("source:%d", src.ID), audit.Failure, "reason", msg))
}

func (s *Service) accept(ctx context.Context, a stacks.Actor, src Source, data []byte) (Source, error) {
	pub, err := catalog.ParsePublicKey(src.PublicKey)
	if err != nil {
		return Source{}, err
	}
	v, err := catalog.Open(data, pub, catalog.State{Serial: src.Serial, PayloadSHA256: src.payloadSHA256}, s.now())
	if err != nil {
		s.reject(ctx, a, src, err)
		return Source{}, &RejectedError{err}
	}
	var out Source
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM catalog_apps WHERE source_id = ?`, src.ID); err != nil {
			return err
		}
		for _, app := range v.Catalog.Apps {
			cats, _ := json.Marshal(orEmpty(app.Categories))
			entry, _ := json.Marshal(app)
			if _, err := tx.ExecContext(ctx, `INSERT INTO catalog_apps (source_id, app_id, name, version, summary, categories, entry) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				src.ID, app.ID, app.Name, app.Version, app.Summary, string(cats), string(entry)); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE catalog_sources SET serial = ?, payload_sha256 = ?, catalog_name = ?, expires_ms = ?, synced_ms = ?, last_error = ''
			WHERE id = ?`, v.Catalog.Serial, v.PayloadSHA256, v.Catalog.Name, v.Catalog.Expires.UnixMilli(), s.nowMS(), src.ID); err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, s.now(), event(a, "catalog.sync", fmt.Sprintf("source:%d", src.ID), audit.Success,
			"serial", fmt.Sprint(v.Catalog.Serial), "apps", fmt.Sprint(len(v.Catalog.Apps)), "sha256", v.PayloadSHA256)); err != nil {
			return err
		}
		out, err = s.source(ctx, tx, src.ID)
		return err
	})
	return out, err
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func event(a stacks.Actor, action, target string, result audit.Result, kv ...string) audit.Event {
	ev := audit.Event{ActorID: a.ID, Actor: a.Name, Action: action, Target: target, Result: result, RequestID: a.RequestID, IP: a.IP, Details: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		ev.Details[kv[i]] = kv[i+1]
	}
	return ev
}

// Listing is one app in the store.
type Listing struct {
	SourceID   int64    `json:"source_id"`
	SourceName string   `json:"source_name"`
	AppID      string   `json:"app_id"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Summary    string   `json:"summary"`
	Categories []string `json:"categories"`
	Installed  []string `json:"installed"`
}

// Browse lists catalog apps matching the query and category (AT-F04-02).
// It also returns all categories for filtering.
func (s *Service) Browse(ctx context.Context, query, category string, sourceID int64) ([]Listing, []string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.source_id, s.name, a.app_id, a.name, a.version, a.summary, a.categories
		FROM catalog_apps a JOIN catalog_sources s ON s.id = a.source_id ORDER BY a.name COLLATE NOCASE, s.name`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	installed, err := s.installedBy(ctx)
	if err != nil {
		return nil, nil, err
	}
	query = strings.ToLower(strings.TrimSpace(query))
	cats := map[string]bool{}
	out := []Listing{}
	for rows.Next() {
		var l Listing
		var c string
		if err := rows.Scan(&l.SourceID, &l.SourceName, &l.AppID, &l.Name, &l.Version, &l.Summary, &c); err != nil {
			return nil, nil, err
		}
		_ = json.Unmarshal([]byte(c), &l.Categories)
		l.Categories = orEmpty(l.Categories)
		for _, x := range l.Categories {
			cats[x] = true
		}
		if sourceID > 0 && l.SourceID != sourceID {
			continue
		}
		if category != "" && !contains(l.Categories, category) {
			continue
		}
		if query != "" && !strings.Contains(strings.ToLower(l.Name+" "+l.AppID+" "+l.Summary), query) {
			continue
		}
		l.Installed = orEmpty(installed[fmt.Sprintf("%d/%s", l.SourceID, l.AppID)])
		out = append(out, l)
	}
	all := make([]string, 0, len(cats))
	for c := range cats {
		all = append(all, c)
	}
	sort.Strings(all)
	return out, all, rows.Err()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// installedBy maps "source/app" to the names of installed instances.
func (s *Service) installedBy(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT a.source_id, a.app_id, st.name FROM apps a JOIN stacks st ON st.id = a.stack_id WHERE a.source_id IS NOT NULL ORDER BY st.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string][]string{}
	for rows.Next() {
		var src int64
		var app, name string
		if err := rows.Scan(&src, &app, &name); err != nil {
			return nil, err
		}
		k := fmt.Sprintf("%d/%s", src, app)
		m[k] = append(m[k], name)
	}
	return m, rows.Err()
}

// entry loads a verified catalog entry.
func (s *Service) entry(ctx context.Context, q querier, sourceID int64, appID string) (Source, catalog.App, error) {
	src, err := s.source(ctx, q, sourceID)
	if err != nil {
		return src, catalog.App{}, err
	}
	var raw string
	err = q.QueryRowContext(ctx, `SELECT entry FROM catalog_apps WHERE source_id = ? AND app_id = ?`, sourceID, appID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return src, catalog.App{}, ErrNotFound
	}
	if err != nil {
		return src, catalog.App{}, err
	}
	var app catalog.App
	if err := json.Unmarshal([]byte(raw), &app); err != nil {
		return src, app, err
	}
	return src, app, nil
}

// Detail is a store app with its configuration form and disclosure.
type Detail struct {
	Source     Source      `json:"source"`
	App        catalog.App `json:"app"`
	Disclosure Disclosure  `json:"disclosure"`
	Installed  []string    `json:"installed"`
	Expired    bool        `json:"expired"`
}

// AppDetail returns an app of the store (AT-F04-02, AT-F04-04).
func (s *Service) AppDetail(ctx context.Context, sourceID int64, appID string) (Detail, error) {
	src, app, err := s.entry(ctx, s.db, sourceID, appID)
	if err != nil {
		return Detail{}, err
	}
	installed, err := s.installedBy(ctx)
	if err != nil {
		return Detail{}, err
	}
	return Detail{Source: src, App: app, Disclosure: s.disclose(app.ID, app, app.Placeholders()),
		Installed: orEmpty(installed[fmt.Sprintf("%d/%s", sourceID, appID)]), Expired: src.expired(s.now())}, nil
}
