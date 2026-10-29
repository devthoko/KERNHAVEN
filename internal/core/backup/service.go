package backup

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
)

// Target kinds.
const (
	TargetLocal = "local"
	TargetSFTP  = "sftp"
	TargetS3    = "s3"
)

// Errors of the backup API.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("already exists")
	ErrInUse    = errors.New("the repository is used by a backup plan")
)

// ValidationError is invalid input.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{fmt.Sprintf(format, a...)} }

// UnavailableError is a target that could not be used (unreachable,
// refused credentials, damaged repository); the message is shown to the
// administrator.
type UnavailableError struct{ Err error }

func (e *UnavailableError) Error() string { return e.Err.Error() }
func (e *UnavailableError) Unwrap() error { return e.Err }

// unavailable wraps target errors that are not the caller's input.
func unavailable(err error) error {
	var ve *ValidationError
	var te *TargetError
	var ue *UnavailableError
	if err == nil || errors.As(err, &ve) || errors.As(err, &te) || errors.As(err, &ue) || errors.Is(err, netguard.ErrForbiddenAddress) ||
		errors.Is(err, ErrPassphrase) || errors.Is(err, ErrRepoExists) || errors.Is(err, ErrNotFound) {
		return err
	}
	return &UnavailableError{err}
}

// Actor performs a change.
type Actor struct {
	ID        int64
	Name      string
	RequestID string
	IP        string
}

// Config are the host settings of the backup service.
type Config struct {
	LocalRoots []string
	Guard      netguard.Guard
	Roots      *x509.CertPool // for S3 over HTTPS; nil means the system roots
	DataDir    string
	ConfigPath string // core.toml, included for reference; may be empty
	// StepTimeout bounds waiting for helpers and health checks.
	HealthTimeout time.Duration
}

// Service implements backups (M16).
type Service struct {
	db     *sql.DB
	box    *secretbox.Box
	audit  *audit.Log
	jobs   *jobs.Service
	wake   func()
	agent  *agentclient.Client
	stacks *stacks.Service
	cfg    Config
	log    *slog.Logger
	now    func() time.Time
	poll   time.Duration

	mu sync.Mutex // one scheduler round at a time
}

// New returns the service and registers its job kinds.
func New(db *sql.DB, box *secretbox.Box, auditLog *audit.Log, js *jobs.Service, wake func(), agent *agentclient.Client, st *stacks.Service, cfg Config, log *slog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	if cfg.HealthTimeout <= 0 {
		cfg.HealthTimeout = 5 * time.Minute
	}
	s := &Service{db: db, box: box, audit: auditLog, jobs: js, wake: wake, agent: agent, stacks: st, cfg: cfg, log: log, now: now, poll: 200 * time.Millisecond}
	s.registerJobs()
	return s
}

func withTx(ctx context.Context, db *sql.DB, f func(tx *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
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
		ev.Result, ev.Details["error"] = audit.Failure, err.Error()
	}
	return ev
}

func (s *Service) recordFailure(ctx context.Context, a Actor, action, target string, err error, kv ...string) {
	var ve *ValidationError
	var te *TargetError
	if errors.As(err, &ve) || errors.As(err, &te) || errors.Is(err, ErrPassphrase) || errors.Is(err, ErrRepoExists) {
		_ = s.audit.Record(context.WithoutCancel(ctx), s.event(a, action, target, err, kv...))
	}
}

// ---- targets ----

// TargetSecret holds a target's credentials; it is write-only in the API.
type TargetSecret struct {
	Password        string `json:"password,omitempty"`          // SFTP
	SecretAccessKey string `json:"secret_access_key,omitempty"` // S3
}

func strictJSON(raw json.RawMessage, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return invalid("invalid target settings: %v", err)
	}
	return nil
}

// normalizeConfig validates a target's settings and returns them in their
// canonical form.
func (s *Service) normalizeConfig(kind string, raw json.RawMessage) (json.RawMessage, error) {
	var v any
	switch kind {
	case TargetLocal:
		var c LocalConfig
		if err := strictJSON(raw, &c); err != nil {
			return nil, err
		}
		if err := CheckLocalPath(c.Path, s.cfg.LocalRoots); err != nil {
			return nil, err
		}
		v = c
	case TargetSFTP:
		var c SFTPConfig
		if err := strictJSON(raw, &c); err != nil {
			return nil, err
		}
		if err := c.validate(); err != nil {
			return nil, err
		}
		if err := s.literalAllowed(c.Host); err != nil {
			return nil, err
		}
		v = c
	case TargetS3:
		var c S3Config
		if err := strictJSON(raw, &c); err != nil {
			return nil, err
		}
		u, err := c.validate()
		if err != nil {
			return nil, err
		}
		if err := s.literalAllowed(u.Hostname()); err != nil {
			return nil, err
		}
		v = c
	default:
		return nil, invalid("kind must be local, sftp or s3")
	}
	b, _ := json.Marshal(v)
	return b, nil
}

func (s *Service) literalAllowed(host string) error {
	if a, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil && !s.cfg.Guard.Allowed(a) {
		return invalid("%s is a loopback, link-local or multicast address, which Kernhaven does not contact", a.Unmap())
	}
	return nil
}

// OpenTarget connects to a target with validated settings.
func (s *Service) OpenTarget(ctx context.Context, kind string, raw json.RawMessage, sec TargetSecret) (Target, error) {
	t, err := s.openTarget(ctx, kind, raw, sec)
	return t, unavailable(err)
}

func (s *Service) openTarget(ctx context.Context, kind string, raw json.RawMessage, sec TargetSecret) (Target, error) {
	cfg, err := s.normalizeConfig(kind, raw)
	if err != nil {
		return nil, err
	}
	switch kind {
	case TargetLocal:
		var c LocalConfig
		_ = json.Unmarshal(cfg, &c)
		return OpenLocal(c, s.cfg.LocalRoots)
	case TargetSFTP:
		var c SFTPConfig
		_ = json.Unmarshal(cfg, &c)
		auth := SFTPAuth{Password: sec.Password}
		if sec.Password == "" {
			k, err := s.sftpKey(ctx, false)
			if err != nil {
				return nil, err
			}
			auth = k
		}
		return OpenSFTP(ctx, s.cfg.Guard, c, auth)
	default:
		var c S3Config
		_ = json.Unmarshal(cfg, &c)
		return OpenS3(ctx, s.cfg.Guard, c, sec.SecretAccessKey, s.cfg.Roots)
	}
}

const sftpKeySetting = "sftp_key"

// sftpKey returns the Core's SSH key for SFTP targets, creating it once.
func (s *Service) sftpKey(ctx context.Context, create bool) (SFTPAuth, error) {
	var sealed []byte
	err := s.db.QueryRowContext(ctx, `SELECT v FROM backup_settings WHERE k = ?`, sftpKeySetting).Scan(&sealed)
	if err == nil {
		seed, err := s.box.Open(sealed, "backup/"+sftpKeySetting)
		if err != nil {
			return SFTPAuth{}, err
		}
		return SFTPAuth{PrivateKey: []byte(seed)}, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return SFTPAuth{}, err
	}
	if !create {
		return SFTPAuth{}, invalid("no SSH key exists yet; show the Core's public key first or use a password")
	}
	a, _, err := NewSFTPKey()
	if err != nil {
		return SFTPAuth{}, err
	}
	b, err := s.box.Seal(string(a.PrivateKey), "backup/"+sftpKeySetting)
	if err != nil {
		return SFTPAuth{}, err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO backup_settings (k, v) VALUES (?, ?) ON CONFLICT (k) DO NOTHING`, sftpKeySetting, b); err != nil {
		return SFTPAuth{}, err
	}
	return s.sftpKey(ctx, false) // the stored key wins a race
}

// SFTPPublicKey returns the authorized_keys line of the Core's SSH key.
func (s *Service) SFTPPublicKey(ctx context.Context) (string, error) {
	a, err := s.sftpKey(ctx, true)
	if err != nil {
		return "", err
	}
	return a.PublicKey()
}

// ScanHostKey reads an SFTP server's host key for confirmation.
func (s *Service) ScanHostKey(ctx context.Context, host string, port int) (string, string, error) {
	if err := s.literalAllowed(host); err != nil {
		return "", "", err
	}
	return ScanHostKey(ctx, s.cfg.Guard, host, port)
}

// ---- repositories ----

// Repository is a configured backup repository without its secrets.
type Repository struct {
	ID             int64           `json:"id"`
	Name           string          `json:"name"`
	Kind           string          `json:"kind"`
	Config         json.RawMessage `json:"config"`
	HasSecret      bool            `json:"has_secret"`
	RepoID         string          `json:"repo_id"`
	VerifySchedule string          `json:"verify_schedule"`
	VerifyNext     *time.Time      `json:"verify_next,omitempty"`
	VerifiedAt     *time.Time      `json:"verified_at,omitempty"`
	VerifyOK       *bool           `json:"verify_ok,omitempty"`
	VerifyMessage  string          `json:"verify_message"`
	Snapshots      int             `json:"snapshots"`
	Size           int64           `json:"size"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// RepoInput creates a repository (initialising the target or connecting
// to an existing repository on it) or changes its settings.
type RepoInput struct {
	Name           string          `json:"name"`
	Kind           string          `json:"kind"`
	Config         json.RawMessage `json:"config"`
	Secret         *TargetSecret   `json:"secret"`
	Passphrase     string          `json:"passphrase"`
	Connect        bool            `json:"connect"`
	VerifySchedule string          `json:"verify_schedule"`
}

func msTime(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64)
	return &t
}

const repoColumns = `r.id, r.name, r.kind, r.config, r.secret IS NOT NULL AND length(r.secret) > 0, r.repo_id, r.verify_schedule, r.verify_next_ms, r.verified_ms, r.verify_ok, r.verify_msg, r.created_ms, r.updated_ms,
	(SELECT count(*) FROM backup_snapshots s WHERE s.repo = r.id), (SELECT coalesce(sum(size), 0) FROM backup_snapshots s WHERE s.repo = r.id)`

func scanRepo(sc interface{ Scan(...any) error }) (Repository, error) {
	var r Repository
	var cfg string
	var next, verified, ok sql.NullInt64
	var created, updated int64
	err := sc.Scan(&r.ID, &r.Name, &r.Kind, &cfg, &r.HasSecret, &r.RepoID, &r.VerifySchedule, &next, &verified, &ok, &r.VerifyMessage, &created, &updated, &r.Snapshots, &r.Size)
	if errors.Is(err, sql.ErrNoRows) {
		return r, ErrNotFound
	}
	r.Config = json.RawMessage(cfg)
	r.VerifyNext, r.VerifiedAt = msTime(next), msTime(verified)
	if ok.Valid {
		b := ok.Int64 == 1
		r.VerifyOK = &b
	}
	r.CreatedAt, r.UpdatedAt = time.UnixMilli(created), time.UnixMilli(updated)
	return r, err
}

// Repositories lists all repositories.
func (s *Service) Repositories(ctx context.Context) ([]Repository, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+repoColumns+` FROM backup_repos r ORDER BY r.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Repository{}
	for rows.Next() {
		r, err := scanRepo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Repository returns one repository.
func (s *Service) Repository(ctx context.Context, id int64) (Repository, error) {
	return scanRepo(s.db.QueryRowContext(ctx, `SELECT `+repoColumns+` FROM backup_repos r WHERE r.id = ?`, id))
}

func keyContext(repoID string) string    { return "backup/repo/" + repoID + "/key" }
func secretContext(repoID string) string { return "backup/repo/" + repoID + "/secret" }

func (s *Service) repoSecret(ctx context.Context, id int64) (Repository, TargetSecret, []byte, error) {
	r, err := s.Repository(ctx, id)
	if err != nil {
		return r, TargetSecret{}, nil, err
	}
	var sealedSecret, sealedKey []byte
	if err := s.db.QueryRowContext(ctx, `SELECT secret, data_key FROM backup_repos WHERE id = ?`, id).Scan(&sealedSecret, &sealedKey); err != nil {
		return r, TargetSecret{}, nil, err
	}
	var sec TargetSecret
	if len(sealedSecret) > 0 {
		plain, err := s.box.Open(sealedSecret, secretContext(r.RepoID))
		if err != nil {
			return r, sec, nil, err
		}
		if err := json.Unmarshal([]byte(plain), &sec); err != nil {
			return r, sec, nil, err
		}
	}
	key, err := s.box.Open(sealedKey, keyContext(r.RepoID))
	if err != nil {
		return r, sec, nil, err
	}
	return r, sec, []byte(key), nil
}

// OpenRepository connects to a stored repository.
func (s *Service) OpenRepository(ctx context.Context, id int64) (*Repo, Repository, error) {
	r, sec, key, err := s.repoSecret(ctx, id)
	if err != nil {
		return nil, r, err
	}
	t, err := s.OpenTarget(ctx, r.Kind, r.Config, sec)
	if err != nil {
		return nil, r, err
	}
	repo, err := OpenRepoKey(ctx, t, r.RepoID, key)
	if err != nil {
		t.Close()
		return nil, r, unavailable(err)
	}
	return repo, r, nil
}

func validName(kind, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 || strings.ContainsAny(name, "\r\n\t") {
		return "", invalid("%s name must be 1 to 64 characters", kind)
	}
	return name, nil
}

func sealSecret(box *secretbox.Box, repoID string, sec TargetSecret) ([]byte, error) {
	if sec == (TargetSecret{}) {
		return nil, nil
	}
	b, _ := json.Marshal(sec)
	return box.Seal(string(b), secretContext(repoID))
}

// CreateRepository initialises or connects to a repository. The target is
// contacted before anything is stored.
func (s *Service) CreateRepository(ctx context.Context, a Actor, in RepoInput) (Repository, error) {
	name, err := validName("repository", in.Name)
	if err != nil {
		return Repository{}, err
	}
	if in.VerifySchedule == "" {
		in.VerifySchedule = "@weekly"
	}
	sched, err := ParseSchedule(in.VerifySchedule)
	if err != nil {
		return Repository{}, invalid("verify_schedule: %v", err)
	}
	if err := ValidatePassphrase(in.Passphrase); err != nil && !in.Connect {
		return Repository{}, invalid("%v", err)
	}
	cfg, err := s.normalizeConfig(in.Kind, in.Config)
	if err != nil {
		s.recordFailure(ctx, a, "backup.repo_create", "backup-repo:"+name, err)
		return Repository{}, err
	}
	sec := TargetSecret{}
	if in.Secret != nil {
		sec = *in.Secret
	}
	t, err := s.OpenTarget(ctx, in.Kind, cfg, sec)
	if err != nil {
		s.recordFailure(ctx, a, "backup.repo_create", "backup-repo:"+name, err)
		return Repository{}, err
	}
	defer t.Close()
	var repo *Repo
	if in.Connect {
		repo, err = OpenRepo(ctx, t, in.Passphrase)
	} else {
		repo, err = InitRepo(ctx, t, in.Passphrase, s.now())
	}
	if err != nil {
		s.recordFailure(ctx, a, "backup.repo_create", "backup-repo:"+name, err)
		return Repository{}, unavailable(err)
	}
	rid := repo.Header.ID
	sealedKey, err := s.box.Seal(string(repo.Key()), keyContext(rid))
	if err != nil {
		return Repository{}, err
	}
	sealedSecret, err := sealSecret(s.box, rid, sec)
	if err != nil {
		return Repository{}, err
	}
	now := s.now()
	var id int64
	err = withTx(ctx, s.db, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM backup_repos WHERE repo_id = ? OR name = ?`, rid, name).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrExists
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO backup_repos (name, kind, config, secret, repo_id, data_key, verify_schedule, verify_next_ms, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			name, in.Kind, string(cfg), sealedSecret, rid, sealedKey, in.VerifySchedule, sched.Next(now).UnixMilli(), now.UnixMilli(), now.UnixMilli())
		if err != nil {
			return err
		}
		id, _ = res.LastInsertId()
		mode := "initialised"
		if in.Connect {
			mode = "connected"
		}
		_, err = audit.Append(ctx, tx, now, s.event(a, "backup.repo_create", "backup-repo:"+name, nil, "kind", in.Kind, "repo_id", rid, "mode", mode))
		return err
	})
	if err != nil {
		return Repository{}, err
	}
	if in.Connect {
		// Snapshots already on the target become known (and verifiable).
		if err := s.syncSnapshots(ctx, id, repo); err != nil {
			s.log.Warn("listing snapshots of a connected repository failed", "repo", name, "error", err.Error())
		}
	}
	return s.Repository(ctx, id)
}

// UpdateRepository changes a repository's name, settings or credentials;
// the target must still hold the same repository.
func (s *Service) UpdateRepository(ctx context.Context, a Actor, id int64, in RepoInput) (Repository, error) {
	cur, sec, key, err := s.repoSecret(ctx, id)
	if err != nil {
		return Repository{}, err
	}
	name, err := validName("repository", in.Name)
	if err != nil {
		return Repository{}, err
	}
	if in.Kind != "" && in.Kind != cur.Kind {
		return Repository{}, invalid("the kind of a repository cannot change")
	}
	if in.VerifySchedule == "" {
		in.VerifySchedule = cur.VerifySchedule
	}
	sched, err := ParseSchedule(in.VerifySchedule)
	if err != nil {
		return Repository{}, invalid("verify_schedule: %v", err)
	}
	if len(in.Config) == 0 {
		in.Config = cur.Config
	}
	cfg, err := s.normalizeConfig(cur.Kind, in.Config)
	if err != nil {
		return Repository{}, err
	}
	if in.Secret != nil {
		sec = *in.Secret
	}
	t, err := s.OpenTarget(ctx, cur.Kind, cfg, sec)
	if err != nil {
		s.recordFailure(ctx, a, "backup.repo_update", "backup-repo:"+cur.Name, err)
		return Repository{}, err
	}
	defer t.Close()
	if _, err := OpenRepoKey(ctx, t, cur.RepoID, key); err != nil {
		return Repository{}, invalid("%v", err)
	}
	sealedSecret, err := sealSecret(s.box, cur.RepoID, sec)
	if err != nil {
		return Repository{}, err
	}
	now := s.now()
	err = withTx(ctx, s.db, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE backup_repos SET name = ?, config = ?, secret = ?, verify_schedule = ?, verify_next_ms = ?, updated_ms = ? WHERE id = ?`,
			name, string(cfg), sealedSecret, in.VerifySchedule, sched.Next(now).UnixMilli(), now.UnixMilli(), id)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrExists
			}
			return err
		}
		_, err = audit.Append(ctx, tx, now, s.event(a, "backup.repo_update", "backup-repo:"+name, nil, "secret_changed", fmt.Sprint(in.Secret != nil)))
		return err
	})
	if err != nil {
		return Repository{}, err
	}
	return s.Repository(ctx, id)
}

// DeleteRepository forgets a repository; the data on the target stays.
func (s *Service) DeleteRepository(ctx context.Context, a Actor, id int64) error {
	cur, err := s.Repository(ctx, id)
	if err != nil {
		return err
	}
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM backup_plans WHERE repo = ?`, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrInUse
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM backup_repos WHERE id = ?`, id); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), s.event(a, "backup.repo_delete", "backup-repo:"+cur.Name, nil, "repo_id", cur.RepoID))
		return err
	})
}

// ---- plans ----

// Plan is a scheduled backup.
type Plan struct {
	ID        int64      `json:"id"`
	Name      string     `json:"name"`
	Repo      int64      `json:"repo"`
	Schedule  string     `json:"schedule"`
	Platform  bool       `json:"platform"`
	Stacks    []string   `json:"stacks"`
	Quiesce   bool       `json:"quiesce"`
	Retention Retention  `json:"retention"`
	Enabled   bool       `json:"enabled"`
	Next      *time.Time `json:"next,omitempty"`
	LastJob   *int64     `json:"last_job,omitempty"`
	LastState string     `json:"last_state"`
	LastAt    *time.Time `json:"last_at,omitempty"`
}

// PlanInput creates or replaces a plan.
type PlanInput struct {
	Name      string    `json:"name"`
	Repo      int64     `json:"repo"`
	Schedule  string    `json:"schedule"`
	Platform  bool      `json:"platform"`
	Stacks    []string  `json:"stacks"`
	Quiesce   *bool     `json:"quiesce"`
	Retention Retention `json:"retention"`
	Enabled   *bool     `json:"enabled"`
}

const planColumns = `p.id, p.name, p.repo, p.schedule, p.platform, p.stacks, p.quiesce, p.retention, p.enabled, p.next_ms, p.last_job,
	coalesce((SELECT state FROM jobs j WHERE j.id = p.last_job), ''), (SELECT updated_ms FROM jobs j WHERE j.id = p.last_job)`

func scanPlan(sc interface{ Scan(...any) error }) (Plan, error) {
	var p Plan
	var stacksJSON, ret string
	var next, last, lastAt sql.NullInt64
	err := sc.Scan(&p.ID, &p.Name, &p.Repo, &p.Schedule, &p.Platform, &stacksJSON, &p.Quiesce, &ret, &p.Enabled, &next, &last, &p.LastState, &lastAt)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	_ = json.Unmarshal([]byte(stacksJSON), &p.Stacks)
	_ = json.Unmarshal([]byte(ret), &p.Retention)
	p.Next, p.LastAt = msTime(next), msTime(lastAt)
	if last.Valid {
		p.LastJob = &last.Int64
	}
	return p, err
}

// Plans lists all plans.
func (s *Service) Plans(ctx context.Context) ([]Plan, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+planColumns+` FROM backup_plans p ORDER BY p.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Plan{}
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPlan returns one plan.
func (s *Service) GetPlan(ctx context.Context, id int64) (Plan, error) {
	return scanPlan(s.db.QueryRowContext(ctx, `SELECT `+planColumns+` FROM backup_plans p WHERE p.id = ?`, id))
}

func (s *Service) stackNames(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name, deployed_revision FROM stacks`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var n string
		var rev int
		if err := rows.Scan(&n, &rev); err != nil {
			return nil, err
		}
		out[n] = rev
	}
	return out, rows.Err()
}

// SavePlan creates (id 0) or replaces a plan.
func (s *Service) SavePlan(ctx context.Context, a Actor, id int64, in PlanInput) (Plan, error) {
	name, err := validName("plan", in.Name)
	if err != nil {
		return Plan{}, err
	}
	sched, err := ParseSchedule(in.Schedule)
	if err != nil {
		return Plan{}, invalid("schedule: %v", err)
	}
	if err := in.Retention.validate(); err != nil {
		return Plan{}, invalid("%v", err)
	}
	if _, err := s.Repository(ctx, in.Repo); err != nil {
		return Plan{}, invalid("repository %d does not exist", in.Repo)
	}
	known, err := s.stackNames(ctx)
	if err != nil {
		return Plan{}, err
	}
	stackList := []string{}
	seen := map[string]bool{}
	for _, n := range in.Stacks {
		if n == "*" && len(in.Stacks) == 1 {
			stackList = []string{"*"}
			break
		}
		if _, ok := known[n]; !ok {
			return Plan{}, invalid("stack %q does not exist", n)
		}
		if !seen[n] {
			seen[n] = true
			stackList = append(stackList, n)
		}
	}
	sort.Strings(stackList)
	if !in.Platform && len(stackList) == 0 {
		return Plan{}, invalid("a plan must back up the platform or at least one stack")
	}
	quiesce := in.Quiesce == nil || *in.Quiesce
	enabled := in.Enabled == nil || *in.Enabled
	stacksJSON, _ := json.Marshal(stackList)
	ret, _ := json.Marshal(in.Retention)
	now := s.now()
	err = withTx(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		if id == 0 {
			var res sql.Result
			res, err = tx.ExecContext(ctx, `INSERT INTO backup_plans (name, repo, schedule, platform, stacks, quiesce, retention, enabled, next_ms, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				name, in.Repo, in.Schedule, in.Platform, string(stacksJSON), quiesce, string(ret), enabled, sched.Next(now).UnixMilli(), now.UnixMilli(), now.UnixMilli())
			if err == nil {
				id, _ = res.LastInsertId()
			}
		} else {
			var res sql.Result
			res, err = tx.ExecContext(ctx, `UPDATE backup_plans SET name = ?, repo = ?, schedule = ?, platform = ?, stacks = ?, quiesce = ?, retention = ?, enabled = ?, next_ms = ?, updated_ms = ? WHERE id = ?`,
				name, in.Repo, in.Schedule, in.Platform, string(stacksJSON), quiesce, string(ret), enabled, sched.Next(now).UnixMilli(), now.UnixMilli(), id)
			if err == nil {
				if n, _ := res.RowsAffected(); n == 0 {
					return ErrNotFound
				}
			}
		}
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrExists
			}
			return err
		}
		_, err = audit.Append(ctx, tx, now, s.event(a, "backup.plan_save", "backup-plan:"+name, nil, "schedule", in.Schedule, "stacks", strings.Join(stackList, ","),
			"platform", fmt.Sprint(in.Platform), "enabled", fmt.Sprint(enabled), "retention", string(ret)))
		return err
	})
	if err != nil {
		return Plan{}, err
	}
	return s.GetPlan(ctx, id)
}

// DeletePlan removes a plan; its snapshots stay.
func (s *Service) DeletePlan(ctx context.Context, a Actor, id int64) error {
	p, err := s.GetPlan(ctx, id)
	if err != nil {
		return err
	}
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM backup_plans WHERE id = ?`, id); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), s.event(a, "backup.plan_delete", "backup-plan:"+p.Name, nil))
		return err
	})
}

// ---- snapshots ----

// Snapshot is a backup known to the Core.
type Snapshot struct {
	Repo          int64      `json:"repo"`
	ID            string     `json:"id"`
	Plan          string     `json:"plan"`
	CreatedAt     time.Time  `json:"created_at"`
	Size          int64      `json:"size"`
	Objects       int        `json:"objects"`
	Platform      bool       `json:"platform"`
	Stacks        []string   `json:"stacks"`
	VerifiedAt    *time.Time `json:"verified_at,omitempty"`
	VerifyOK      *bool      `json:"verify_ok,omitempty"`
	VerifyMessage string     `json:"verify_message"`
}

// Snapshots lists a repository's snapshots, newest first.
func (s *Service) Snapshots(ctx context.Context, repo int64) ([]Snapshot, error) {
	if _, err := s.Repository(ctx, repo); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT repo, id, plan_name, created_ms, size, objects, platform, stacks, verified_ms, verify_ok, verify_msg FROM backup_snapshots WHERE repo = ? ORDER BY created_ms DESC, id DESC`, repo)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Snapshot{}
	for rows.Next() {
		var sn Snapshot
		var created int64
		var stacksJSON string
		var verified, ok sql.NullInt64
		if err := rows.Scan(&sn.Repo, &sn.ID, &sn.Plan, &created, &sn.Size, &sn.Objects, &sn.Platform, &stacksJSON, &verified, &ok, &sn.VerifyMessage); err != nil {
			return nil, err
		}
		sn.CreatedAt, sn.VerifiedAt = time.UnixMilli(created), msTime(verified)
		_ = json.Unmarshal([]byte(stacksJSON), &sn.Stacks)
		if ok.Valid {
			b := ok.Int64 == 1
			sn.VerifyOK = &b
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

func manifestStacks(m Manifest) []string {
	out := []string{}
	for _, st := range m.Stacks {
		out = append(out, st.Name)
	}
	return out
}

func insertSnapshot(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, repo int64, planID *int64, m Manifest) error {
	stacksJSON, _ := json.Marshal(manifestStacks(m))
	_, err := q.ExecContext(ctx, `INSERT INTO backup_snapshots (repo, id, plan, plan_name, created_ms, size, objects, platform, stacks) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (repo, id) DO NOTHING`, repo, m.ID, planID, m.Plan, m.CreatedMS, m.Size(), len(m.Objects), m.Platform, string(stacksJSON))
	return err
}

// syncSnapshots records complete snapshots on the target that the Core
// does not know yet (after connecting or restoring).
func (s *Service) syncSnapshots(ctx context.Context, repo int64, r *Repo) error {
	list, err := r.ListSnapshots(ctx)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM backup_snapshots WHERE repo = ?`, repo)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		known[id] = true
	}
	rows.Close()
	for _, id := range list.Complete {
		if known[id] {
			continue
		}
		m, err := r.ReadManifest(ctx, id)
		if err != nil {
			// Recorded so that verification reports it.
			m = Manifest{ID: id, CreatedMS: s.now().UnixMilli()}
		}
		if err := insertSnapshot(ctx, s.db, repo, nil, m); err != nil {
			return err
		}
	}
	return nil
}

// SnapshotDetail returns a snapshot's manifest.
func (s *Service) SnapshotDetail(ctx context.Context, repo int64, id string) (Manifest, error) {
	if !ValidSnapshotID(id) {
		return Manifest{}, ErrNotFound
	}
	r, _, err := s.OpenRepository(ctx, repo)
	if err != nil {
		return Manifest{}, err
	}
	defer r.T.Close()
	m, err := r.ReadManifest(ctx, id)
	if errors.Is(err, ErrNotExist) {
		return m, ErrNotFound
	}
	return m, unavailable(err)
}

// ---- scheduling ----

// Run starts scheduled backups and verifications until ctx ends (AT-F14-04).
// Runs missed while the Core was down are made once on start.
func (s *Service) Run(ctx context.Context) {
	s.Tick(ctx)
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Tick(ctx)
		}
	}
}

// Tick enqueues every due plan and verification, and a pending platform
// restore.
func (s *Service) Tick(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if err := s.startPendingRestore(ctx); err != nil {
		s.log.Error("starting the platform restore failed", "error", err.Error())
	}
	plans, err := s.Plans(ctx)
	if err != nil {
		s.log.Error("backup scheduler", "error", err.Error())
		return
	}
	for _, p := range plans {
		if !p.Enabled {
			continue
		}
		sched, err := ParseSchedule(p.Schedule)
		if err != nil {
			continue
		}
		if p.Next == nil || p.Next.After(now) {
			if p.Next == nil {
				_, _ = s.db.ExecContext(ctx, `UPDATE backup_plans SET next_ms = ? WHERE id = ?`, sched.Next(now).UnixMilli(), p.ID)
			}
			continue
		}
		trigger := "schedule"
		if now.Sub(*p.Next) > 5*time.Minute {
			trigger = "catch-up"
			s.log.Warn("a scheduled backup was missed and runs now", "plan", p.Name, "due", p.Next.Format(time.RFC3339))
		}
		if _, err := s.StartBackup(ctx, Actor{Name: "system"}, p.ID, trigger); err != nil && !errors.Is(err, jobs.ErrDuplicate) {
			s.log.Error("starting a scheduled backup failed", "plan", p.Name, "error", err.Error())
		}
		_, _ = s.db.ExecContext(ctx, `UPDATE backup_plans SET next_ms = ? WHERE id = ?`, sched.Next(now).UnixMilli(), p.ID)
	}
	repos, err := s.Repositories(ctx)
	if err != nil {
		return
	}
	for _, r := range repos {
		sched, err := ParseSchedule(r.VerifySchedule)
		if err != nil || r.VerifyNext == nil || r.VerifyNext.After(now) {
			continue
		}
		if _, err := s.StartVerify(ctx, Actor{Name: "system"}, r.ID); err != nil && !errors.Is(err, jobs.ErrDuplicate) {
			s.log.Error("starting a scheduled verification failed", "repo", r.Name, "error", err.Error())
		}
		_, _ = s.db.ExecContext(ctx, `UPDATE backup_repos SET verify_next_ms = ? WHERE id = ?`, sched.Next(now).UnixMilli(), r.ID)
	}
}
