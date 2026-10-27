// Package identity implements users, password authentication, server-side
// sessions, CSRF protection and first-run setup (M2).
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

// Config configures the service.
type Config struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
	SetupTokenTTL   time.Duration
	// Origin is the normalized public origin; its scheme decides whether the
	// session cookie is Secure.
	Origin string
	Hash   HashParams
}

// Account lockout parameters (AT-F08-02).
const (
	lockoutThreshold = 5
	lockoutBase      = time.Minute
	lockoutMax       = time.Hour

	// lastSeenGranularity limits session writes on busy clients.
	lastSeenGranularity = time.Minute
)

// Service is the identity service.
type Service struct {
	db        *sql.DB
	audit     *audit.Log
	cfg       Config
	log       *slog.Logger
	now       func() time.Time
	limiter   *limiter
	hashSem   chan struct{}
	dummyHash string
}

// New creates the service. now may be nil (time.Now).
func New(db *sql.DB, auditLog *audit.Log, cfg Config, log *slog.Logger, now func() time.Time) (*Service, error) {
	if now == nil {
		now = time.Now
	}
	if cfg.Hash == (HashParams{}) {
		cfg.Hash = DefaultHashParams
	}
	s := &Service{
		db:      db,
		audit:   auditLog,
		cfg:     cfg,
		log:     log,
		now:     now,
		limiter: newLimiter(10, 6*time.Second, now),
		hashSem: make(chan struct{}, 2),
	}
	h, err := hashPassword(cfg.Hash, randomToken(16))
	if err != nil {
		return nil, err
	}
	s.dummyHash = h
	return s, nil
}

// Meta describes the request on whose behalf an operation runs.
type Meta struct {
	RequestID string
	IP        string
	UserAgent string
}

// User is an account.
type User struct {
	ID          int64      `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Role        authz.Role `json:"role"`
	Disabled    bool       `json:"disabled"`
	Locked      bool       `json:"locked"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// Session is a server-side login session.
type Session struct {
	ID                string    `json:"id"`
	UserID            int64     `json:"-"`
	CSRFToken         string    `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	IdleExpiresAt     time.Time `json:"idle_expires_at"`
	AbsoluteExpiresAt time.Time `json:"absolute_expires_at"`
	IP                string    `json:"ip"`
	UserAgent         string    `json:"user_agent"`
}

// Principal is an authenticated user with the session used.
type Principal struct {
	User    User
	Session Session
}

// Has reports whether the principal holds p.
func (p *Principal) Has(perm authz.Permission) bool { return p.User.Role.Has(perm) }

type principalKey struct{}

// FromContext returns the authenticated principal, if any.
func FromContext(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(*Principal)
	return p, ok
}

func withPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

func randomToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("identity: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("identity: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func ms(t time.Time) int64           { return t.UnixMilli() }
func fromMS(v int64) time.Time       { return time.UnixMilli(v).UTC() }
func (s *Service) nowMS() int64      { return ms(s.now()) }
func targetUser(id int64) string     { return "user:" + itoa(id) }
func targetSession(id string) string { return "session:" + id }

// hash computes a password hash, bounding concurrent Argon2 computations.
func (s *Service) hash(ctx context.Context, password string) (string, error) {
	if err := s.acquire(ctx); err != nil {
		return "", err
	}
	defer s.release()
	return hashPassword(s.cfg.Hash, password)
}

func (s *Service) verify(ctx context.Context, encoded, password string) (bool, error) {
	if err := s.acquire(ctx); err != nil {
		return false, err
	}
	defer s.release()
	return verifyPassword(encoded, password)
}

func (s *Service) acquire(ctx context.Context) error {
	select {
	case s.hashSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Service) release() { <-s.hashSem }

// record writes an audit event in its own transaction; failures are logged
// because the triggering operation has already been decided.
func (s *Service) record(ctx context.Context, ev audit.Event) {
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.ErrorContext(ctx, "audit write failed", "action", ev.Action, "error", err.Error())
	}
}

func actorEvent(p *Principal, m Meta, action, target string, result audit.Result) audit.Event {
	ev := audit.Event{Action: action, Target: target, Result: result, RequestID: m.RequestID, IP: m.IP}
	if p != nil {
		ev.ActorID = p.User.ID
		ev.Actor = p.User.Username
	}
	return ev
}

// withTx runs f in a write transaction.
func (s *Service) withTx(ctx context.Context, f func(tx *sql.Tx) error) error {
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
