// Package certs manages TLS certificates per host (M13, ADR-0026): the
// internal CA and HTTP-01 stay with Caddy, DNS-01 runs here, uploaded
// certificates are validated here. Keys and credentials are stored
// encrypted; every change reaches Caddy through the network module and is
// stored only when Caddy accepted it.
package certs

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
)

// Host modes.
const (
	ModeInternal = "internal"
	ModeACME     = "acme"
	ModeDNS      = "dns"
	ModeCustom   = "custom"
)

// RenewBefore is how long before expiry DNS-01 certificates are renewed.
const RenewBefore = 30 * 24 * time.Hour

// Errors of the certificate service.
var (
	ErrNotFound = errors.New("not found")
	ErrInUse    = errors.New("the certificate is assigned to a host; assign another one first")
)

// ValidationError is invalid input.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{fmt.Sprintf(format, a...)} }

// Config holds test overrides from core.toml and the issuer.
type Config struct {
	// ACMEDirectory and ACMERoots replace Let's Encrypt (tests with Pebble).
	ACMEDirectory string
	ACMERoots     *x509.CertPool
	// UploadRoots replaces the system roots for uploads (tests).
	UploadRoots *x509.CertPool
	// Propagation is the wait between creating the TXT record and asking the CA to validate.
	Propagation time.Duration
	// Issuer obtains DNS-01 certificates; nil means ACME with the DNS providers.
	Issuer Issuer
	// Providers creates DNS providers; nil means the built-in ones.
	Providers func(name, credentials string) (DNSProvider, error)
}

// Service implements certificates.
type Service struct {
	db    *sql.DB
	box   *secretbox.Box
	net   *network.Service
	audit *audit.Log
	jobs  *jobs.Service
	wake  func()
	cfg   Config
	log   *slog.Logger
	now   func() time.Time
}

// New returns the service, registers its jobs and connects it to the proxy.
func New(db *sql.DB, box *secretbox.Box, net *network.Service, auditLog *audit.Log, js *jobs.Service, wake func(), cfg Config, log *slog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	s := &Service{db: db, box: box, net: net, audit: auditLog, jobs: js, wake: wake, cfg: cfg, log: log, now: now}
	if s.cfg.Providers == nil {
		s.cfg.Providers = builtinProvider
	}
	if s.cfg.Issuer == nil {
		s.cfg.Issuer = &acmeIssuer{s: s}
	}
	js.Register(jobs.Kind{Name: KindIssue, Plan: s.planIssue})
	net.SetTLS(func(ctx context.Context, hosts map[string]bool) (network.TLS, error) {
		return s.build(ctx, hosts, nil, nil)
	})
	return s
}

// ---- settings ----

// Settings are the ACME settings shown to admins (no secrets).
type Settings struct {
	Email         string    `json:"email"`
	CA            string    `json:"ca"`
	AgreedAt      time.Time `json:"agreed_at,omitzero"`
	DNSProvider   string    `json:"dns_provider"`
	DNSConfigured bool      `json:"dns_configured"`
}

// SettingsInput changes the settings. A nil token keeps the stored one; ""
// removes it.
type SettingsInput struct {
	Email           string  `json:"email"`
	CA              string  `json:"ca"`
	AgreeTOS        bool    `json:"agree_tos"`
	DNSProvider     string  `json:"dns_provider"`
	CloudflareToken *string `json:"cloudflare_token"`
}

type querier interface {
	QueryContext(ctx context.Context, q string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
}

func (s *Service) settings(ctx context.Context, q querier) (Settings, error) {
	var st Settings
	var agreed int64
	var creds []byte
	err := q.QueryRowContext(ctx, `SELECT email, ca, agreed_ms, dns_provider, dns_credentials FROM tls_settings WHERE id = 1`).Scan(&st.Email, &st.CA, &agreed, &st.DNSProvider, &creds)
	if agreed > 0 {
		st.AgreedAt = time.UnixMilli(agreed).UTC()
	}
	st.DNSConfigured = st.DNSProvider != "" && len(creds) > 0
	return st, err
}

func (st Settings) acmeReady() bool { return st.Email != "" && !st.AgreedAt.IsZero() }

// SetSettings stores the ACME and DNS settings (step-up in the handler).
func (s *Service) SetSettings(ctx context.Context, a network.Actor, in SettingsInput) (Settings, error) {
	in.Email = strings.TrimSpace(in.Email)
	if in.Email != "" && !proxy.ValidEmail(in.Email) {
		return Settings{}, invalid("%q is not a valid e-mail address", in.Email)
	}
	if in.CA == "" {
		in.CA = agentproto.ACMEProduction
	}
	if _, ok := proxy.ACMEDirectories[in.CA]; !ok {
		return Settings{}, invalid("ca must be production or staging")
	}
	if in.DNSProvider != "" && in.DNSProvider != "cloudflare" {
		return Settings{}, invalid("dns_provider must be empty or cloudflare")
	}
	cur, err := s.settings(ctx, s.db)
	if err != nil {
		return Settings{}, err
	}
	agreed := cur.AgreedAt
	if in.AgreeTOS && agreed.IsZero() {
		agreed = s.now()
	}
	if !in.AgreeTOS {
		agreed = time.Time{}
	}
	if (in.Email == "" || agreed.IsZero()) && s.hostsWithModes(ctx, ModeACME, ModeDNS) > 0 {
		return Settings{}, invalid("hosts use ACME; switch them to another mode before removing the e-mail address or the agreement")
	}
	var creds []byte
	setCreds := in.CloudflareToken != nil || in.DNSProvider == ""
	if in.CloudflareToken != nil && strings.TrimSpace(*in.CloudflareToken) != "" {
		if creds, err = s.box.Seal(strings.TrimSpace(*in.CloudflareToken), credsContext); err != nil {
			return Settings{}, err
		}
	}
	next := Settings{Email: in.Email, CA: in.CA, AgreedAt: agreed, DNSProvider: in.DNSProvider}
	write := func(tx *sql.Tx) error {
		var agreedMS int64
		if !agreed.IsZero() {
			agreedMS = agreed.UnixMilli()
		}
		if _, err := tx.ExecContext(ctx, `UPDATE tls_settings SET email = ?, ca = ?, agreed_ms = ?, agreed_by = CASE WHEN ? > 0 AND agreed_ms = 0 THEN ? ELSE agreed_by END, dns_provider = ? WHERE id = 1`,
			next.Email, next.CA, agreedMS, agreedMS, a.Name, next.DNSProvider); err != nil {
			return err
		}
		if setCreds {
			_, err := tx.ExecContext(ctx, `UPDATE tls_settings SET dns_credentials = ? WHERE id = 1`, creds)
			return err
		}
		return nil
	}
	details := []string{"email", next.Email, "ca", next.CA, "agreed", strconv.FormatBool(!agreed.IsZero()), "dns_provider", next.DNSProvider,
		"dns_credentials_changed", strconv.FormatBool(setCreds)}
	// Caddy's ACME issuer uses e-mail and CA: apply with the new values.
	err = s.net.ChangeTLS(ctx, a, "tls.settings", "tls", func(ctx context.Context, hosts map[string]bool) (network.TLS, error) {
		return s.build(ctx, hosts, nil, &next)
	}, write, details...)
	if err != nil {
		return Settings{}, err
	}
	return s.settings(ctx, s.db)
}

const credsContext = "tls/dns-credentials"

func (s *Service) hostsWithModes(ctx context.Context, modes ...string) int {
	var n int
	q := `SELECT count(*) FROM tls_hosts WHERE mode IN (?` + strings.Repeat(", ?", len(modes)-1) + `)`
	args := make([]any, len(modes))
	for i, m := range modes {
		args[i] = m
	}
	_ = s.db.QueryRowContext(ctx, q, args...).Scan(&n)
	return n
}

// ---- certificates ----

// Certificate is a stored certificate without its key.
type Certificate struct {
	ID        int64     `json:"id"`
	Source    string    `json:"source"`
	Names     []string  `json:"names"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	SHA256    string    `json:"sha256"`
	Hosts     []string  `json:"hosts"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Certificates lists the stored certificates with the hosts using them.
func (s *Service) Certificates(ctx context.Context) ([]Certificate, error) {
	return s.certificates(ctx)
}

func (s *Service) certificates(ctx context.Context) ([]Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT c.id, c.source, c.names, c.issuer, c.not_before_ms, c.not_after_ms, c.sha256, c.created_by, c.created_ms,
		COALESCE((SELECT json_group_array(h.host) FROM tls_hosts h WHERE h.certificate_id = c.id), '[]')
		FROM tls_certificates c ORDER BY c.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Certificate{}
	for rows.Next() {
		var c Certificate
		var names, hosts string
		var nb, na, created int64
		if err := rows.Scan(&c.ID, &c.Source, &names, &c.Issuer, &nb, &na, &c.SHA256, &c.CreatedBy, &created, &hosts); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(names), &c.Names)
		_ = json.Unmarshal([]byte(hosts), &c.Hosts)
		c.NotBefore, c.NotAfter, c.CreatedAt = time.UnixMilli(nb).UTC(), time.UnixMilli(na).UTC(), time.UnixMilli(created).UTC()
		out = append(out, c)
	}
	return out, rows.Err()
}

func keyContext(id int64) string { return "tls/key/" + strconv.FormatInt(id, 10) }

// store saves a validated certificate; the key is encrypted with its ID as
// associated data.
func (s *Service) store(ctx context.Context, tx *sql.Tx, a network.Actor, source string, kp proxy.KeyPair, chainPEM, keyPEM string) (int64, error) {
	info := kp.Info()
	names, _ := json.Marshal(info.Names)
	res, err := tx.ExecContext(ctx, `INSERT INTO tls_certificates (source, names, issuer, not_before_ms, not_after_ms, sha256, chain_pem, key, created_by, created_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, x'', ?, ?)`, source, string(names), info.Issuer, info.NotBefore.UnixMilli(), info.NotAfter.UnixMilli(), info.SHA256, chainPEM, a.Name, s.now().UnixMilli())
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	sealed, err := s.box.Seal(keyPEM, keyContext(id))
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE tls_certificates SET key = ? WHERE id = ?`, sealed, id)
	return id, err
}

// Upload validates and stores a certificate (AT-F12-03). It is not used
// until it is assigned to a host.
func (s *Service) Upload(ctx context.Context, a network.Actor, certPEM, keyPEM string) (Certificate, error) {
	kp, err := proxy.ValidateUpload(certPEM, keyPEM, s.now(), s.cfg.UploadRoots)
	var ie *proxy.InvalidError
	if errors.As(err, &ie) {
		_ = s.audit.Record(context.WithoutCancel(ctx), event(a, "tls.certificate_upload", "tls", audit.Failure, "error", ie.Msg))
		return Certificate{}, invalid("%s", ie.Msg)
	}
	if err != nil {
		return Certificate{}, err
	}
	var id int64
	err = withTx(ctx, s.db, func(tx *sql.Tx) error {
		if id, err = s.store(ctx, tx, a, "upload", kp, certPEM, keyPEM); err != nil {
			return err
		}
		info := kp.Info()
		_, err := audit.Append(ctx, tx, s.now(), event(a, "tls.certificate_upload", "certificate:"+strconv.FormatInt(id, 10), audit.Success,
			"names", strings.Join(info.Names, ","), "issuer", info.Issuer, "sha256", info.SHA256, "not_after", info.NotAfter.Format(time.RFC3339)))
		return err
	})
	if err != nil {
		return Certificate{}, err
	}
	return s.certificate(ctx, id)
}

func (s *Service) certificate(ctx context.Context, id int64) (Certificate, error) {
	all, err := s.certificates(ctx)
	if err != nil {
		return Certificate{}, err
	}
	for _, c := range all {
		if c.ID == id {
			return c, nil
		}
	}
	return Certificate{}, ErrNotFound
}

// DeleteCertificate removes an unassigned certificate.
func (s *Service) DeleteCertificate(ctx context.Context, a network.Actor, id int64) error {
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM tls_hosts WHERE certificate_id = ?`, id).Scan(&n); err != nil {
			return err
		}
		if n > 0 {
			return ErrInUse
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM tls_certificates WHERE id = ?`, id)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		_, err = audit.Append(ctx, tx, s.now(), event(a, "tls.certificate_delete", "certificate:"+strconv.FormatInt(id, 10), audit.Success))
		return err
	})
}

// ---- hosts ----

// HostTLS is a host with its TLS settings.
type HostTLS struct {
	network.Host
	Mode          string `json:"mode"`
	CertificateID int64  `json:"certificate_id,omitempty"`
	// Effective is what Caddy uses: a dns host uses the internal CA until
	// its first certificate is issued.
	Effective string    `json:"effective"`
	Error     string    `json:"error,omitempty"`
	ErrorAt   time.Time `json:"error_at,omitzero"`
}

type hostRow struct {
	mode    string
	certID  sql.NullInt64
	err     string
	errorMS int64
}

func (s *Service) hostRows(ctx context.Context, q querier) (map[string]hostRow, error) {
	rows, err := q.QueryContext(ctx, `SELECT host, mode, certificate_id, error, error_ms FROM tls_hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]hostRow{}
	for rows.Next() {
		var h string
		var r hostRow
		if err := rows.Scan(&h, &r.mode, &r.certID, &r.err, &r.errorMS); err != nil {
			return nil, err
		}
		out[h] = r
	}
	return out, rows.Err()
}

func effective(r hostRow) string {
	switch {
	case r.mode == ModeACME:
		return ModeACME
	case (r.mode == ModeDNS || r.mode == ModeCustom) && r.certID.Valid:
		return r.mode
	default:
		return ModeInternal
	}
}

// Hosts lists the hosts with their TLS settings.
func (s *Service) Hosts(ctx context.Context) ([]HostTLS, error) {
	hosts, err := s.net.Hosts(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := s.hostRows(ctx, s.db)
	if err != nil {
		return nil, err
	}
	out := make([]HostTLS, len(hosts))
	for i, h := range hosts {
		r, ok := rows[h.Host]
		if !ok {
			r.mode = ModeInternal
		}
		out[i] = HostTLS{Host: h, Mode: r.mode, CertificateID: r.certID.Int64, Effective: effective(r), Error: r.err}
		if r.errorMS > 0 {
			out[i].ErrorAt = time.UnixMilli(r.errorMS).UTC()
		}
	}
	return out, nil
}

// HostInput selects a host's mode.
type HostInput struct {
	Mode          string `json:"mode"`
	CertificateID int64  `json:"certificate_id"`
}

// privateSuffixes never get public certificates (RFC 6761/6762/8375 and
// common LAN conventions).
var privateSuffixes = []string{"localhost", "local", "lan", "home", "internal", "intranet", "corp", "private", "invalid", "home.arpa"}

// publicName reports whether a public CA can issue a certificate for host.
func publicName(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil || !strings.Contains(host, ".") {
		return false
	}
	for _, s := range privateSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return false
		}
	}
	return true
}

// SetHost changes a host's mode; dns starts an issuance job.
func (s *Service) SetHost(ctx context.Context, a network.Actor, host string, in HostInput) (HostTLS, int64, error) {
	hosts, err := s.net.Hosts(ctx)
	if err != nil {
		return HostTLS{}, 0, err
	}
	var h *network.Host
	for i := range hosts {
		if hosts[i].Host == host {
			h = &hosts[i]
		}
	}
	if h == nil {
		return HostTLS{}, 0, ErrNotFound
	}
	st, err := s.settings(ctx, s.db)
	if err != nil {
		return HostTLS{}, 0, err
	}
	rows, err := s.hostRows(ctx, s.db)
	if err != nil {
		return HostTLS{}, 0, err
	}
	next := hostRow{mode: in.Mode}
	switch in.Mode {
	case ModeInternal:
	case ModeACME:
		switch {
		case !st.acmeReady():
			return HostTLS{}, 0, invalid("set an e-mail address and accept Let's Encrypt's subscriber agreement first")
		case !publicName(host):
			return HostTLS{}, 0, invalid("%s is not a public host name; use the internal CA or an own certificate", host)
		case h.LANOnly:
			return HostTLS{}, 0, invalid("%s has a LAN-only route; HTTP-01 needs the host to be reachable from the internet (use DNS-01 instead)", host)
		}
	case ModeDNS:
		switch {
		case !st.acmeReady():
			return HostTLS{}, 0, invalid("set an e-mail address and accept Let's Encrypt's subscriber agreement first")
		case !st.DNSConfigured:
			return HostTLS{}, 0, invalid("configure a DNS provider first")
		case !publicName(host):
			return HostTLS{}, 0, invalid("%s is not a public host name; DNS-01 needs a domain in your DNS zone", host)
		}
		// Keep a certificate issued earlier for this host until a new one exists.
		if cur := rows[host]; cur.mode == ModeDNS && cur.certID.Valid {
			next.certID = cur.certID
		}
	case ModeCustom:
		ok, err := s.covers(ctx, in.CertificateID, host)
		if err != nil {
			return HostTLS{}, 0, err
		}
		if !ok {
			return HostTLS{}, 0, invalid("certificate %d does not cover %s", in.CertificateID, host)
		}
		next.certID = sql.NullInt64{Int64: in.CertificateID, Valid: true}
	default:
		return HostTLS{}, 0, invalid("mode must be internal, acme, dns or custom")
	}
	var job int64
	write := func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO tls_hosts (host, mode, certificate_id, updated_ms) VALUES (?, ?, ?, ?)
			ON CONFLICT (host) DO UPDATE SET mode = excluded.mode, certificate_id = excluded.certificate_id, error = '', error_ms = 0, updated_ms = excluded.updated_ms`,
			host, next.mode, next.certID, s.now().UnixMilli()); err != nil {
			return err
		}
		if next.mode == ModeDNS && !next.certID.Valid {
			var err error
			job, err = s.jobs.EnqueueTx(ctx, tx, jobs.Request{Kind: KindIssue, Payload: issuePayload{Host: host, Actor: a.Name}, CreatedBy: a.ID, DedupeKey: KindIssue + ":" + host})
			if errors.Is(err, jobs.ErrDuplicate) {
				return nil
			}
			return err
		}
		return nil
	}
	err = s.net.ChangeTLS(ctx, a, "tls.host", "host:"+host, func(ctx context.Context, hosts map[string]bool) (network.TLS, error) {
		return s.stateWith(ctx, hosts, host, next)
	}, write, "mode", next.mode, "certificate", strconv.FormatInt(next.certID.Int64, 10))
	if err != nil {
		return HostTLS{}, 0, err
	}
	if job > 0 {
		s.wake()
	}
	all, err := s.Hosts(ctx)
	if err != nil {
		return HostTLS{}, 0, err
	}
	for _, x := range all {
		if x.Host.Host == host {
			return x, job, nil
		}
	}
	return HostTLS{}, job, ErrNotFound
}

func (s *Service) covers(ctx context.Context, id int64, host string) (bool, error) {
	var chain string
	err := s.db.QueryRowContext(ctx, `SELECT chain_pem FROM tls_certificates WHERE id = ?`, id).Scan(&chain)
	if errors.Is(err, sql.ErrNoRows) {
		return false, invalid("certificate %d does not exist", id)
	}
	if err != nil {
		return false, err
	}
	c, err := leafOf(chain)
	if err != nil {
		return false, err
	}
	return proxy.Covers(c, host), nil
}

// ---- the proxy's TLS configuration ----

// stateWith is state with one host's row replaced (a pending change).
func (s *Service) stateWith(ctx context.Context, hosts map[string]bool, host string, r hostRow) (network.TLS, error) {
	return s.build(ctx, hosts, func(rows map[string]hostRow) { rows[host] = r }, nil)
}

// build returns the TLS settings for the proxy; mod changes host rows and
// settings replaces the stored ACME settings (pending changes).
func (s *Service) build(ctx context.Context, hosts map[string]bool, mod func(map[string]hostRow), settings *Settings) (network.TLS, error) {
	rows, err := s.hostRows(ctx, s.db)
	if err != nil {
		return network.TLS{}, err
	}
	if mod != nil {
		mod(rows)
	}
	st := settings
	if st == nil {
		cur, err := s.settings(ctx, s.db)
		if err != nil {
			return network.TLS{}, err
		}
		st = &cur
	}
	var t network.TLS
	if st.acmeReady() {
		t.ACME = &agentproto.ACMESettings{Email: st.Email, CA: st.CA}
	}
	certs := map[int64]bool{}
	for host, r := range rows {
		if !hosts[host] {
			continue // the host lost its last route
		}
		switch effective(r) {
		case ModeACME:
			t.Hosts = append(t.Hosts, agentproto.TLSHost{Host: host, Mode: agentproto.TLSACME})
		case ModeDNS, ModeCustom:
			t.Hosts = append(t.Hosts, agentproto.TLSHost{Host: host, Mode: agentproto.TLSLoaded, CertificateID: r.certID.Int64})
			certs[r.certID.Int64] = true
		}
	}
	for id := range certs {
		var chain string
		var sealed []byte
		if err := s.db.QueryRowContext(ctx, `SELECT chain_pem, key FROM tls_certificates WHERE id = ?`, id).Scan(&chain, &sealed); err != nil {
			return network.TLS{}, err
		}
		key, err := s.box.Open(sealed, keyContext(id))
		if err != nil {
			return network.TLS{}, fmt.Errorf("certificate %d: %w", id, err)
		}
		t.Certificates = append(t.Certificates, agentproto.TLSCertificate{ID: id, CertificatePEM: chain, KeyPEM: key})
	}
	return t, nil
}

// Root returns the internal CA's root certificate.
func (s *Service) Root(ctx context.Context, a network.Actor) (agentproto.ProxyCA, error) {
	return s.net.CA(ctx, a)
}

// ---- helpers ----

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

func event(a network.Actor, action, target string, result audit.Result, kv ...string) audit.Event {
	ev := audit.Event{ActorID: a.ID, Actor: a.Name, Action: action, Target: target, RequestID: a.RequestID, IP: a.IP, Result: result, Details: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			ev.Details[kv[i]] = kv[i+1]
		}
	}
	return ev
}
