package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/network"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
)

// KindIssue obtains a certificate for one host through DNS-01.
const KindIssue = "tls.issue"

type issuePayload struct {
	Host  string `json:"host"`
	Actor string `json:"actor"`
}

// Issuer obtains a certificate chain and key for host through DNS-01.
type Issuer interface {
	Issue(ctx context.Context, host string) (chainPEM, keyPEM string, err error)
}

// DNSProvider creates and removes the TXT record of a DNS-01 challenge.
type DNSProvider interface {
	Present(ctx context.Context, fqdn, value string) error
	CleanUp(ctx context.Context, fqdn, value string) error
}

func builtinProvider(name, credentials string) (DNSProvider, error) {
	switch name {
	case "cloudflare":
		return newCloudflare(credentials, cloudflareAPI), nil
	default:
		return nil, fmt.Errorf("no DNS provider is configured")
	}
}

func leafOf(chain string) (*x509.Certificate, error) {
	b, _ := pem.Decode([]byte(chain))
	if b == nil {
		return nil, errors.New("stored certificate is not PEM")
	}
	return x509.ParseCertificate(b.Bytes)
}

func (s *Service) planIssue(raw json.RawMessage) ([]jobs.Step, error) {
	var p issuePayload
	if err := json.Unmarshal(raw, &p); err != nil || p.Host == "" {
		return nil, jobs.Permanent(errors.New("invalid payload"))
	}
	return []jobs.Step{{
		Name: "obtain a certificate for " + p.Host + " through DNS-01",
		Run: func(ctx context.Context, sc *jobs.StepContext) error {
			return s.issue(ctx, sc, p)
		},
	}}, nil
}

func (s *Service) issue(ctx context.Context, sc *jobs.StepContext, p issuePayload) error {
	a := network.Actor{Name: p.Actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}
	var mode string
	var oldID sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT mode, certificate_id FROM tls_hosts WHERE host = ?`, p.Host).Scan(&mode, &oldID)
	if errors.Is(err, sql.ErrNoRows) || err == nil && mode != ModeDNS {
		sc.Logf("%s no longer uses DNS-01; nothing to do", p.Host)
		return nil
	}
	if err != nil {
		return err
	}
	fail := func(err error) error {
		_, _ = s.db.ExecContext(context.WithoutCancel(ctx), `UPDATE tls_hosts SET error = ?, error_ms = ? WHERE host = ?`, truncate(err.Error(), 500), s.now().UnixMilli(), p.Host)
		_ = s.audit.Record(context.WithoutCancel(ctx), event(a, "tls.issue", "host:"+p.Host, audit.Failure, "error", truncate(err.Error(), 500)))
		return err
	}
	ictx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	chain, key, err := s.cfg.Issuer.Issue(ictx, p.Host)
	if err != nil {
		return fail(err)
	}
	kp, err := proxy.ParseKeyPair(chain, key)
	if err == nil && !proxy.Covers(kp.Leaf, p.Host) {
		err = fmt.Errorf("the CA issued a certificate that does not cover %s", p.Host)
	}
	if err != nil {
		return fail(jobs.Permanent(err))
	}
	var id int64
	if err := withTx(ctx, s.db, func(tx *sql.Tx) error {
		id, err = s.store(ctx, tx, a, "dns", kp, chain, key)
		return err
	}); err != nil {
		return err
	}
	info := kp.Info()
	next := hostRow{mode: ModeDNS, certID: sql.NullInt64{Int64: id, Valid: true}}
	err = s.net.ChangeTLS(ctx, a, "tls.issue", "host:"+p.Host, func(ctx context.Context, hosts map[string]bool) (network.TLS, error) {
		return s.stateWith(ctx, hosts, p.Host, next)
	}, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE tls_hosts SET certificate_id = ?, error = '', error_ms = 0, updated_ms = ? WHERE host = ? AND mode = 'dns'`,
			id, s.now().UnixMilli(), p.Host); err != nil {
			return err
		}
		// The previous DNS-01 certificate of this host is no longer needed.
		if oldID.Valid {
			_, err := tx.ExecContext(ctx, `DELETE FROM tls_certificates WHERE id = ? AND source = 'dns' AND NOT EXISTS (SELECT 1 FROM tls_hosts WHERE certificate_id = ?)`, oldID.Int64, oldID.Int64)
			return err
		}
		return nil
	}, "certificate", fmt.Sprint(id), "not_after", info.NotAfter.Format(time.RFC3339), "issuer", info.Issuer)
	if err != nil {
		_, _ = s.db.ExecContext(context.WithoutCancel(ctx), `DELETE FROM tls_certificates WHERE id = ? AND NOT EXISTS (SELECT 1 FROM tls_hosts WHERE certificate_id = ?)`, id, id)
		return fail(err)
	}
	sc.Logf("issued by %s, valid until %s", info.Issuer, info.NotAfter.Format(time.RFC3339))
	return nil
}

// EnqueueRenewals queues DNS-01 issuance for hosts without a certificate or
// whose certificate expires within RenewBefore.
func (s *Service) EnqueueRenewals(ctx context.Context) (int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT h.host FROM tls_hosts h LEFT JOIN tls_certificates c ON c.id = h.certificate_id
		WHERE h.mode = 'dns' AND (c.id IS NULL OR c.not_after_ms < ?)`, s.now().Add(RenewBefore).UnixMilli())
	if err != nil {
		return 0, err
	}
	var hosts []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return 0, err
		}
		hosts = append(hosts, h)
	}
	rows.Close()
	n := 0
	for _, h := range hosts {
		_, err := s.jobs.Enqueue(ctx, jobs.Request{Kind: KindIssue, Payload: issuePayload{Host: h, Actor: "system"}, DedupeKey: KindIssue + ":" + h})
		if err != nil && !errors.Is(err, jobs.ErrDuplicate) {
			return n, err
		}
		if err == nil {
			n++
		}
	}
	return n, nil
}

// Renew queues DNS-01 issuance for one host now.
func (s *Service) Renew(ctx context.Context, a network.Actor, host string) (int64, error) {
	var mode string
	err := s.db.QueryRowContext(ctx, `SELECT mode FROM tls_hosts WHERE host = ?`, host).Scan(&mode)
	if errors.Is(err, sql.ErrNoRows) || err == nil && mode != ModeDNS {
		return 0, invalid("%s does not use DNS-01", host)
	}
	if err != nil {
		return 0, err
	}
	id, err := s.jobs.Enqueue(ctx, jobs.Request{Kind: KindIssue, Payload: issuePayload{Host: host, Actor: a.Name}, CreatedBy: a.ID, DedupeKey: KindIssue + ":" + host})
	if errors.Is(err, jobs.ErrDuplicate) {
		return 0, invalid("a certificate for %s is already being obtained", host)
	}
	if err == nil {
		s.wake()
	}
	return id, err
}

// ---- ACME DNS-01 with golang.org/x/crypto/acme ----

type acmeIssuer struct{ s *Service }

const accountContext = "tls/acme-account"

func (s *Service) directory(ca string) string {
	if s.cfg.ACMEDirectory != "" {
		return s.cfg.ACMEDirectory
	}
	return proxy.ACMEDirectories[ca]
}

// accountKey returns the account key for dir, creating one when the
// directory changed (production and staging have separate accounts).
func (s *Service) accountKey(ctx context.Context, dir string) (*ecdsa.PrivateKey, error) {
	var sealed []byte
	var stored string
	if err := s.db.QueryRowContext(ctx, `SELECT account_key, account_dir FROM tls_settings WHERE id = 1`).Scan(&sealed, &stored); err != nil {
		return nil, err
	}
	if len(sealed) > 0 && stored == dir {
		p, err := s.box.Open(sealed, accountContext)
		if err != nil {
			return nil, err
		}
		k, err := x509.ParseECPrivateKey([]byte(p))
		if err != nil {
			return nil, err
		}
		return k, nil
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		return nil, err
	}
	if sealed, err = s.box.Seal(string(der), accountContext); err != nil {
		return nil, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE tls_settings SET account_key = ?, account_dir = ?, account_url = '' WHERE id = 1`, sealed, dir)
	return k, err
}

func (i *acmeIssuer) Issue(ctx context.Context, host string) (string, string, error) {
	s := i.s
	st, err := s.settings(ctx, s.db)
	if err != nil {
		return "", "", err
	}
	if !st.acmeReady() || !st.DNSConfigured {
		return "", "", errors.New("ACME or the DNS provider is not configured")
	}
	var sealed []byte
	if err := s.db.QueryRowContext(ctx, `SELECT dns_credentials FROM tls_settings WHERE id = 1`).Scan(&sealed); err != nil {
		return "", "", err
	}
	creds, err := s.box.Open(sealed, credsContext)
	if err != nil {
		return "", "", err
	}
	provider, err := s.cfg.Providers(st.DNSProvider, creds)
	if err != nil {
		return "", "", err
	}
	dir := s.directory(st.CA)
	key, err := s.accountKey(ctx, dir)
	if err != nil {
		return "", "", err
	}
	hc := &http.Client{Timeout: time.Minute}
	if s.cfg.ACMERoots != nil {
		hc.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.cfg.ACMERoots}}
	}
	client := &acme.Client{Key: key, DirectoryURL: dir, HTTPClient: hc, UserAgent: "kernhaven"}
	if _, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:" + st.Email}}, acme.AcceptTOS); err != nil && !errors.Is(err, acme.ErrAccountAlreadyExists) {
		return "", "", fmt.Errorf("ACME account: %w", err)
	}
	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(host))
	if err != nil {
		return "", "", fmt.Errorf("ACME order: %w", err)
	}
	for _, u := range order.AuthzURLs {
		z, err := client.GetAuthorization(ctx, u)
		if err != nil {
			return "", "", err
		}
		if z.Status == acme.StatusValid {
			continue
		}
		var chal *acme.Challenge
		for _, c := range z.Challenges {
			if c.Type == "dns-01" {
				chal = c
			}
		}
		if chal == nil {
			return "", "", errors.New("the CA offers no DNS-01 challenge")
		}
		value, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return "", "", err
		}
		fqdn := "_acme-challenge." + z.Identifier.Value
		if err := provider.Present(ctx, fqdn, value); err != nil {
			return "", "", fmt.Errorf("DNS record %s: %w", fqdn, err)
		}
		defer func() { _ = provider.CleanUp(context.WithoutCancel(ctx), fqdn, value) }()
		if err := sleep(ctx, s.cfg.Propagation); err != nil {
			return "", "", err
		}
		if _, err := client.Accept(ctx, chal); err != nil {
			return "", "", err
		}
		if _, err := client.WaitAuthorization(ctx, z.URI); err != nil {
			return "", "", fmt.Errorf("DNS-01 validation of %s: %w", host, err)
		}
	}
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		return "", "", err
	}
	if ready.FinalizeURL != "" {
		order.FinalizeURL = ready.FinalizeURL
	}
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, certKey)
	if err != nil {
		return "", "", err
	}
	// CreateCertFromOrder polls the order URL instead of relying on a Location header.
	ders, _, err := client.CreateCertFromOrder(ctx, order, csr, true)
	if err != nil {
		return "", "", fmt.Errorf("ACME certificate: %w", err)
	}
	var chain strings.Builder
	for _, d := range ders {
		_ = pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: d})
	}
	der, err := x509.MarshalPKCS8PrivateKey(certKey)
	if err != nil {
		return "", "", err
	}
	return chain.String(), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
