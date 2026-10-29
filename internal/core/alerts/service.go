// Package alerts evaluates alert rules and delivers notifications through
// SMTP, webhooks, ntfy and Gotify (M15, ADR-0028). Alerts are recorded even
// when no channel is configured; deliveries are retried with backoff,
// deduplicated per alert and rate-limited per channel.
package alerts

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
)

// Delivery limits (AT-F16-03).
const (
	MaxAttempts    = 6           // first try plus retries after 1, 2, 4, 8, 16 minutes
	RetryBase      = time.Minute // doubled per attempt
	RatePerHour    = 20          // deliveries per channel and hour
	DeliveryWindow = 30 * 24 * time.Hour
)

// Errors of the alerts API.
var (
	ErrNotFound = errors.New("not found")
	ErrExists   = errors.New("a channel with this name exists")
)

// ValidationError is invalid input.
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{fmt.Sprintf(format, a...)} }

// Actor performs a change.
type Actor struct {
	ID        int64
	Name      string
	RequestID string
	IP        string
}

// Service implements alerts and notifications.
type Service struct {
	db       *sql.DB
	box      *secretbox.Box
	audit    *audit.Log
	sender   Sender
	src      Sources
	instance string
	log      *slog.Logger
	now      func() time.Time

	mu        sync.Mutex // one evaluation or delivery round at a time
	downCount map[string]int
	logins    []time.Time
	lastBurst time.Time
	lastChain time.Time
	chainOK   bool
	lastPrune time.Time
}

// New returns the service. instance names this Kernhaven in messages.
func New(db *sql.DB, box *secretbox.Box, auditLog *audit.Log, sender Sender, src Sources, instance string, log *slog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, box: box, audit: auditLog, sender: sender, src: src, instance: instance, log: log, now: now, downCount: map[string]int{}, chainOK: true}
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

// ---- channels ----

// Channel is a notification channel without its secret.
type Channel struct {
	ID        int64         `json:"id"`
	Name      string        `json:"name"`
	Kind      string        `json:"kind"`
	Config    ChannelConfig `json:"config"`
	HasSecret bool          `json:"has_secret"`
	Enabled   bool          `json:"enabled"`
	CreatedBy string        `json:"created_by"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// ChannelInput creates or replaces a channel. A nil Secret keeps the stored
// one; "" removes it.
type ChannelInput struct {
	Name    string        `json:"name"`
	Kind    string        `json:"kind"`
	Config  ChannelConfig `json:"config"`
	Secret  *string       `json:"secret"`
	Enabled *bool         `json:"enabled"`
}

const channelColumns = `id, name, kind, config, secret IS NOT NULL AND length(secret) > 0, enabled, created_by, created_ms, updated_ms`

type rowScanner interface{ Scan(...any) error }

func scanChannel(r rowScanner) (Channel, error) {
	var c Channel
	var cfg string
	var created, updated int64
	err := r.Scan(&c.ID, &c.Name, &c.Kind, &cfg, &c.HasSecret, &c.Enabled, &c.CreatedBy, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(cfg), &c.Config)
	c.CreatedAt, c.UpdatedAt = time.UnixMilli(created).UTC(), time.UnixMilli(updated).UTC()
	return c, nil
}

// Channels lists the channels.
func (s *Service) Channels(ctx context.Context) ([]Channel, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+channelColumns+` FROM notify_channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Service) channel(ctx context.Context, id int64) (Channel, error) {
	return scanChannel(s.db.QueryRowContext(ctx, `SELECT `+channelColumns+` FROM notify_channels WHERE id = ?`, id))
}

func secretContext(id int64) string { return "alerts/channel/" + strconv.FormatInt(id, 10) }

func (s *Service) secret(ctx context.Context, id int64) (string, error) {
	var sealed []byte
	if err := s.db.QueryRowContext(ctx, `SELECT secret FROM notify_channels WHERE id = ?`, id).Scan(&sealed); err != nil {
		return "", err
	}
	if len(sealed) == 0 {
		return "", nil
	}
	return s.box.Open(sealed, secretContext(id))
}

// SaveChannel creates (id 0) or replaces a channel.
func (s *Service) SaveChannel(ctx context.Context, a Actor, id int64, in ChannelInput) (Channel, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 64 {
		return Channel{}, invalid("name must be 1 to 64 characters")
	}
	hasSecret := in.Secret != nil && *in.Secret != ""
	if id != 0 {
		cur, err := s.channel(ctx, id)
		if err != nil {
			return Channel{}, err
		}
		if in.Kind != cur.Kind {
			return Channel{}, invalid("the kind of a channel cannot change")
		}
		if in.Secret == nil {
			hasSecret = cur.HasSecret
		}
	}
	if err := validate(in.Kind, &in.Config, hasSecret); err != nil {
		return Channel{}, invalid("%s", err.Error())
	}
	// Refuse a forbidden literal address now; names are checked at every connection.
	host := in.Config.Host
	if u, err := url.Parse(in.Config.URL); in.Kind != KindSMTP && err == nil {
		host = u.Hostname()
	}
	if a, err := netip.ParseAddr(host); err == nil && !s.sender.Guard.Allowed(a) {
		return Channel{}, invalid("%s is a loopback, link-local or multicast address, which Kernhaven does not contact", host)
	}
	if in.Kind == KindGotify && !hasSecret {
		return Channel{}, invalid("Gotify needs an application token")
	}
	enabled := in.Enabled == nil || *in.Enabled
	cfg, _ := json.Marshal(in.Config)
	now := s.now().UnixMilli()
	target := "channel:" + in.Name
	err := withTx(ctx, s.db, func(tx *sql.Tx) error {
		if id == 0 {
			res, err := tx.ExecContext(ctx, `INSERT INTO notify_channels (name, kind, config, enabled, created_by, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				in.Name, in.Kind, string(cfg), enabled, a.Name, now, now)
			if err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					return ErrExists
				}
				return err
			}
			id, _ = res.LastInsertId()
		} else {
			if _, err := tx.ExecContext(ctx, `UPDATE notify_channels SET name = ?, config = ?, enabled = ?, updated_ms = ? WHERE id = ?`, in.Name, string(cfg), enabled, now, id); err != nil {
				if strings.Contains(err.Error(), "UNIQUE") {
					return ErrExists
				}
				return err
			}
		}
		if in.Secret != nil {
			var sealed []byte
			if *in.Secret != "" {
				var err error
				if sealed, err = s.box.Seal(*in.Secret, secretContext(id)); err != nil {
					return err
				}
			}
			if _, err := tx.ExecContext(ctx, `UPDATE notify_channels SET secret = ? WHERE id = ?`, sealed, id); err != nil {
				return err
			}
		}
		dest := in.Config.URL
		if in.Kind == KindSMTP {
			dest = in.Config.Host + ":" + strconv.Itoa(in.Config.Port)
		}
		_, err := audit.Append(ctx, tx, s.now(), s.event(a, "notify.channel_save", target, nil, "kind", in.Kind, "destination", dest,
			"secret_changed", strconv.FormatBool(in.Secret != nil), "enabled", strconv.FormatBool(enabled)))
		return err
	})
	if err != nil {
		return Channel{}, err
	}
	return s.channel(ctx, id)
}

// DeleteChannel removes a channel and takes it out of every rule.
func (s *Service) DeleteChannel(ctx context.Context, a Actor, id int64) error {
	c, err := s.channel(ctx, id)
	if err != nil {
		return err
	}
	rules, err := s.Rules(ctx)
	if err != nil {
		return err
	}
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM notify_channels WHERE id = ?`, id); err != nil {
			return err
		}
		for _, r := range rules {
			keep := []int64{}
			for _, ch := range r.Channels {
				if ch != id {
					keep = append(keep, ch)
				}
			}
			if len(keep) != len(r.Channels) {
				b, _ := json.Marshal(keep)
				if _, err := tx.ExecContext(ctx, `UPDATE alert_rules SET channels = ? WHERE rule = ?`, string(b), r.Rule); err != nil {
					return err
				}
			}
		}
		_, err := audit.Append(ctx, tx, s.now(), s.event(a, "notify.channel_delete", "channel:"+c.Name, nil, "kind", c.Kind))
		return err
	})
}

// ---- rules ----

// Rule is an alert rule.
type Rule struct {
	Rule     string             `json:"rule"`
	Title    string             `json:"title"`
	Enabled  bool               `json:"enabled"`
	Params   map[string]float64 `json:"params"`
	Channels []int64            `json:"channels"`
}

type paramSpec struct {
	def, min, max float64
}

// ruleSpecs lists every rule with its editable parameters and defaults.
var ruleSpecs = map[string]struct {
	title  string
	params map[string]paramSpec
}{
	RuleServiceDown: {"A service is down", map[string]paramSpec{"checks": {2, 1, 10}}},
	RuleCPUHigh:     {"CPU usage is high", map[string]paramSpec{"percent": {90, 10, 100}, "minutes": {10, 1, 60}}},
	RuleMemoryHigh:  {"Memory is almost full", map[string]paramSpec{"percent": {90, 10, 100}}},
	RuleDiskFull:    {"A file system is almost full", map[string]paramSpec{"percent": {90, 10, 100}}},
	RuleSMART:       {"A disk reports a SMART failure", map[string]paramSpec{}},
	RuleCertExpiry:  {"A certificate expires soon", map[string]paramSpec{}},
	RuleJobFailed:   {"A job failed", map[string]paramSpec{}},
	RuleSecurity:    {"Security event", map[string]paramSpec{"failed_logins": {10, 3, 1000}, "minutes": {10, 1, 120}}},
}

// Rule names.
const (
	RuleServiceDown = "service_down"
	RuleCPUHigh     = "cpu_high"
	RuleMemoryHigh  = "memory_high"
	RuleDiskFull    = "disk_full"
	RuleSMART       = "smart_failed"
	RuleCertExpiry  = "cert_expiry"
	RuleJobFailed   = "job_failed"
	RuleSecurity    = "security"
)

// Rules lists the rules with their parameters (defaults filled in).
func (s *Service) Rules(ctx context.Context) ([]Rule, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT rule, enabled, params, channels FROM alert_rules ORDER BY rule`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Rule{}
	for rows.Next() {
		var r Rule
		var params, chans string
		if err := rows.Scan(&r.Rule, &r.Enabled, &params, &chans); err != nil {
			return nil, err
		}
		spec, ok := ruleSpecs[r.Rule]
		if !ok {
			continue
		}
		r.Title = spec.title
		stored := map[string]float64{}
		_ = json.Unmarshal([]byte(params), &stored)
		r.Params = map[string]float64{}
		for k, p := range spec.params {
			r.Params[k] = p.def
			if v, ok := stored[k]; ok {
				r.Params[k] = v
			}
		}
		r.Channels = []int64{}
		_ = json.Unmarshal([]byte(chans), &r.Channels)
		out = append(out, r)
	}
	return out, rows.Err()
}

// RuleInput changes a rule.
type RuleInput struct {
	Enabled  bool               `json:"enabled"`
	Params   map[string]float64 `json:"params"`
	Channels []int64            `json:"channels"`
}

// SetRule changes a rule's thresholds, channels and state.
func (s *Service) SetRule(ctx context.Context, a Actor, rule string, in RuleInput) (Rule, error) {
	spec, ok := ruleSpecs[rule]
	if !ok {
		return Rule{}, ErrNotFound
	}
	for k, v := range in.Params {
		p, ok := spec.params[k]
		if !ok {
			return Rule{}, invalid("%s has no parameter %q", rule, k)
		}
		if v < p.min || v > p.max {
			return Rule{}, invalid("%s must be %g to %g", k, p.min, p.max)
		}
	}
	seen := map[int64]bool{}
	chans := []int64{}
	for _, id := range in.Channels {
		if seen[id] {
			continue
		}
		if _, err := s.channel(ctx, id); err != nil {
			return Rule{}, invalid("channel %d does not exist", id)
		}
		seen[id] = true
		chans = append(chans, id)
	}
	params, _ := json.Marshal(in.Params)
	cb, _ := json.Marshal(chans)
	err := withTx(ctx, s.db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE alert_rules SET enabled = ?, params = ?, channels = ?, updated_ms = ? WHERE rule = ?`,
			in.Enabled, string(params), string(cb), s.now().UnixMilli(), rule); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), s.event(a, "alerts.rule_update", "rule:"+rule, nil, "enabled", strconv.FormatBool(in.Enabled),
			"params", string(params), "channels", string(cb)))
		return err
	})
	if err != nil {
		return Rule{}, err
	}
	rules, err := s.Rules(ctx)
	if err != nil {
		return Rule{}, err
	}
	for _, r := range rules {
		if r.Rule == rule {
			return r, nil
		}
	}
	return Rule{}, ErrNotFound
}

// ---- alerts ----

// Alert is a recorded alert.
type Alert struct {
	ID         int64     `json:"id"`
	Rule       string    `json:"rule"`
	Key        string    `json:"key"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	State      string    `json:"state"`
	FiredAt    time.Time `json:"fired_at"`
	ResolvedAt time.Time `json:"resolved_at,omitzero"`
}

// Alerts lists firing alerts, or the newest 200 of all states.
func (s *Service) Alerts(ctx context.Context, firingOnly bool) ([]Alert, error) {
	q := `SELECT id, rule, key, severity, title, body, state, fired_ms, resolved_ms FROM alerts`
	if firingOnly {
		q += ` WHERE state = 'firing'`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY fired_ms DESC, id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		var al Alert
		var fired, resolved int64
		if err := rows.Scan(&al.ID, &al.Rule, &al.Key, &al.Severity, &al.Title, &al.Body, &al.State, &fired, &resolved); err != nil {
			return nil, err
		}
		al.FiredAt = time.UnixMilli(fired).UTC()
		if resolved > 0 {
			al.ResolvedAt = time.UnixMilli(resolved).UTC()
		}
		out = append(out, al)
	}
	return out, rows.Err()
}

// condition is something a rule found.
type condition struct {
	key, severity, title, body string
}

func (s *Service) ruleChannels(ctx context.Context, tx *sql.Tx, rule string) ([]int64, error) {
	var chans string
	if err := tx.QueryRowContext(ctx, `SELECT channels FROM alert_rules WHERE rule = ?`, rule).Scan(&chans); err != nil {
		return nil, err
	}
	var ids []int64
	_ = json.Unmarshal([]byte(chans), &ids)
	return ids, nil
}

func (s *Service) enqueue(ctx context.Context, tx *sql.Tx, alertID int64, kind string, channels []int64) error {
	for _, ch := range channels {
		if _, err := tx.ExecContext(ctx, `INSERT INTO notify_deliveries (alert_id, channel_id, kind, status, next_ms, created_ms)
			SELECT ?, id, ?, 'pending', ?, ? FROM notify_channels WHERE id = ? AND enabled = 1`, alertID, kind, s.now().UnixMilli(), s.now().UnixMilli(), ch); err != nil {
			return err
		}
	}
	return nil
}

// apply brings the firing alerts of a state rule in line with conds.
func (s *Service) apply(ctx context.Context, rule string, conds []condition) error {
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		chans, err := s.ruleChannels(ctx, tx, rule)
		if err != nil {
			return err
		}
		firing := map[string]int64{}
		rows, err := tx.QueryContext(ctx, `SELECT id, key FROM alerts WHERE rule = ? AND state = 'firing'`, rule)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id int64
			var key string
			if err := rows.Scan(&id, &key); err != nil {
				rows.Close()
				return err
			}
			firing[key] = id
		}
		rows.Close()
		now := s.now().UnixMilli()
		active := map[string]bool{}
		for _, c := range conds {
			active[c.key] = true
			if _, ok := firing[c.key]; ok {
				continue // deduplicated: already firing and notified
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO alerts (rule, key, severity, title, body, state, fired_ms) VALUES (?, ?, ?, ?, ?, 'firing', ?)`,
				rule, c.key, c.severity, c.title, c.body, now)
			if err != nil {
				return err
			}
			id, _ := res.LastInsertId()
			if err := s.enqueue(ctx, tx, id, "fire", chans); err != nil {
				return err
			}
		}
		for key, id := range firing {
			if active[key] {
				continue
			}
			if _, err := tx.ExecContext(ctx, `UPDATE alerts SET state = 'resolved', resolved_ms = ? WHERE id = ?`, now, id); err != nil {
				return err
			}
			if err := s.enqueue(ctx, tx, id, "resolve", chans); err != nil {
				return err
			}
		}
		return nil
	})
}

// fireEvent records an event once per rule and key.
func (s *Service) fireEvent(ctx context.Context, rule string, c condition) error {
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM alerts WHERE rule = ? AND key = ?`, rule, c.key).Scan(&n); err != nil || n > 0 {
			return err
		}
		chans, err := s.ruleChannels(ctx, tx, rule)
		if err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO alerts (rule, key, severity, title, body, state, fired_ms) VALUES (?, ?, ?, ?, ?, 'event', ?)`,
			rule, c.key, c.severity, c.title, c.body, s.now().UnixMilli())
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		return s.enqueue(ctx, tx, id, "fire", chans)
	})
}

// ---- deliveries ----

// Delivery is an entry of the delivery log.
type Delivery struct {
	ID        int64     `json:"id"`
	AlertID   *int64    `json:"alert_id"`
	Title     string    `json:"title"`
	Channel   string    `json:"channel"`
	Kind      string    `json:"kind"`
	Status    string    `json:"status"`
	Attempts  int       `json:"attempts"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	SentAt    time.Time `json:"sent_at,omitzero"`
	NextAt    time.Time `json:"next_at,omitzero"`
}

// Deliveries lists the newest 200 deliveries.
func (s *Service) Deliveries(ctx context.Context) ([]Delivery, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT d.id, d.alert_id, COALESCE(a.title, 'Test message'), c.name, d.kind, d.status, d.attempts, d.last_error, d.created_ms, d.sent_ms, d.next_ms
		FROM notify_deliveries d JOIN notify_channels c ON c.id = d.channel_id LEFT JOIN alerts a ON a.id = d.alert_id ORDER BY d.id DESC LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		var alert sql.NullInt64
		var created, sent, next int64
		if err := rows.Scan(&d.ID, &alert, &d.Title, &d.Channel, &d.Kind, &d.Status, &d.Attempts, &d.LastError, &created, &sent, &next); err != nil {
			return nil, err
		}
		if alert.Valid {
			d.AlertID = &alert.Int64
		}
		d.CreatedAt = time.UnixMilli(created).UTC()
		if sent > 0 {
			d.SentAt = time.UnixMilli(sent).UTC()
		}
		if d.Status == "pending" {
			d.NextAt = time.UnixMilli(next).UTC()
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *Service) message(ctx context.Context, alertID sql.NullInt64, kind string) Message {
	m := Message{Title: "Test message", Body: "This is a test notification from Kernhaven.", Severity: "warning", State: "test", Time: s.now().UTC(), Instance: s.instance}
	if !alertID.Valid {
		return m
	}
	var fired int64
	_ = s.db.QueryRowContext(ctx, `SELECT rule, key, severity, title, body, fired_ms FROM alerts WHERE id = ?`, alertID.Int64).Scan(&m.Rule, &m.Key, &m.Severity, &m.Title, &m.Body, &fired)
	m.State = "firing"
	if kind == "resolve" {
		m.State, m.Title = "resolved", "Resolved: "+m.Title
	}
	return m
}

// deliver tries one delivery now and records the outcome.
func (s *Service) deliver(ctx context.Context, id int64) error {
	var alertID sql.NullInt64
	var chID int64
	var kind, status string
	var attempts int
	if err := s.db.QueryRowContext(ctx, `SELECT alert_id, channel_id, kind, status, attempts FROM notify_deliveries WHERE id = ?`, id).Scan(&alertID, &chID, &kind, &status, &attempts); err != nil {
		return err
	}
	if status != "pending" {
		return nil
	}
	now := s.now()
	// Rate limit per channel (tests are not limited).
	if kind != "test" {
		var recent int
		if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM notify_deliveries WHERE channel_id = ? AND status = 'sent' AND kind <> 'test' AND sent_ms > ?`,
			chID, now.Add(-time.Hour).UnixMilli()).Scan(&recent); err != nil {
			return err
		}
		if recent >= RatePerHour {
			_, err := s.db.ExecContext(ctx, `UPDATE notify_deliveries SET status = 'dropped', last_error = ? WHERE id = ?`,
				fmt.Sprintf("rate limit: %d deliveries per channel and hour", RatePerHour), id)
			return err
		}
	}
	ch, err := s.channel(ctx, chID)
	if err != nil {
		return err
	}
	secret, err := s.secret(ctx, chID)
	if err != nil {
		return err
	}
	sctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	sendErr := s.sender.Send(sctx, ch.Kind, ch.Config, secret, s.message(ctx, alertID, kind))
	cancel()
	attempts++
	if sendErr == nil {
		_, err = s.db.ExecContext(ctx, `UPDATE notify_deliveries SET status = 'sent', attempts = ?, sent_ms = ?, last_error = '' WHERE id = ?`, attempts, now.UnixMilli(), id)
		return err
	}
	msg := sendErr.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	if attempts >= MaxAttempts || kind == "test" {
		_, err = s.db.ExecContext(ctx, `UPDATE notify_deliveries SET status = 'failed', attempts = ?, last_error = ? WHERE id = ?`, attempts, msg, id)
	} else {
		next := now.Add(RetryBase << (attempts - 1))
		_, err = s.db.ExecContext(ctx, `UPDATE notify_deliveries SET attempts = ?, last_error = ?, next_ms = ? WHERE id = ?`, attempts, msg, next.UnixMilli(), id)
	}
	if err != nil {
		return err
	}
	return sendErr
}

// Deliver sends every due delivery.
func (s *Service) Deliver(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM notify_deliveries WHERE status = 'pending' AND next_ms <= ? ORDER BY id LIMIT 50`, s.now().UnixMilli())
	if err != nil {
		s.log.Warn("loading deliveries failed", "error", err.Error())
		return
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		if err := s.deliver(ctx, id); err != nil && ctx.Err() == nil {
			s.log.Warn("notification not delivered", "delivery", id, "error", err.Error())
		}
	}
}

// Test sends a test message to a channel now and returns the result.
func (s *Service) Test(ctx context.Context, a Actor, id int64) (Delivery, error) {
	c, err := s.channel(ctx, id)
	if err != nil {
		return Delivery{}, err
	}
	now := s.now().UnixMilli()
	res, err := s.db.ExecContext(ctx, `INSERT INTO notify_deliveries (channel_id, kind, status, next_ms, created_ms) VALUES (?, 'test', 'pending', ?, ?)`, id, now, now)
	if err != nil {
		return Delivery{}, err
	}
	did, _ := res.LastInsertId()
	s.mu.Lock()
	sendErr := s.deliver(ctx, did)
	s.mu.Unlock()
	_ = s.audit.Record(context.WithoutCancel(ctx), s.event(a, "notify.channel_test", "channel:"+c.Name, sendErr))
	all, err := s.Deliveries(ctx)
	if err != nil {
		return Delivery{}, err
	}
	for _, d := range all {
		if d.ID == did {
			return d, nil
		}
	}
	return Delivery{}, ErrNotFound
}

// prune removes deliveries and resolved alerts older than 30 days.
func (s *Service) prune(ctx context.Context) {
	cut := s.now().Add(-DeliveryWindow).UnixMilli()
	_, _ = s.db.ExecContext(ctx, `DELETE FROM notify_deliveries WHERE created_ms < ? AND status <> 'pending'`, cut)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM alerts WHERE state <> 'firing' AND fired_ms < ? AND rule <> 'cert_expiry'`, cut)
}

// Run evaluates every minute and delivers every 15 seconds until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	var lastEval time.Time
	for {
		if s.now().Sub(lastEval) >= time.Minute {
			lastEval = s.now()
			s.Evaluate(ctx)
		}
		s.Deliver(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
