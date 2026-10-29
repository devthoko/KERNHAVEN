package alerts

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/certs"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/metrics"
)

// Sources are what the rules look at, through the other modules' APIs. A
// nil source skips its rules.
type Sources struct {
	Health       func(ctx context.Context) []metrics.Check
	Host         func() (metrics.Host, error)
	CPUAverage   func(d time.Duration) (float64, int)
	Storage      func(ctx context.Context) (agentproto.StorageInventory, error)
	Certificates func(ctx context.Context) ([]certs.Certificate, error)
	FailedJobs   func(ctx context.Context, since time.Time) ([]jobs.Job, error)
	Audit        func(ctx context.Context, after int64, limit int) ([]audit.Record, error)
	VerifyAudit  func(ctx context.Context) (audit.VerifyResult, error)
}

// Expiry stages of certificates (AT-F12-04).
var expiryStages = []int{30, 14, 3}

func (s *Service) cursor(ctx context.Context, name string) (int64, bool) {
	var v int64
	err := s.db.QueryRowContext(ctx, `SELECT value FROM alert_cursor WHERE name = ?`, name).Scan(&v)
	return v, err == nil
}

func (s *Service) setCursor(ctx context.Context, name string, v int64) {
	_, _ = s.db.ExecContext(ctx, `INSERT INTO alert_cursor (name, value) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET value = excluded.value`, name, v)
}

// Evaluate runs every enabled rule once.
func (s *Service) Evaluate(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rules, err := s.Rules(ctx)
	if err != nil {
		s.log.Warn("loading alert rules failed", "error", err.Error())
		return
	}
	for _, r := range rules {
		if !r.Enabled {
			// A disabled rule ends its alerts without notifying.
			_, _ = s.db.ExecContext(ctx, `UPDATE alerts SET state = 'resolved', resolved_ms = ? WHERE rule = ? AND state = 'firing'`, s.now().UnixMilli(), r.Rule)
			continue
		}
		if err := s.evaluate(ctx, r); err != nil && ctx.Err() == nil {
			s.log.Warn("alert rule failed", "rule", r.Rule, "error", err.Error())
		}
	}
	if s.now().Sub(s.lastPrune) >= time.Hour {
		s.prune(ctx)
		s.lastPrune = s.now()
	}
}

// errSkip keeps the current alerts when a source is not available.
var errSkip = errors.New("source not available")

func (s *Service) evaluate(ctx context.Context, r Rule) error {
	var conds []condition
	var err error
	switch r.Rule {
	case RuleServiceDown:
		conds, err = s.serviceDown(ctx, r)
	case RuleCPUHigh:
		conds, err = s.cpuHigh(r)
	case RuleMemoryHigh:
		conds, err = s.memoryHigh(r)
	case RuleDiskFull, RuleSMART:
		conds, err = s.storage(ctx, r)
	case RuleCertExpiry:
		return s.certExpiry(ctx)
	case RuleJobFailed:
		return s.jobFailed(ctx)
	case RuleSecurity:
		return s.security(ctx, r)
	default:
		return nil
	}
	return s.state(ctx, r.Rule, conds, err)
}

func (s *Service) state(ctx context.Context, rule string, conds []condition, err error) error {
	if errors.Is(err, errSkip) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.apply(ctx, rule, conds)
}

func (s *Service) serviceDown(ctx context.Context, r Rule) ([]condition, error) {
	if s.src.Health == nil {
		return nil, errSkip
	}
	need := int(r.Params["checks"])
	var out []condition
	for _, c := range s.src.Health(ctx) {
		if c.Status != metrics.StatusDown {
			delete(s.downCount, c.Name)
			continue
		}
		s.downCount[c.Name]++
		if s.downCount[c.Name] >= need {
			out = append(out, condition{key: c.Name, severity: "critical", title: c.Label + " is down", body: fmt.Sprintf("%s is down: %s", c.Label, c.Detail)})
		}
	}
	return out, nil
}

func (s *Service) cpuHigh(r Rule) ([]condition, error) {
	if s.src.CPUAverage == nil {
		return nil, errSkip
	}
	d := time.Duration(r.Params["minutes"]) * time.Minute
	avg, n := s.src.CPUAverage(d)
	if n == 0 {
		return nil, errSkip
	}
	if avg > r.Params["percent"] {
		return []condition{{key: "host", severity: "warning", title: "CPU usage is high",
			body: fmt.Sprintf("The host's CPU usage averaged %.0f %% over the last %g minutes (threshold %g %%).", avg, r.Params["minutes"], r.Params["percent"])}}, nil
	}
	return nil, nil
}

func (s *Service) memoryHigh(r Rule) ([]condition, error) {
	if s.src.Host == nil {
		return nil, errSkip
	}
	h, err := s.src.Host()
	if err != nil || h.Memory.Total == 0 {
		return nil, errSkip
	}
	pct := float64(h.MemoryUsed) / float64(h.Memory.Total) * 100
	if pct > r.Params["percent"] {
		return []condition{{key: "host", severity: "warning", title: "Memory is almost full",
			body: fmt.Sprintf("%.0f %% of the host's memory is used (threshold %g %%).", pct, r.Params["percent"])}}, nil
	}
	return nil, nil
}

// storage covers disk_full and smart_failed (AT-F06-04).
func (s *Service) storage(ctx context.Context, r Rule) ([]condition, error) {
	if s.src.Storage == nil {
		return nil, errSkip
	}
	inv, err := s.src.Storage(ctx)
	if err != nil {
		return nil, errSkip // the storage service is down: service_down reports that
	}
	var out []condition
	for _, d := range inv.Disks {
		if r.Rule == RuleSMART {
			if d.SMART.Available && d.SMART.Passed != nil && !*d.SMART.Passed {
				out = append(out, condition{key: d.Path, severity: "critical", title: "SMART failure on " + d.Name,
					body: fmt.Sprintf("%s (%s, serial %s) fails its SMART self-assessment: %s. Back up its data and replace it.", d.Path, d.Model, d.Serial, d.SMART.Message)})
			}
			continue
		}
		for _, fs := range d.FileSystems {
			if fs.FSSizeBytes <= 0 || len(fs.Mountpoints) == 0 {
				continue
			}
			pct := float64(fs.FSUsedBytes) / float64(fs.FSSizeBytes) * 100
			if pct > r.Params["percent"] {
				out = append(out, condition{key: fs.Path, severity: "warning", title: fmt.Sprintf("%s is %.0f %% full", fs.Mountpoints[0], pct),
					body: fmt.Sprintf("%s (%s) mounted at %s uses %.0f %% of its space (threshold %g %%).", fs.Path, fs.FSType, strings.Join(fs.Mountpoints, ", "), pct, r.Params["percent"])})
			}
		}
	}
	return out, nil
}

// certExpiry fires once per certificate and stage (AT-F12-04).
func (s *Service) certExpiry(ctx context.Context) error {
	if s.src.Certificates == nil {
		return nil
	}
	list, err := s.src.Certificates(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	for _, c := range list {
		if len(c.Hosts) == 0 {
			continue
		}
		days := int(math.Floor(c.NotAfter.Sub(now).Hours() / 24))
		stage, sev := -1, "warning"
		switch {
		case days < 0:
			stage, sev = 0, "critical"
		default:
			for _, st := range expiryStages {
				if days <= st {
					stage = st
				}
			}
			if stage == 3 {
				sev = "critical"
			}
		}
		if stage < 0 {
			continue
		}
		what := fmt.Sprintf("expires in %d days (%s)", days, c.NotAfter.Format("2006-01-02"))
		if stage == 0 {
			what = "has expired (" + c.NotAfter.Format("2006-01-02") + ")"
		}
		if err := s.fireEvent(ctx, RuleCertExpiry, condition{key: fmt.Sprintf("cert:%d:%d", c.ID, stage), severity: sev,
			title: fmt.Sprintf("Certificate for %s %s", strings.Join(c.Hosts, ", "), what),
			body:  fmt.Sprintf("The certificate for %s (%s, issued by %s) %s. Replace it under Certificates.", strings.Join(c.Hosts, ", "), strings.Join(c.Names, ", "), c.Issuer, what)}); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) jobFailed(ctx context.Context) error {
	if s.src.FailedJobs == nil {
		return nil
	}
	since, ok := s.cursor(ctx, "jobs_ms")
	if !ok {
		// Start now: older failures were visible before alerts existed.
		s.setCursor(ctx, "jobs_ms", s.now().UnixMilli())
		return nil
	}
	// Including the cursor's millisecond: jobs finishing in the same
	// millisecond are not lost; fireEvent deduplicates by job.
	list, err := s.src.FailedJobs(ctx, time.UnixMilli(since-1))
	if err != nil {
		return err
	}
	for _, j := range list {
		if j.FinishedAt != nil && j.FinishedAt.UnixMilli() > since {
			since = j.FinishedAt.UnixMilli()
		}
		if err := s.fireEvent(ctx, RuleJobFailed, condition{key: fmt.Sprintf("job:%d", j.ID), severity: "warning",
			title: fmt.Sprintf("Job #%d (%s) failed", j.ID, j.Kind), body: fmt.Sprintf("Job #%d (%s) failed: %s", j.ID, j.Kind, j.Error)}); err != nil {
			return err
		}
	}
	s.setCursor(ctx, "jobs_ms", since)
	return nil
}

// security reads new audit records: sign-in bursts, lockouts, MFA policy
// downgrades, new owners and admins; and verifies the audit chain hourly.
func (s *Service) security(ctx context.Context, r Rule) error {
	if s.src.Audit == nil {
		return nil
	}
	after, ok := s.cursor(ctx, "audit_seq")
	for {
		recs, err := s.src.Audit(ctx, after, 500)
		if err != nil {
			return err
		}
		if len(recs) == 0 {
			break
		}
		for _, rec := range recs {
			after = rec.Seq
			if !ok {
				continue // first run: start after the existing records
			}
			if err := s.securityRecord(ctx, rec); err != nil {
				return err
			}
		}
	}
	s.setCursor(ctx, "audit_seq", after)

	window := time.Duration(r.Params["minutes"]) * time.Minute
	cut := 0
	for cut < len(s.logins) && s.now().Sub(s.logins[cut]) > window {
		cut++
	}
	s.logins = s.logins[cut:]
	if len(s.logins) >= int(r.Params["failed_logins"]) && s.now().Sub(s.lastBurst) > window {
		s.lastBurst = s.now()
		if err := s.fireEvent(ctx, RuleSecurity, condition{key: fmt.Sprintf("logins:%d", s.now().Unix()), severity: "warning",
			title: fmt.Sprintf("%d failed sign-ins in %g minutes", len(s.logins), r.Params["minutes"]),
			body:  fmt.Sprintf("%d sign-ins failed within %g minutes. Check the audit log for the source addresses.", len(s.logins), r.Params["minutes"])}); err != nil {
			return err
		}
	}

	if s.src.VerifyAudit != nil && s.now().Sub(s.lastChain) >= time.Hour {
		s.lastChain = s.now()
		v, err := s.src.VerifyAudit(ctx)
		if err != nil {
			return err
		}
		var conds []condition
		if !v.OK {
			conds = append(conds, condition{key: "audit_chain", severity: "critical", title: "The audit log was modified",
				body: fmt.Sprintf("Verification of the audit chain failed at record %d: %s. Someone changed or deleted audit records.", v.BrokenAt, v.Reason)})
		}
		s.chainOK = v.OK
		return s.applyKeys(ctx, RuleSecurity, conds, "audit_chain")
	}
	return nil
}

func (s *Service) securityRecord(ctx context.Context, rec audit.Record) error {
	ev := func(sev, title, body string) error {
		return s.fireEvent(ctx, RuleSecurity, condition{key: fmt.Sprintf("audit:%d", rec.Seq), severity: sev, title: title, body: body + fmt.Sprintf(" (audit record %d, %s)", rec.Seq, rec.IP)})
	}
	privileged := func(role string) bool { return role == "owner" || role == "admin" }
	switch {
	case rec.Action == "auth.login" && rec.Result == audit.Failure:
		s.logins = append(s.logins, rec.Time)
	case rec.Action == "auth.lockout":
		return ev("warning", "An account was locked", fmt.Sprintf("%s was locked after %s failed sign-ins.", rec.Target, rec.Details["failed_logins"]))
	case rec.Action == "auth.mfa_policy" && rec.Result == audit.Success && rec.Details["downgrade"] == "true":
		return ev("critical", "The MFA policy was weakened", fmt.Sprintf("%s no longer requires a second factor for: %s.", rec.Actor, rec.Details["required_removed"]))
	case rec.Action == "user.create" && rec.Result == audit.Success && privileged(rec.Details["role"]):
		return ev("critical", "New "+rec.Details["role"]+" account", fmt.Sprintf("%s created %s with the role %s.", rec.Actor, rec.Details["username"], rec.Details["role"]))
	case rec.Action == "user.update" && rec.Result == audit.Success && privileged(rec.Details["role_to"]):
		return ev("critical", "A user became "+rec.Details["role_to"], fmt.Sprintf("%s changed %s from %s to %s.", rec.Actor, rec.Target, rec.Details["role_from"], rec.Details["role_to"]))
	}
	return nil
}

// applyKeys is apply for some keys of a rule only (others stay as they are).
func (s *Service) applyKeys(ctx context.Context, rule string, conds []condition, keys ...string) error {
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		chans, err := s.ruleChannels(ctx, tx, rule)
		if err != nil {
			return err
		}
		now := s.now().UnixMilli()
		want := map[string]condition{}
		for _, c := range conds {
			want[c.key] = c
		}
		for _, key := range keys {
			var id int64
			err := tx.QueryRowContext(ctx, `SELECT id FROM alerts WHERE rule = ? AND key = ? AND state = 'firing'`, rule, key).Scan(&id)
			firing := err == nil
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			c, active := want[key]
			switch {
			case active && !firing:
				res, err := tx.ExecContext(ctx, `INSERT INTO alerts (rule, key, severity, title, body, state, fired_ms) VALUES (?, ?, ?, ?, ?, 'firing', ?)`, rule, key, c.severity, c.title, c.body, now)
				if err != nil {
					return err
				}
				id, _ = res.LastInsertId()
				if err := s.enqueue(ctx, tx, id, "fire", chans); err != nil {
					return err
				}
			case !active && firing:
				if _, err := tx.ExecContext(ctx, `UPDATE alerts SET state = 'resolved', resolved_ms = ? WHERE id = ?`, now, id); err != nil {
					return err
				}
				if err := s.enqueue(ctx, tx, id, "resolve", chans); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
