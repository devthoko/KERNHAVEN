// Package audit implements the tamper-evident, append-only audit log
// (ADR-0016, AT-F10-01, AT-F10-02).
//
// Every record stores the hash of its predecessor; its own hash covers the
// predecessor hash and a canonical JSON encoding of the record. Modifying or
// deleting any record except the newest breaks the chain.
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

// Result is the outcome of an audited action.
type Result string

const (
	Success Result = "success"
	Failure Result = "failure"
	Denied  Result = "denied"
)

// genesisHash is the predecessor hash of the first record.
var genesisHash = strings.Repeat("0", 64)

// Field length limits keep records bounded and logs readable.
const (
	maxField       = 128
	maxDetailValue = 512
	maxDetails     = 32
)

// Event is what callers record.
type Event struct {
	ActorID   int64 // 0 for anonymous or system actions
	Actor     string
	Action    string
	Target    string
	Result    Result
	RequestID string
	IP        string
	Details   map[string]string
}

// Record is a stored audit event.
type Record struct {
	Seq       int64             `json:"seq"`
	Time      time.Time         `json:"time"`
	ActorID   int64             `json:"actor_id"`
	Actor     string            `json:"actor"`
	Action    string            `json:"action"`
	Target    string            `json:"target"`
	Result    Result            `json:"result"`
	RequestID string            `json:"request_id"`
	IP        string            `json:"ip"`
	Details   map[string]string `json:"details"`
	PrevHash  string            `json:"prev_hash"`
	Hash      string            `json:"hash"`
}

// canonical is the hashed representation. Field order is fixed by the struct;
// details are the stored canonical JSON text.
type canonical struct {
	Seq       int64           `json:"seq"`
	TSms      int64           `json:"ts_ms"`
	ActorID   int64           `json:"actor_id"`
	Actor     string          `json:"actor"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Result    Result          `json:"result"`
	RequestID string          `json:"request_id"`
	IP        string          `json:"ip"`
	Details   json.RawMessage `json:"details"`
}

func computeHash(prev string, c canonical) (string, error) {
	b, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'\n'})
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// Append writes ev inside tx. Callers that change state must append in the
// same transaction as the change so that the change and its record commit
// together. The Core's transactions take the write lock at BEGIN
// (_txlock=immediate), which serializes chain extension.
func Append(ctx context.Context, tx *sql.Tx, now time.Time, ev Event) (Record, error) {
	if ev.Action == "" {
		return Record{}, errors.New("audit: empty action")
	}
	switch ev.Result {
	case Success, Failure, Denied:
	default:
		return Record{}, fmt.Errorf("audit: invalid result %q", ev.Result)
	}
	if ev.Actor == "" {
		ev.Actor = "anonymous"
	}
	if len(ev.Details) > maxDetails {
		return Record{}, fmt.Errorf("audit: too many details (%d)", len(ev.Details))
	}
	details := make(map[string]string, len(ev.Details))
	for k, v := range ev.Details {
		details[truncate(k, maxField)] = truncate(v, maxDetailValue)
	}
	detailsJSON, err := json.Marshal(details) // map keys are sorted: canonical
	if err != nil {
		return Record{}, err
	}

	var prevSeq int64
	prevHash := genesisHash
	err = tx.QueryRowContext(ctx, `SELECT seq, hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&prevSeq, &prevHash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Record{}, fmt.Errorf("audit: read chain head: %w", err)
	}

	rec := Record{
		Seq:       prevSeq + 1,
		Time:      now.UTC().Truncate(time.Millisecond),
		ActorID:   ev.ActorID,
		Actor:     truncate(ev.Actor, maxField),
		Action:    truncate(ev.Action, maxField),
		Target:    truncate(ev.Target, maxField),
		Result:    ev.Result,
		RequestID: truncate(ev.RequestID, maxField),
		IP:        truncate(ev.IP, maxField),
		Details:   details,
		PrevHash:  prevHash,
	}
	c := toCanonical(rec, detailsJSON)
	if rec.Hash, err = computeHash(prevHash, c); err != nil {
		return Record{}, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO audit_events
		(seq, ts_ms, actor_id, actor, action, target, result, request_id, ip, details, prev_hash, hash)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Seq, c.TSms, rec.ActorID, rec.Actor, rec.Action, rec.Target, string(rec.Result),
		rec.RequestID, rec.IP, string(detailsJSON), rec.PrevHash, rec.Hash)
	if err != nil {
		return Record{}, fmt.Errorf("audit: insert: %w", err)
	}
	return rec, nil
}

func toCanonical(r Record, details []byte) canonical {
	return canonical{
		Seq: r.Seq, TSms: r.Time.UnixMilli(), ActorID: r.ActorID, Actor: r.Actor,
		Action: r.Action, Target: r.Target, Result: r.Result, RequestID: r.RequestID,
		IP: r.IP, Details: details,
	}
}

// Log reads and writes the audit log.
type Log struct {
	db  *sql.DB
	now func() time.Time
}

// New returns a Log. now may be nil (time.Now).
func New(db *sql.DB, now func() time.Time) *Log {
	if now == nil {
		now = time.Now
	}
	return &Log{db: db, now: now}
}

// Record appends ev in its own transaction. Use it for events without an
// accompanying state change, such as failed logins.
func (l *Log) Record(ctx context.Context, ev Event) error {
	tx, err := l.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	if _, err := Append(ctx, tx, l.now(), ev); err != nil {
		return err
	}
	return tx.Commit()
}

// Filter selects records for List and Export.
type Filter struct {
	Limit     int    // 1..500, default 100 (List only)
	BeforeSeq int64  // only records with seq < BeforeSeq (0 = newest)
	Action    string // exact match
	Actor     string // exact match
	// M17 (AT-F10-03)
	Query   string // substring of action, actor, target, request ID, IP or details
	Result  Result // exact match
	SinceMS int64  // ts_ms >= SinceMS
	UntilMS int64  // ts_ms < UntilMS
}

// likeEscape makes s a literal LIKE pattern (escape character '\').
func likeEscape(s string) string {
	return "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s) + "%"
}

func (f Filter) where() (string, []any) {
	q := ` WHERE 1=1`
	var args []any
	if f.BeforeSeq > 0 {
		q += ` AND seq < ?`
		args = append(args, f.BeforeSeq)
	}
	if f.Action != "" {
		q += ` AND action = ?`
		args = append(args, f.Action)
	}
	if f.Actor != "" {
		q += ` AND actor = ?`
		args = append(args, f.Actor)
	}
	if f.Result != "" {
		q += ` AND result = ?`
		args = append(args, string(f.Result))
	}
	if f.SinceMS > 0 {
		q += ` AND ts_ms >= ?`
		args = append(args, f.SinceMS)
	}
	if f.UntilMS > 0 {
		q += ` AND ts_ms < ?`
		args = append(args, f.UntilMS)
	}
	if f.Query != "" {
		p := likeEscape(f.Query)
		q += ` AND (action LIKE ? ESCAPE '\' OR actor LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\' OR request_id LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\' OR details LIKE ? ESCAPE '\')`
		args = append(args, p, p, p, p, p, p)
	}
	return q, args
}

// List returns matching records, newest first.
func (l *Log) List(ctx context.Context, f Filter) ([]Record, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 500 {
		f.Limit = 500
	}
	where, args := f.where()
	q := `SELECT ` + recordColumns + ` FROM audit_events` + where + ` ORDER BY seq DESC LIMIT ?`
	args = append(args, f.Limit)

	rows, err := l.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		rec, _, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func scan(rows *sql.Rows) (Record, []byte, error) {
	var r Record
	var ts int64
	var result, details string
	if err := rows.Scan(&r.Seq, &ts, &r.ActorID, &r.Actor, &r.Action, &r.Target, &result,
		&r.RequestID, &r.IP, &details, &r.PrevHash, &r.Hash); err != nil {
		return Record{}, nil, err
	}
	r.Time = time.UnixMilli(ts).UTC()
	r.Result = Result(result)
	if err := json.Unmarshal([]byte(details), &r.Details); err != nil {
		r.Details = map[string]string{"_invalid_details": details}
	}
	return r, []byte(details), nil
}

const recordColumns = `seq, ts_ms, actor_id, actor, action, target, result, request_id, ip, details, prev_hash, hash`

// Since returns up to limit records with seq > after, oldest first (M15).
func (l *Log) Since(ctx context.Context, after int64, limit int) ([]Record, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT `+recordColumns+` FROM audit_events WHERE seq > ? ORDER BY seq LIMIT ?`, after, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		r, _, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// VerifyResult reports the outcome of a chain verification.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Records  int64  `json:"records"`
	BrokenAt int64  `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Verify recomputes the whole chain.
func (l *Log) Verify(ctx context.Context) (VerifyResult, error) {
	rows, err := l.db.QueryContext(ctx, `SELECT seq, ts_ms, actor_id, actor, action, target, result, request_id, ip, details, prev_hash, hash
		FROM audit_events ORDER BY seq ASC`)
	if err != nil {
		return VerifyResult{}, err
	}
	defer rows.Close()
	prev := genesisHash
	var n int64
	for rows.Next() {
		rec, details, err := scan(rows)
		if err != nil {
			return VerifyResult{}, err
		}
		n++
		fail := func(reason string) (VerifyResult, error) {
			return VerifyResult{OK: false, Records: n, BrokenAt: rec.Seq, Reason: reason}, nil
		}
		if rec.Seq != n {
			return fail(fmt.Sprintf("sequence gap: expected %d", n))
		}
		if rec.PrevHash != prev {
			return fail("previous-hash link broken")
		}
		want, err := computeHash(prev, toCanonical(rec, details))
		if err != nil {
			return VerifyResult{}, err
		}
		if want != rec.Hash {
			return fail("record hash mismatch")
		}
		prev = rec.Hash
	}
	if err := rows.Err(); err != nil {
		return VerifyResult{}, err
	}
	return VerifyResult{OK: true, Records: n}, nil
}
