package audit

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

func newLog(t *testing.T) (*Log, *sql.DB) {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), store.FileName))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	clock := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	return New(db, func() time.Time { clock = clock.Add(time.Second); return clock }), db
}

func record(t *testing.T, l *Log, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		err := l.Record(context.Background(), Event{
			ActorID: 1, Actor: "alice", Action: "user.update", Target: "user:2",
			Result: Success, RequestID: "req", IP: "192.0.2.1",
			Details: map[string]string{"field": "role", "index": string(rune('a' + i))},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

// AT-F10-01, AT-F10-02
func TestAppendBuildsVerifiableChain(t *testing.T) {
	l, _ := newLog(t)
	record(t, l, 5)
	res, err := l.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Records != 5 {
		t.Fatalf("verify = %+v", res)
	}
	recs, err := l.List(context.Background(), Filter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 5 || recs[0].Seq != 5 || recs[4].PrevHash != genesisHash || recs[0].PrevHash != recs[1].Hash {
		t.Fatalf("unexpected chain: %+v", recs)
	}
	r := recs[0]
	if r.Actor != "alice" || r.Action != "user.update" || r.Target != "user:2" || r.Result != Success ||
		r.RequestID != "req" || r.IP != "192.0.2.1" || r.Details["field"] != "role" {
		t.Fatalf("record fields not stored: %+v", r)
	}
}

func TestEmptyLogVerifies(t *testing.T) {
	l, _ := newLog(t)
	res, err := l.Verify(context.Background())
	if err != nil || !res.OK || res.Records != 0 {
		t.Fatalf("verify = %+v err=%v", res, err)
	}
}

// AT-F10-02: the database refuses updates and deletes.
func TestAppendOnlyTriggers(t *testing.T) {
	l, db := newLog(t)
	record(t, l, 2)
	if _, err := db.Exec(`UPDATE audit_events SET actor = 'mallory' WHERE seq = 1`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("update err = %v", err)
	}
	if _, err := db.Exec(`DELETE FROM audit_events WHERE seq = 1`); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Fatalf("delete err = %v", err)
	}
}

func dropTriggers(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, s := range []string{`DROP TRIGGER audit_events_no_update`, `DROP TRIGGER audit_events_no_delete`} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
}

// AT-F10-02: tampering by someone with raw database access is detected.
func TestVerifyDetectsTampering(t *testing.T) {
	cases := map[string]struct {
		stmt     string
		brokenAt int64
		reason   string
	}{
		"modified field":   {`UPDATE audit_events SET actor = 'mallory' WHERE seq = 3`, 3, "record hash mismatch"},
		"modified details": {`UPDATE audit_events SET details = '{"field":"none"}' WHERE seq = 2`, 2, "record hash mismatch"},
		"modified time":    {`UPDATE audit_events SET ts_ms = ts_ms + 1 WHERE seq = 4`, 4, "record hash mismatch"},
		"deleted record":   {`DELETE FROM audit_events WHERE seq = 2`, 3, "sequence gap"},
		"rehashed record":  {`UPDATE audit_events SET hash = '` + strings.Repeat("a", 64) + `' WHERE seq = 2`, 2, "record hash mismatch"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			l, db := newLog(t)
			record(t, l, 5)
			dropTriggers(t, db)
			if _, err := db.Exec(tc.stmt); err != nil {
				t.Fatal(err)
			}
			res, err := l.Verify(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if res.OK || res.BrokenAt != tc.brokenAt || !strings.Contains(res.Reason, tc.reason) {
				t.Fatalf("verify = %+v, want broken at %d (%s)", res, tc.brokenAt, tc.reason)
			}
		})
	}
}

func TestInvalidEventsRejected(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()
	if err := l.Record(ctx, Event{Result: Success}); err == nil {
		t.Error("empty action accepted")
	}
	if err := l.Record(ctx, Event{Action: "x", Result: "maybe"}); err == nil {
		t.Error("invalid result accepted")
	}
	many := map[string]string{}
	for i := 0; i < maxDetails+1; i++ {
		many[strings.Repeat("k", i+1)] = "v"
	}
	if err := l.Record(ctx, Event{Action: "x", Result: Success, Details: many}); err == nil {
		t.Error("too many details accepted")
	}
}

func TestLongFieldsTruncatedAndAnonymousDefault(t *testing.T) {
	l, _ := newLog(t)
	long := strings.Repeat("x", 1000)
	if err := l.Record(context.Background(), Event{Action: "auth.login", Target: long, Result: Failure, Details: map[string]string{"v": long}}); err != nil {
		t.Fatal(err)
	}
	recs, _ := l.List(context.Background(), Filter{})
	r := recs[0]
	if r.Actor != "anonymous" || len([]rune(r.Target)) != maxField+1 || len([]rune(r.Details["v"])) != maxDetailValue+1 {
		t.Fatalf("record = actor %q target len %d detail len %d", r.Actor, len([]rune(r.Target)), len([]rune(r.Details["v"])))
	}
	if res, _ := l.Verify(context.Background()); !res.OK {
		t.Fatalf("verify = %+v", res)
	}
}

func TestListFilters(t *testing.T) {
	l, _ := newLog(t)
	ctx := context.Background()
	record(t, l, 3)
	if err := l.Record(ctx, Event{Actor: "bob", Action: "auth.login", Result: Failure}); err != nil {
		t.Fatal(err)
	}
	byAction, _ := l.List(ctx, Filter{Action: "auth.login"})
	byActor, _ := l.List(ctx, Filter{Actor: "alice"})
	limited, _ := l.List(ctx, Filter{Limit: 2})
	before, _ := l.List(ctx, Filter{BeforeSeq: 3})
	if len(byAction) != 1 || byAction[0].Actor != "bob" {
		t.Errorf("action filter: %+v", byAction)
	}
	if len(byActor) != 3 {
		t.Errorf("actor filter: %d", len(byActor))
	}
	if len(limited) != 2 || limited[0].Seq != 4 {
		t.Errorf("limit: %+v", limited)
	}
	if len(before) != 2 || before[0].Seq != 2 {
		t.Errorf("before: %+v", before)
	}
}

// A rolled-back transaction leaves no audit record behind.
func TestAppendRollsBackWithTransaction(t *testing.T) {
	l, db := newLog(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Append(context.Background(), tx, time.Now(), Event{Action: "x", Result: Success}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	recs, _ := l.List(context.Background(), Filter{})
	if len(recs) != 0 {
		t.Fatalf("records after rollback: %d", len(recs))
	}
}
