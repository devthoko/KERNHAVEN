package audit

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func seed(t *testing.T, l *Log) {
	t.Helper()
	for _, ev := range []Event{
		{Actor: "alice", Action: "auth.login", Result: Success, IP: "192.0.2.1"},
		{Actor: "mallory", Action: "auth.login", Result: Failure, IP: "203.0.113.9", Details: map[string]string{"reason": "bad password"}},
		{Actor: "alice", Action: "stack.deploy", Target: "stack:shop_2", Result: Success, Details: map[string]string{"revision": "3"}},
		{Actor: "bob", Action: "files.write", Target: "file:docs/100%_done.txt", Result: Denied},
		{Actor: "alice", Action: "backup.run", Target: "backup-plan:nightly", Result: Success, RequestID: "req-xyz"},
	} {
		if err := l.Record(context.Background(), ev); err != nil {
			t.Fatal(err)
		}
	}
}

// AT-F10-03: search across fields, literal wildcards, result and time range.
func TestSearchFilters(t *testing.T) {
	l, _ := newLog(t)
	seed(t, l)
	ctx := context.Background()
	count := func(f Filter) int {
		t.Helper()
		recs, err := l.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return len(recs)
	}
	cases := map[string]struct {
		f    Filter
		want int
	}{
		"query in details":       {Filter{Query: "bad pass"}, 1},
		"query in target":        {Filter{Query: "nightly"}, 1},
		"query in ip":            {Filter{Query: "203.0.113"}, 1},
		"query in request id":    {Filter{Query: "req-xyz"}, 1},
		"query in actor":         {Filter{Query: "mallo"}, 1},
		"percent is literal":     {Filter{Query: "100%_"}, 1},
		"underscore is literal":  {Filter{Query: "p_2"}, 1},
		"wildcard does not run":  {Filter{Query: "%"}, 1},
		"no match":               {Filter{Query: "nothing like this"}, 0},
		"result":                 {Filter{Result: Failure}, 1},
		"result and actor":       {Filter{Result: Success, Actor: "alice"}, 3},
		"query and action":       {Filter{Query: "alice", Action: "auth.login"}, 1},
		"since the third second": {Filter{SinceMS: time.Date(2026, 10, 27, 12, 0, 3, 0, time.UTC).UnixMilli()}, 3},
		"until the third second": {Filter{UntilMS: time.Date(2026, 10, 27, 12, 0, 3, 0, time.UTC).UnixMilli()}, 2},
	}
	for name, c := range cases {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: %d, want %d", name, got, c.want)
		}
	}
}

// AT-F10-03, TH-52: exports are verifiable; changes, removed records and
// truncation between two exports are detected.
func TestExportAndCheck(t *testing.T) {
	l, db := newLog(t)
	ctx := context.Background()
	seed(t, l)
	var first bytes.Buffer
	if n, err := l.Export(ctx, Filter{}, &first); err != nil || n != 5 {
		t.Fatalf("export %d %v", n, err)
	}
	if strings.Count(first.String(), "\n") != 5 || !strings.Contains(first.String(), `"hash":`) {
		t.Fatalf("export %s", first.String())
	}
	s, err := CheckExport(bytes.NewReader(first.Bytes()))
	if err != nil || !s.Linked || !s.Genesis || s.First != 1 || s.Last != 5 || s.Records != 5 {
		t.Fatalf("check %+v %v", s, err)
	}
	// A filtered export is checked record by record.
	var filtered bytes.Buffer
	if _, err := l.Export(ctx, Filter{Actor: "alice"}, &filtered); err != nil {
		t.Fatal(err)
	}
	if fs, err := CheckExport(&filtered); err != nil || fs.Linked || fs.Gaps != 2 || fs.Records != 3 {
		t.Fatalf("filtered %+v %v", fs, err)
	}
	// Modifications of an export are found.
	lines := strings.Split(strings.TrimSpace(first.String()), "\n")
	for name, bad := range map[string]string{
		"changed actor":   strings.Join(append(append([]string{}, lines[:1]...), append([]string{strings.Replace(lines[1], "mallory", "alice", 1)}, lines[2:]...)...), "\n"),
		"reordered":       strings.Join([]string{lines[0], lines[2], lines[1], lines[3], lines[4]}, "\n"),
		"changed details": strings.Replace(first.String(), "bad password", "good password", 1),
		"unknown field":   strings.Replace(lines[0], `"seq":`, `"extra":1,"seq":`, 1),
		"empty":           "",
	} {
		if _, err := CheckExport(strings.NewReader(bad)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A record removed from a full export shows as a gap: the export is no
	// longer linked (a filtered export looks the same, by design).
	if gs, err := CheckExport(strings.NewReader(strings.Join(append(append([]string{}, lines[:2]...), lines[3:]...), "\n"))); err != nil || gs.Linked || gs.Gaps != 1 {
		t.Fatalf("removed record: %+v %v", gs, err)
	}

	// The log grows: the newer export continues the older one.
	if err := l.Record(ctx, Event{Actor: "alice", Action: "auth.logout", Result: Success}); err != nil {
		t.Fatal(err)
	}
	var second bytes.Buffer
	_, _ = l.Export(ctx, Filter{}, &second)
	if err := Continues(s, bytes.NewReader(second.Bytes())); err != nil {
		t.Fatalf("continuation: %v", err)
	}
	// Someone with database access deletes the newest records and writes
	// new ones: the chain verifies, but the older export proves it.
	dropTriggers(t, db)
	if _, err := db.Exec(`DELETE FROM audit_events WHERE seq >= 5`); err != nil {
		t.Fatal(err)
	}
	if res, _ := l.Verify(ctx); !res.OK {
		t.Fatal("tail truncation should not break the chain itself")
	}
	var truncated bytes.Buffer
	_, _ = l.Export(ctx, Filter{}, &truncated)
	if err := Continues(s, &truncated); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("truncation: %v", err)
	}
	if err := l.Record(ctx, Event{Actor: "alice", Action: "innocent", Result: Success}); err != nil {
		t.Fatal(err)
	}
	var rewritten bytes.Buffer
	_, _ = l.Export(ctx, Filter{}, &rewritten)
	if err := Continues(s, &rewritten); err == nil || !strings.Contains(err.Error(), "rewritten") {
		t.Fatalf("rewrite: %v", err)
	}
}
