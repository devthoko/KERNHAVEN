package backup

import (
	"reflect"
	"testing"
	"time"
)

// AT-F14-04: cron expressions.
func TestSchedule(t *testing.T) {
	loc := time.FixedZone("test", 3600)
	at := func(s string) time.Time {
		v, err := time.ParseInLocation("2006-01-02 15:04", s, loc)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	cases := []struct{ expr, from, want string }{
		{"0 3 * * *", "2026-10-29 02:59", "2026-10-29 03:00"},
		{"0 3 * * *", "2026-10-29 03:00", "2026-10-30 03:00"},
		{"@daily", "2026-12-31 04:00", "2027-01-01 03:00"},
		{"*/15 * * * *", "2026-10-29 10:07", "2026-10-29 10:15"},
		{"30 2 * * 0", "2026-10-29 10:00", "2026-11-01 02:30"}, // next Sunday
		{"30 2 * * 7", "2026-10-29 10:00", "2026-11-01 02:30"},
		{"0 4 1 * *", "2026-10-29 10:00", "2026-11-01 04:00"},
		{"0 4 1,15 * 1", "2026-10-29 10:00", "2026-11-01 04:00"}, // dom OR dow
		{"0 4 13 * 5", "2026-10-29 10:00", "2026-10-30 04:00"},   // Friday comes first
		{"0 0 29 2 *", "2026-10-29 10:00", "2028-02-29 00:00"},
		{"5 1-3/2 * * 1-5", "2026-10-30 01:06", "2026-10-30 03:05"},
		{"0 12 * 6 *", "2026-10-29 10:00", "2027-06-01 12:00"},
	}
	for _, c := range cases {
		s, err := ParseSchedule(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if got := s.Next(at(c.from)); !got.Equal(at(c.want)) {
			t.Errorf("%s from %s: %s, want %s", c.expr, c.from, got.Format("2006-01-02 15:04"), c.want)
		}
	}
	never, _ := ParseSchedule("0 0 30 2 *")
	if !never.Next(at("2026-01-01 00:00")).IsZero() {
		t.Error("30 February matched")
	}
	for _, bad := range []string{"", "* * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "a * * * *", "5-1 * * * *", "*/0 * * * *", "* * * * * *", "* * * * *", "*/10 * * * *", "1,2,3,4,5 * * * *"} {
		if _, err := ParseSchedule(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// AT-F14-04: retention keeps by count and by calendar buckets.
func TestRetention(t *testing.T) {
	base := time.Date(2026, 10, 29, 3, 0, 0, 0, time.Local)
	times := map[string]time.Time{}
	var ids []string
	for i := range 60 { // one snapshot a day, two on the newest day
		id := base.AddDate(0, 0, -i).Format("2006-01-02")
		times[id] = base.AddDate(0, 0, -i)
		ids = append(ids, id)
	}
	times["extra"] = base.Add(-time.Hour)
	forget := Retention{KeepDaily: 7, KeepWeekly: 4, KeepMonthly: 3}.Forget(times)
	keep := map[string]bool{}
	for id := range times {
		keep[id] = true
	}
	for _, id := range forget {
		delete(keep, id)
	}
	for i := range 7 {
		if !keep[ids[i]] {
			t.Errorf("daily %s not kept", ids[i])
		}
	}
	if keep["extra"] {
		t.Error("second snapshot of a day kept by the daily rule")
	}
	// 7 days + up to 4 weekly (some overlap) + up to 3 monthly.
	if len(keep) < 9 || len(keep) > 14 {
		t.Errorf("kept %d", len(keep))
	}
	if got := (Retention{KeepLast: 2}).Forget(map[string]time.Time{"a": base, "b": base.Add(time.Hour), "c": base.Add(2 * time.Hour)}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("keep_last: %v", got)
	}
	// The monthly rule keeps the newest snapshot of each month.
	if got := (Retention{KeepMonthly: 1}).Forget(map[string]time.Time{"old": base.AddDate(0, -1, 0), "new": base}); !reflect.DeepEqual(got, []string{"old"}) {
		t.Errorf("monthly: %v", got)
	}
	// Even a policy that keeps nothing (refused by validation, e.g. from an
	// old job payload) keeps the newest snapshot.
	if got := (Retention{}).Forget(map[string]time.Time{"old": base.AddDate(0, -1, 0), "new": base}); !reflect.DeepEqual(got, []string{"old"}) {
		t.Errorf("empty policy: %v", got)
	}
	if (Retention{}).validate() == nil || (Retention{KeepLast: -1}).validate() == nil || (Retention{KeepLast: 1}).validate() != nil {
		t.Error("validation")
	}
}
