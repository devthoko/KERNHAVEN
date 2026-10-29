package backup

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Schedule is a five-field cron expression (minute hour day-of-month month
// day-of-week) evaluated in the host's local time (AT-F14-04).
type Schedule struct {
	min, hour, dom, month, dow uint64
	domStar, dowStar           bool
}

var macros = map[string]string{
	"@hourly": "0 * * * *", "@daily": "0 3 * * *", "@weekly": "0 3 * * 0", "@monthly": "0 3 1 * *",
}

func parseField(f string, lo, hi int) (uint64, bool, error) {
	var bits uint64
	for _, part := range strings.Split(f, ",") {
		step := 1
		if i := strings.Index(part, "/"); i >= 0 {
			s, err := strconv.Atoi(part[i+1:])
			if err != nil || s < 1 || s > hi {
				return 0, false, fmt.Errorf("invalid step in %q", f)
			}
			step, part = s, part[:i]
		}
		a, b := lo, hi
		switch {
		case part == "*":
		case strings.Contains(part, "-"):
			x, y, _ := strings.Cut(part, "-")
			var err1, err2 error
			a, err1 = strconv.Atoi(x)
			b, err2 = strconv.Atoi(y)
			if err1 != nil || err2 != nil {
				return 0, false, fmt.Errorf("invalid range %q", part)
			}
		default:
			v, err := strconv.Atoi(part)
			if err != nil {
				return 0, false, fmt.Errorf("invalid value %q", part)
			}
			a, b = v, v
			if step > 1 {
				b = hi
			}
		}
		if a < lo || b > hi || a > b {
			return 0, false, fmt.Errorf("%q is outside %d-%d", part, lo, hi)
		}
		for v := a; v <= b; v += step {
			bits |= 1 << uint(v)
		}
	}
	return bits, f == "*", nil
}

// ParseSchedule parses a cron expression or one of @hourly, @daily,
// @weekly, @monthly.
func ParseSchedule(expr string) (Schedule, error) {
	expr = strings.TrimSpace(expr)
	if m, ok := macros[expr]; ok {
		expr = m
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return Schedule{}, errors.New("schedule must have five fields: minute hour day month weekday")
	}
	var s Schedule
	var err error
	if s.min, _, err = parseField(f[0], 0, 59); err != nil {
		return s, err
	}
	if s.hour, _, err = parseField(f[1], 0, 23); err != nil {
		return s, err
	}
	if s.dom, s.domStar, err = parseField(f[2], 1, 31); err != nil {
		return s, err
	}
	if s.month, _, err = parseField(f[3], 1, 12); err != nil {
		return s, err
	}
	if s.dow, s.dowStar, err = parseField(f[4], 0, 7); err != nil {
		return s, err
	}
	if s.dow&(1<<7) != 0 {
		s.dow |= 1 // 7 is Sunday too
	}
	// More frequent runs would mostly measure the backup itself.
	if countBits(s.min) > 4 {
		return s, errors.New("a schedule may run at most four times an hour")
	}
	return s, nil
}

func countBits(v uint64) int {
	n := 0
	for ; v != 0; v &= v - 1 {
		n++
	}
	return n
}

func (s Schedule) dayMatches(t time.Time) bool {
	dom := s.dom&(1<<uint(t.Day())) != 0
	dow := s.dow&(1<<uint(t.Weekday())) != 0
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return dow
	case s.dowStar:
		return dom
	default:
		return dom || dow // cron semantics: either restriction matches
	}
}

// Next returns the first time after t that matches, or the zero time if
// none exists within five years (for example 30 February).
func (s Schedule) Next(t time.Time) time.Time {
	t = t.Truncate(time.Minute).Add(time.Minute)
	limit := t.AddDate(5, 0, 0)
	for t.Before(limit) {
		if s.month&(1<<uint(t.Month())) == 0 {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}
		if !s.dayMatches(t) {
			t = time.Date(t.Year(), t.Month(), t.Day()+1, 0, 0, 0, 0, t.Location())
			continue
		}
		if s.hour&(1<<uint(t.Hour())) == 0 {
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour()+1, 0, 0, 0, t.Location())
			continue
		}
		if s.min&(1<<uint(t.Minute())) == 0 {
			t = t.Add(time.Minute)
			continue
		}
		return t
	}
	return time.Time{}
}

// Retention keeps snapshots of one plan (AT-F14-04). A snapshot is kept if
// any rule keeps it; the newest snapshot is always kept.
type Retention struct {
	KeepLast    int `json:"keep_last"`
	KeepDaily   int `json:"keep_daily"`
	KeepWeekly  int `json:"keep_weekly"`
	KeepMonthly int `json:"keep_monthly"`
}

func (r Retention) validate() error {
	for _, v := range []int{r.KeepLast, r.KeepDaily, r.KeepWeekly, r.KeepMonthly} {
		if v < 0 || v > 1000 {
			return errors.New("retention values must be 0..1000")
		}
	}
	if r.KeepLast+r.KeepDaily+r.KeepWeekly+r.KeepMonthly == 0 {
		return errors.New("retention must keep at least one snapshot")
	}
	return nil
}

// Forget returns the snapshots (by time) that the policy does not keep.
func (r Retention) Forget(times map[string]time.Time) []string {
	ids := make([]string, 0, len(times))
	for id := range times {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return times[ids[i]].After(times[ids[j]]) }) // newest first
	keep := map[string]bool{}
	bucket := func(n int, key func(time.Time) string) {
		seen := map[string]bool{}
		for _, id := range ids {
			if len(seen) >= n {
				return
			}
			k := key(times[id].Local())
			if !seen[k] {
				seen[k] = true
				keep[id] = true
			}
		}
	}
	for i, id := range ids {
		if i < r.KeepLast || i == 0 {
			keep[id] = true
		}
	}
	bucket(r.KeepDaily, func(t time.Time) string { return t.Format("2006-01-02") })
	bucket(r.KeepWeekly, func(t time.Time) string { y, w := t.ISOWeek(); return fmt.Sprint(y, "-", w) })
	bucket(r.KeepMonthly, func(t time.Time) string { return t.Format("2006-01") })
	var out []string
	for _, id := range ids {
		if !keep[id] {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
