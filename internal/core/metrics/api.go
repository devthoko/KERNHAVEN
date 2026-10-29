package metrics

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

// Errors of the metrics API.
var (
	ErrUnavailable = errors.New("not configured")
	ErrNoData      = errors.New("no reading yet")
	ErrRange       = errors.New("range must be 1h, 24h or 7d")
)

// HostNow returns the latest host snapshot.
func (s *Service) HostNow() (Host, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.monitor == nil {
		return Host{}, ErrUnavailable
	}
	if s.host == nil {
		if s.hostErr != nil {
			return Host{}, s.hostErr
		}
		return Host{}, ErrNoData
	}
	return *s.host, nil
}

// ContainersNow returns the latest container snapshots.
func (s *Service) ContainersNow() ([]Container, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.docker == nil {
		return nil, ErrUnavailable
	}
	if s.containers == nil && s.contErr != nil {
		return nil, s.contErr
	}
	return append([]Container{}, s.containers...), nil
}

// SeriesInfo names a series.
type SeriesInfo struct {
	Key  string `json:"key"`
	Unit string `json:"unit"`
}

// Series lists the series in memory and in the database.
func (s *Service) Series(ctx context.Context) ([]SeriesInfo, error) {
	seen := map[string]string{}
	rows, err := s.db.QueryContext(ctx, `SELECT key, unit FROM metric_series`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, u string
		if err := rows.Scan(&k, &u); err != nil {
			rows.Close()
			return nil, err
		}
		seen[k] = u
	}
	rows.Close()
	s.mu.Lock()
	for k, sr := range s.series {
		seen[k] = sr.unit
	}
	s.mu.Unlock()
	out := make([]SeriesInfo, 0, len(seen))
	for k, u := range seen {
		out = append(out, SeriesInfo{Key: k, Unit: u})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out, nil
}

// History is the points of one series in a range.
type History struct {
	Series     string  `json:"series"`
	Unit       string  `json:"unit"`
	Resolution int     `json:"resolution"` // seconds
	Points     []Point `json:"points"`
}

// History returns 1h of raw samples, 24h of 1-minute or 7d of 15-minute points.
func (s *Service) History(ctx context.Context, key, rng string) (History, error) {
	now := s.now()
	h := History{Series: key, Points: []Point{}}
	var res int64
	var from time.Time
	switch rng {
	case "1h":
		s.mu.Lock()
		defer s.mu.Unlock()
		sr := s.series[key]
		if sr == nil {
			return h, nil
		}
		h.Unit, h.Resolution = sr.unit, int(s.interval.Seconds())
		h.Points = append(h.Points, sr.raw...)
		return h, nil
	case "24h":
		res, from = 60, now.Add(-MinuteRetention)
	case "7d":
		res, from = 900, now.Add(-QuarterRetention)
	default:
		return h, ErrRange
	}
	h.Resolution = int(res)
	_ = s.db.QueryRowContext(ctx, `SELECT unit FROM metric_series WHERE key = ?`, key).Scan(&h.Unit)
	rows, err := s.db.QueryContext(ctx, `SELECT p.ts, p.avg, p.max FROM metric_points p JOIN metric_series m ON m.id = p.series_id
		WHERE m.key = ? AND p.resolution = ? AND p.ts >= ? ORDER BY p.ts`, key, res, from.UnixMilli())
	if err != nil {
		return h, err
	}
	defer rows.Close()
	for rows.Next() {
		var ts int64
		var p Point
		if err := rows.Scan(&ts, &p.Avg, &p.Max); err != nil {
			return h, err
		}
		p.T = time.UnixMilli(ts).UTC()
		h.Points = append(h.Points, p)
	}
	return h, rows.Err()
}

// Average is the mean of the raw samples of key within d and how many there are.
func (s *Service) Average(key string, d time.Duration) (float64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sr := s.series[key]
	if sr == nil {
		return 0, 0
	}
	from := s.now().Add(-d)
	var sum float64
	n := 0
	for _, p := range sr.raw {
		if !p.T.Before(from) {
			sum += p.Avg
			n++
		}
	}
	if n == 0 {
		return 0, 0
	}
	return sum / float64(n), n
}

// IsContainerSeries reports whether key belongs to a container.
func IsContainerSeries(key string) bool { return strings.HasPrefix(key, "container.") }

// unavailable maps agent errors to the reason shown to users.
func unavailable(err error) string {
	var ae *agentclient.Error
	switch {
	case errors.As(err, &ae):
		return ae.Message
	case errors.Is(err, agentclient.ErrUnavailable):
		return "not reachable"
	default:
		return err.Error()
	}
}
