// Package metrics samples host and container metrics, keeps one hour of raw
// samples in memory and stores 1-minute and 15-minute aggregates in SQLite
// (M14, ADR-0027). Host counters come from the monitor service, container
// counters from the Docker agent.
package metrics

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

// Retention and limits (AT-F13-03).
const (
	RawRetention     = time.Hour
	MinuteRetention  = 24 * time.Hour
	QuarterRetention = 7 * 24 * time.Hour
	MaxSeries        = 300
)

// Units of the series.
const (
	UnitPercent   = "percent"
	UnitBytes     = "bytes"
	UnitPerSecond = "bytes/s"
	UnitLoad      = "load"
	UnitCelsius   = "celsius"
)

// Point is one value at a time; Max equals Avg for raw samples.
type Point struct {
	T   time.Time `json:"t"`
	Avg float64   `json:"avg"`
	Max float64   `json:"max"`
}

// Rate is a per-device rate.
type Rate struct {
	Name string  `json:"name"`
	In   float64 `json:"in"`  // read or received, bytes/s
	Out  float64 `json:"out"` // written or sent, bytes/s
}

// Host is the latest host snapshot. Rates are nil until two readings exist.
type Host struct {
	SampledAt    time.Time                `json:"sampled_at"`
	CPUs         int                      `json:"cpus"`
	CPUPercent   *float64                 `json:"cpu_percent"`
	Load         [3]float64               `json:"load"`
	Memory       agentproto.MemoryInfo    `json:"memory"`
	MemoryUsed   uint64                   `json:"memory_used"`
	Disks        []Rate                   `json:"disks"`
	Interfaces   []Rate                   `json:"interfaces"`
	Temperatures []agentproto.Temperature `json:"temperatures"`
	Errors       map[string]string        `json:"errors,omitempty"`
}

// Container is the latest snapshot of a running container.
type Container struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CPUPercent  *float64 `json:"cpu_percent"` // share of the whole host
	Memory      uint64   `json:"memory"`
	MemoryLimit uint64   `json:"memory_limit"`
	NetRx       *float64 `json:"net_rx"`
	NetTx       *float64 `json:"net_tx"`
	BlockRead   *float64 `json:"block_read"`
	BlockWrite  *float64 `json:"block_write"`
}

type bucket struct {
	start    time.Time
	sum, max float64
	n        int
}

type series struct {
	id      int64
	unit    string
	raw     []Point
	minute  bucket
	quarter bucket
}

// Service collects and serves metrics.
type Service struct {
	db       *sql.DB
	monitor  *agentclient.Client // nil: no host metrics
	docker   *agentclient.Client // nil: no container metrics
	log      *slog.Logger
	now      func() time.Time
	interval time.Duration

	mu         sync.Mutex
	prevHost   *agentproto.HostMetrics
	prevCont   map[string]agentproto.ContainerStats
	prevContAt time.Time
	host       *Host
	hostErr    error
	containers []Container
	contErr    error
	series     map[string]*series
	capWarned  bool
	lastPrune  time.Time
}

// New returns the service.
func New(db *sql.DB, monitor, docker *agentclient.Client, interval time.Duration, log *slog.Logger, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{db: db, monitor: monitor, docker: docker, log: log, now: now, interval: interval, series: map[string]*series{}, prevCont: map[string]agentproto.ContainerStats{}}
}

// Run samples until ctx ends.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		s.Sample(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) call(ctx context.Context, cl *agentclient.Client, op string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, s.interval)
	defer cancel()
	return cl.Do(ctx, agentclient.Call{Op: op, Actor: "system", RequestID: "metrics"}, out)
}

// Sample takes one reading of the host and the containers.
func (s *Service) Sample(ctx context.Context) {
	now := s.now()
	var hm agentproto.HostMetrics
	var hostErr error
	if s.monitor != nil {
		hostErr = s.call(ctx, s.monitor, agentproto.OpHostMetrics, &hm)
	}
	var cs []agentproto.ContainerStats
	var contErr error
	if s.docker != nil {
		contErr = s.call(ctx, s.docker, agentproto.OpContainersStats, &cs)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.monitor != nil {
		s.hostErr = hostErr
		if hostErr == nil {
			s.recordHost(ctx, now, hm)
		}
	}
	if s.docker != nil {
		s.contErr = contErr
		if contErr == nil {
			s.recordContainers(ctx, now, cs)
		}
	}
	if now.Sub(s.lastPrune) >= 15*time.Minute {
		s.prune(ctx, now)
		s.lastPrune = now
	}
}

func rate(cur, prev uint64, dt float64) float64 {
	if cur < prev || dt <= 0 {
		return 0 // counter reset
	}
	return float64(cur-prev) / dt
}

func sumRates(cur, prev []agentproto.IOCounter, dt float64) ([]Rate, float64, float64) {
	old := map[string]agentproto.IOCounter{}
	for _, c := range prev {
		old[c.Name] = c
	}
	out := []Rate{}
	var in, outSum float64
	for _, c := range cur {
		p, ok := old[c.Name]
		if !ok {
			continue
		}
		r := Rate{Name: c.Name, In: rate(c.In, p.In, dt), Out: rate(c.Out, p.Out, dt)}
		in, outSum = in+r.In, outSum+r.Out
		out = append(out, r)
	}
	return out, in, outSum
}

var unsafeKey = regexp.MustCompile(`[^a-z0-9_.-]+`)

// keyPart turns a name into a series key segment.
func keyPart(name string) string {
	k := strings.Trim(unsafeKey.ReplaceAllString(strings.ToLower(name), "_"), "_.")
	if len(k) > 64 {
		k = k[:64]
	}
	if k == "" {
		k = "unnamed"
	}
	return k
}

func (s *Service) recordHost(ctx context.Context, now time.Time, m agentproto.HostMetrics) {
	h := &Host{SampledAt: now.UTC(), CPUs: m.CPUs, Load: m.Load, Memory: m.Memory, Disks: []Rate{}, Interfaces: []Rate{}, Temperatures: m.Temperatures, Errors: m.Errors}
	if m.Memory.Total >= m.Memory.Available {
		h.MemoryUsed = m.Memory.Total - m.Memory.Available
	}
	if p := s.prevHost; p != nil {
		dt := float64(m.TakenAtMS-p.TakenAtMS) / 1000
		if m.CPUTotal > p.CPUTotal && m.CPUBusy >= p.CPUBusy {
			v := float64(m.CPUBusy-p.CPUBusy) / float64(m.CPUTotal-p.CPUTotal) * 100
			h.CPUPercent = &v
			s.record(ctx, now, "host.cpu", UnitPercent, v)
		}
		var rd, wr, rx, tx float64
		h.Disks, rd, wr = sumRates(m.Disks, p.Disks, dt)
		h.Interfaces, rx, tx = sumRates(m.Interfaces, p.Interfaces, dt)
		s.record(ctx, now, "host.disk_read", UnitPerSecond, rd)
		s.record(ctx, now, "host.disk_write", UnitPerSecond, wr)
		s.record(ctx, now, "host.net_rx", UnitPerSecond, rx)
		s.record(ctx, now, "host.net_tx", UnitPerSecond, tx)
	}
	if m.Memory.Total > 0 {
		s.record(ctx, now, "host.memory", UnitBytes, float64(h.MemoryUsed))
	}
	s.record(ctx, now, "host.load1", UnitLoad, m.Load[0])
	for _, t := range m.Temperatures {
		s.record(ctx, now, "host.temp."+keyPart(t.Sensor), UnitCelsius, t.Celsius)
	}
	cp := m
	s.prevHost = &cp
	s.host = h
}

func (s *Service) recordContainers(ctx context.Context, now time.Time, cs []agentproto.ContainerStats) {
	out := []Container{}
	next := map[string]agentproto.ContainerStats{}
	dt := now.Sub(s.prevContAt).Seconds()
	for _, c := range cs {
		cur := Container{ID: c.ID, Name: c.Name, Memory: c.Memory, MemoryLimit: c.MemoryLimit}
		key := "container." + keyPart(c.Name) + "."
		if p, ok := s.prevCont[c.ID]; ok {
			if c.SystemNanos > p.SystemNanos && c.CPUNanos >= p.CPUNanos {
				v := float64(c.CPUNanos-p.CPUNanos) / float64(c.SystemNanos-p.SystemNanos) * 100
				cur.CPUPercent = &v
				s.record(ctx, now, key+"cpu", UnitPercent, v)
			}
			rx, tx, br, bw := rate(c.NetRx, p.NetRx, dt), rate(c.NetTx, p.NetTx, dt), rate(c.BlockRead, p.BlockRead, dt), rate(c.BlockWrite, p.BlockWrite, dt)
			cur.NetRx, cur.NetTx, cur.BlockRead, cur.BlockWrite = &rx, &tx, &br, &bw
			s.record(ctx, now, key+"net_rx", UnitPerSecond, rx)
			s.record(ctx, now, key+"net_tx", UnitPerSecond, tx)
			s.record(ctx, now, key+"blk_read", UnitPerSecond, br)
			s.record(ctx, now, key+"blk_write", UnitPerSecond, bw)
		}
		s.record(ctx, now, key+"memory", UnitBytes, float64(c.Memory))
		next[c.ID] = c
		out = append(out, cur)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	s.prevCont, s.prevContAt = next, now
	s.containers = out
}

// record adds a sample to a series: raw in memory, aggregates in SQLite when
// a minute or quarter hour is complete.
func (s *Service) record(ctx context.Context, now time.Time, key, unit string, v float64) {
	sr := s.series[key]
	if sr == nil {
		sr = &series{unit: unit}
		s.series[key] = sr
	}
	sr.raw = append(sr.raw, Point{T: now.UTC(), Avg: v, Max: v})
	cut := 0
	for cut < len(sr.raw) && now.Sub(sr.raw[cut].T) > RawRetention {
		cut++
	}
	sr.raw = sr.raw[cut:]
	s.add(ctx, key, sr, &sr.minute, 60, now, v)
	s.add(ctx, key, sr, &sr.quarter, 900, now, v)
}

func (s *Service) add(ctx context.Context, key string, sr *series, b *bucket, res int64, now time.Time, v float64) {
	start := now.Truncate(time.Duration(res) * time.Second)
	if b.n > 0 && !b.start.Equal(start) {
		s.flush(ctx, key, sr, b, res)
	}
	if b.n == 0 {
		*b = bucket{start: start}
	}
	b.sum += v
	b.n++
	if b.n == 1 || v > b.max {
		b.max = v
	}
}

func (s *Service) flush(ctx context.Context, key string, sr *series, b *bucket, res int64) {
	defer func() { *b = bucket{} }()
	id, err := s.seriesID(ctx, key, sr)
	if err != nil || id == 0 {
		return
	}
	end := b.start.Add(time.Duration(res) * time.Second).UnixMilli()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO metric_points (series_id, resolution, ts, avg, max) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT (series_id, resolution, ts) DO UPDATE SET avg = excluded.avg, max = excluded.max`,
		id, res, b.start.UnixMilli(), b.sum/float64(b.n), b.max); err != nil {
		s.log.Warn("storing metrics failed", "series", key, "error", err.Error())
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE metric_series SET last_ms = max(last_ms, ?) WHERE id = ?`, end, id)
}

// seriesID returns the stored series, creating it below the cap.
func (s *Service) seriesID(ctx context.Context, key string, sr *series) (int64, error) {
	if sr.id != 0 {
		return sr.id, nil
	}
	err := s.db.QueryRowContext(ctx, `SELECT id FROM metric_series WHERE key = ?`, key).Scan(&sr.id)
	if err == nil {
		return sr.id, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM metric_series`).Scan(&n); err != nil {
		return 0, err
	}
	if n >= MaxSeries {
		if !s.capWarned {
			s.capWarned = true
			s.log.Warn("metric series limit reached; new series are not stored", "limit", MaxSeries, "series", key)
		}
		return 0, nil
	}
	err = s.db.QueryRowContext(ctx, `INSERT INTO metric_series (key, unit, last_ms) VALUES (?, ?, ?) RETURNING id`, key, sr.unit, s.now().UnixMilli()).Scan(&sr.id)
	return sr.id, err
}

// prune deletes points past their retention and series without data for 7 days.
func (s *Service) prune(ctx context.Context, now time.Time) {
	for _, q := range []struct {
		sql string
		arg int64
	}{
		{`DELETE FROM metric_points WHERE resolution = 60 AND ts < ?`, now.Add(-MinuteRetention).UnixMilli()},
		{`DELETE FROM metric_points WHERE resolution = 900 AND ts < ?`, now.Add(-QuarterRetention).UnixMilli()},
		{`DELETE FROM metric_series WHERE last_ms < ?`, now.Add(-QuarterRetention).UnixMilli()},
	} {
		if _, err := s.db.ExecContext(ctx, q.sql, q.arg); err != nil {
			s.log.Warn("pruning metrics failed", "error", err.Error())
			return
		}
	}
	for key, sr := range s.series {
		if len(sr.raw) == 0 || now.Sub(sr.raw[len(sr.raw)-1].T) > RawRetention {
			delete(s.series, key) // no sample for an hour: the container is gone
		} else {
			sr.id = 0 // the stored series may have been deleted; look it up again
		}
	}
}
