// Package monitor is the monitor role of the agent (M14, ADR-0027): it reads
// host counters from /proc and /sys and nothing else.
package monitor

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// MaxSensors bounds the temperatures reported.
const MaxSensors = 64

// Reader reads from a proc and a sys tree (the real ones, or fixtures).
type Reader struct {
	Proc string
	Sys  string
	Now  func() time.Time
}

// New reads the host's /proc and /sys.
func New() *Reader { return &Reader{Proc: "/proc", Sys: "/sys", Now: time.Now} }

// Metrics reads every source; a source that cannot be read is reported in
// Errors instead of failing the whole reading (temperatures are often
// missing in virtual machines).
func (r *Reader) Metrics(context.Context) (agentproto.HostMetrics, error) {
	m := agentproto.HostMetrics{TakenAtMS: r.Now().UnixMilli(), Disks: []agentproto.IOCounter{}, Interfaces: []agentproto.IOCounter{}, Temperatures: []agentproto.Temperature{}}
	errs := map[string]string{}
	note := func(src string, err error) {
		if err != nil {
			errs[src] = err.Error()
		}
	}
	var err error
	m.CPUBusy, m.CPUTotal, m.CPUs, err = r.cpu()
	note("cpu", err)
	m.Memory, err = r.memory()
	note("memory", err)
	m.Load, err = r.load()
	note("load", err)
	m.Disks, err = r.disks()
	note("disks", err)
	m.Interfaces, err = r.interfaces()
	note("interfaces", err)
	m.Temperatures, err = r.temperatures()
	note("temperatures", err)
	if len(errs) > 0 {
		m.Errors = errs
	}
	return m, nil
}

func (r *Reader) open(name string) (*os.File, error) { return os.Open(filepath.Join(r.Proc, name)) }

// cpu sums the first line of /proc/stat. Guest time is already part of user
// time and is not added again; idle includes iowait.
func (r *Reader) cpu() (busy, total uint64, cpus int, err error) {
	f, err := r.open("stat")
	if err != nil {
		return 0, 0, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		switch {
		case fields[0] == "cpu":
			if len(fields) < 9 {
				return 0, 0, 0, fmt.Errorf("short cpu line")
			}
			var v [8]uint64
			for i := range v {
				if v[i], err = strconv.ParseUint(fields[i+1], 10, 64); err != nil {
					return 0, 0, 0, fmt.Errorf("cpu line: %w", err)
				}
				total += v[i]
			}
			busy = total - v[3] - v[4] // idle, iowait
		case strings.HasPrefix(fields[0], "cpu"):
			cpus++
		}
	}
	if total == 0 {
		return 0, 0, 0, fmt.Errorf("no cpu line")
	}
	return busy, total, cpus, sc.Err()
}

func (r *Reader) memory() (agentproto.MemoryInfo, error) {
	f, err := r.open("meminfo")
	if err != nil {
		return agentproto.MemoryInfo{}, err
	}
	defer f.Close()
	var m agentproto.MemoryInfo
	seen := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		v, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		v *= 1024 // kB
		switch k {
		case "MemTotal":
			m.Total, seen = v, seen+1
		case "MemAvailable":
			m.Available, seen = v, seen+1
		case "SwapTotal":
			m.SwapTotal = v
		case "SwapFree":
			m.SwapFree = v
		}
	}
	if seen < 2 {
		return m, fmt.Errorf("MemTotal or MemAvailable missing")
	}
	return m, sc.Err()
}

func (r *Reader) load() ([3]float64, error) {
	var l [3]float64
	b, err := os.ReadFile(filepath.Join(r.Proc, "loadavg"))
	if err != nil {
		return l, err
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return l, fmt.Errorf("short loadavg")
	}
	for i := range l {
		if l[i], err = strconv.ParseFloat(fields[i], 64); err != nil {
			return l, err
		}
	}
	return l, nil
}

var skipDisk = regexp.MustCompile(`^(loop|ram|zram|dm-|sr|fd)`)

// disks reads /proc/diskstats for whole disks (those in /sys/block), without
// loop, RAM and device-mapper devices, whose traffic is counted on the
// disks below them.
func (r *Reader) disks() ([]agentproto.IOCounter, error) {
	f, err := r.open("diskstats")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []agentproto.IOCounter{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 10 {
			continue
		}
		name := fields[2]
		if skipDisk.MatchString(name) {
			continue
		}
		if _, err := os.Stat(filepath.Join(r.Sys, "block", name)); err != nil {
			continue // a partition
		}
		rd, err1 := strconv.ParseUint(fields[5], 10, 64)
		wr, err2 := strconv.ParseUint(fields[9], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, agentproto.IOCounter{Name: name, In: rd * 512, Out: wr * 512})
	}
	return out, sc.Err()
}

// interfaces reads /proc/net/dev without the loopback interface.
func (r *Reader) interfaces() ([]agentproto.IOCounter, error) {
	f, err := r.open("net/dev")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseNetDev(f)
}

func parseNetDev(rd io.Reader) ([]agentproto.IOCounter, error) {
	out := []agentproto.IOCounter{}
	sc := bufio.NewScanner(rd)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue // header lines
		}
		name = strings.TrimSpace(name)
		fields := strings.Fields(rest)
		if name == "lo" || len(fields) < 9 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, agentproto.IOCounter{Name: name, In: rx, Out: tx})
	}
	return out, sc.Err()
}

// temperatures reads hwmon sensors (millidegrees Celsius).
func (r *Reader) temperatures() ([]agentproto.Temperature, error) {
	chips, err := filepath.Glob(filepath.Join(r.Sys, "class", "hwmon", "hwmon*"))
	if err != nil {
		return nil, err
	}
	sort.Strings(chips)
	out := []agentproto.Temperature{}
	for _, chip := range chips {
		name := readTrim(filepath.Join(chip, "name"))
		if name == "" {
			name = filepath.Base(chip)
		}
		inputs, _ := filepath.Glob(filepath.Join(chip, "temp*_input"))
		sort.Strings(inputs)
		for _, in := range inputs {
			v, err := strconv.ParseInt(readTrim(in), 10, 64)
			if err != nil {
				continue
			}
			prefix := strings.TrimSuffix(filepath.Base(in), "_input")
			label := readTrim(filepath.Join(chip, prefix+"_label"))
			if label == "" {
				label = prefix
			}
			out = append(out, agentproto.Temperature{Sensor: name + "/" + label, Celsius: float64(v) / 1000})
			if len(out) == MaxSensors {
				return out, nil
			}
		}
	}
	return out, nil
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil || len(b) > 256 {
		return ""
	}
	return strings.TrimSpace(string(b))
}
