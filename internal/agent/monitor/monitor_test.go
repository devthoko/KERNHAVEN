package monitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestFixture(t *testing.T) {
	dir := t.TempDir()
	proc, sys := filepath.Join(dir, "proc"), filepath.Join(dir, "sys")
	write(t, filepath.Join(proc, "stat"), "cpu  100 10 50 800 20 5 5 10 7 0\ncpu0 50 5 25 400 10 2 3 5 3 0\ncpu1 50 5 25 400 10 3 2 5 4 0\nintr 1 2 3\n")
	write(t, filepath.Join(proc, "meminfo"), "MemTotal:       16000000 kB\nMemFree:         2000000 kB\nMemAvailable:    6000000 kB\nSwapTotal:       1000000 kB\nSwapFree:         250000 kB\n")
	write(t, filepath.Join(proc, "loadavg"), "0.52 0.48 0.40 2/345 6789\n")
	write(t, filepath.Join(proc, "diskstats"), `   8       0 sda 100 0 2000 0 50 0 4000 0 0 0 0
   8       1 sda1 90 0 1800 0 40 0 3600 0 0 0 0
   7       0 loop0 5 0 80 0 0 0 0 0 0 0 0
 253       0 dm-0 10 0 300 0 20 0 600 0 0 0 0
 259       0 nvme0n1 10 0 1 0 10 0 2 0 0 0 0
`)
	for _, d := range []string{"sda", "loop0", "dm-0", "nvme0n1"} {
		write(t, filepath.Join(sys, "block", d, "size"), "1")
	}
	write(t, filepath.Join(proc, "net", "dev"), `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0
  eth0: 123456 100 0 0 0 0 0 0 654321 90 0 0 0 0 0 0
`)
	write(t, filepath.Join(sys, "class", "hwmon", "hwmon0", "name"), "coretemp\n")
	write(t, filepath.Join(sys, "class", "hwmon", "hwmon0", "temp1_input"), "45000\n")
	write(t, filepath.Join(sys, "class", "hwmon", "hwmon0", "temp1_label"), "Package id 0\n")
	write(t, filepath.Join(sys, "class", "hwmon", "hwmon0", "temp2_input"), "41500\n")
	write(t, filepath.Join(sys, "class", "hwmon", "hwmon1", "name"), "nvme\n")
	write(t, filepath.Join(sys, "class", "hwmon", "hwmon1", "temp1_input"), "junk\n")

	r := &Reader{Proc: proc, Sys: sys, Now: func() time.Time { return time.UnixMilli(1000) }}
	m, err := r.Metrics(context.Background())
	if err != nil || m.Errors != nil {
		t.Fatalf("%v %v", err, m.Errors)
	}
	// total = 100+10+50+800+20+5+5+10 = 1000; idle = 800+20.
	if m.CPUTotal != 1000 || m.CPUBusy != 180 || m.CPUs != 2 || m.TakenAtMS != 1000 {
		t.Fatalf("cpu %+v", m)
	}
	if m.Memory.Total != 16000000*1024 || m.Memory.Available != 6000000*1024 || m.Memory.SwapFree != 250000*1024 {
		t.Fatalf("memory %+v", m.Memory)
	}
	if m.Load != [3]float64{0.52, 0.48, 0.40} {
		t.Fatalf("load %v", m.Load)
	}
	if len(m.Disks) != 2 || m.Disks[0].Name != "sda" || m.Disks[0].In != 2000*512 || m.Disks[0].Out != 4000*512 || m.Disks[1].Name != "nvme0n1" {
		t.Fatalf("disks %+v", m.Disks)
	}
	if len(m.Interfaces) != 1 || m.Interfaces[0].Name != "eth0" || m.Interfaces[0].In != 123456 || m.Interfaces[0].Out != 654321 {
		t.Fatalf("interfaces %+v", m.Interfaces)
	}
	if len(m.Temperatures) != 2 || m.Temperatures[0].Sensor != "coretemp/Package id 0" || m.Temperatures[0].Celsius != 45 || m.Temperatures[1].Sensor != "coretemp/temp2" {
		t.Fatalf("temperatures %+v", m.Temperatures)
	}

	// Missing sources are reported, not fatal.
	os.Remove(filepath.Join(proc, "loadavg"))
	os.RemoveAll(filepath.Join(sys, "class"))
	m, err = r.Metrics(context.Background())
	if err != nil || m.Errors["load"] == "" || m.Errors["temperatures"] != "" || len(m.Temperatures) != 0 || m.CPUTotal != 1000 {
		t.Fatalf("partial: %v %+v", err, m)
	}
}

func TestRealHost(t *testing.T) {
	m, err := New().Metrics(context.Background())
	if err != nil || m.CPUTotal == 0 || m.CPUs == 0 || m.Memory.Total == 0 || m.Memory.Available > m.Memory.Total {
		t.Fatalf("%v %+v", err, m)
	}
	if m.Errors["cpu"] != "" || m.Errors["memory"] != "" || m.Errors["interfaces"] != "" {
		t.Fatalf("errors %v", m.Errors)
	}
}
