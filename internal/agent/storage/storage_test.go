package storage

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func disksOf(t *testing.T, name string, managed map[string]string) map[string]agentproto.Disk {
	t.Helper()
	devs, err := parseLsblk(fixture(t, name))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]agentproto.Disk{}
	for _, d := range classify(devs, managed, false, []string{"ext4"}) {
		out[d.Name] = d
	}
	return out
}

// AT-F06-01, TH-32: classification of a typical homelab.
func TestClassifyHomelab(t *testing.T) {
	d := disksOf(t, "lsblk-homelab.json", map[string]string{"/srv/kernhaven/archive": "archive"})
	want := map[string]struct {
		class       string
		formattable bool
		reason      string
	}{
		"nvme0n1": {agentproto.DiskSystem, false, "operating system"},
		"sda":     {agentproto.DiskFree, true, ""},
		"sdb":     {agentproto.DiskFree, true, ""},
		"sdc":     {agentproto.DiskInUse, false, "LVM"},
		"sdd":     {agentproto.DiskInUse, false, "RAID"},
		"sde":     {agentproto.DiskInUse, false, "mounted at /media/user/STICK"},
		"sdf":     {agentproto.DiskManaged, false, ""},
		"sdg":     {agentproto.DiskInUse, false, "read-only"},
		"sdh":     {agentproto.DiskInUse, false, "mounted at /srv/kernhaven/manual"},
	}
	if len(d) != len(want) {
		t.Fatalf("disks %v (zram and optical drives must be skipped)", keys(d))
	}
	for name, w := range want {
		got := d[name]
		if got.Class != w.class || got.Formattable != w.formattable || !strings.Contains(got.Reason, w.reason) {
			t.Errorf("%s: class=%s formattable=%v reason=%q", name, got.Class, got.Formattable, got.Reason)
		}
	}
	sdb1 := d["sdb"].FileSystems[0]
	if !sdb1.Mountable || sdb1.FSType != "ext4" || sdb1.Label != "media" {
		t.Errorf("sdb1 %+v", sdb1)
	}
	sdf1 := d["sdf"].FileSystems[0]
	if sdf1.Mountable || sdf1.MountName != "archive" || sdf1.FSUsedBytes != 2000000000000 {
		t.Errorf("sdf1 %+v", sdf1)
	}
	for _, fs := range d["nvme0n1"].FileSystems {
		if fs.Mountable {
			t.Errorf("system file system %s offered for mounting", fs.Name)
		}
	}
	if d["sda"].Serial != "WD-FREE0001" || d["sda"].WWN != "0x50014ee2b1111111" || d["sda"].SizeBytes != 4000787030016 || !d["sde"].Removable {
		t.Errorf("identity fields %+v", d["sda"])
	}
}

func keys(m map[string]agentproto.Disk) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Recorded on khv01-dev (util-linux 2.41): one system disk, snaps, a DVD drive.
func TestClassifyDevServer(t *testing.T) {
	d := disksOf(t, "lsblk-devserver.json", nil)
	if len(d) != 1 || d["sda"].Class != agentproto.DiskSystem || d["sda"].Formattable {
		t.Fatalf("dev server %+v", d)
	}
}

// util-linux before 2.37: numbers as strings, single "mountpoint".
func TestClassifyOldLsblk(t *testing.T) {
	d := disksOf(t, "lsblk-old.json", nil)
	if d["vda"].Class != agentproto.DiskSystem || d["vdb"].Class != agentproto.DiskFree || d["vdb"].SizeBytes != 107374182400 ||
		d["vda"].FileSystems[0].FSUsedBytes != 5000000000 {
		t.Fatalf("old lsblk %+v", d)
	}
}

func TestParseSMART(t *testing.T) {
	ok := parseSMART(fixture(t, "smart-passed.json"), 0)
	if !ok.Available || ok.Passed == nil || !*ok.Passed || ok.TemperatureC != 34 || ok.PowerOnHours != 28123 {
		t.Errorf("passed %+v", ok)
	}
	bad := parseSMART(fixture(t, "smart-failed.json"), 8)
	if !bad.Available || bad.Passed == nil || *bad.Passed || !strings.Contains(bad.Message, "back up") {
		t.Errorf("failed %+v", bad)
	}
	un := parseSMART(fixture(t, "smart-unsupported.json"), 2)
	if un.Available || !strings.Contains(un.Message, "USB bridge") {
		t.Errorf("unsupported %+v", un)
	}
	if parseSMART([]byte("garbage"), 0).Available {
		t.Error("garbage accepted")
	}
}

func TestUnitName(t *testing.T) {
	cases := map[string]string{
		"/srv/kernhaven/media":   "srv-kernhaven-media.mount",
		"/srv/kernhaven/my-disk": `srv-kernhaven-my\x2ddisk.mount`,
		"/":                      "-.mount",
		"/a/.hidden":             "a-.hidden.mount",
		"/.dot":                  `\x2edot.mount`,
	}
	for in, want := range cases {
		if got := UnitName(in); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
		// Compare with systemd itself where available.
		if out, err := exec.Command("systemd-escape", "--path", "--suffix=mount", in).Output(); err == nil {
			if sys := strings.TrimSpace(string(out)); sys != want {
				t.Errorf("%s: systemd-escape says %s", in, sys)
			}
		}
	}
}

// fakeRunner serves lsblk output and records calls. onCall may change state.
type fakeRunner struct {
	mu     sync.Mutex
	lsblk  []byte
	tools  map[string]bool
	calls  []string
	stdin  map[string]string
	fail   map[string]error
	onCall func(f *fakeRunner, tool string, args []string)
}

func newFake(t *testing.T, lsblk string) *fakeRunner {
	return &fakeRunner{lsblk: fixture(t, lsblk), stdin: map[string]string{}, fail: map[string]error{},
		tools: map[string]bool{"lsblk": true, "sfdisk": true, "mkfs.ext4": true, "mkfs.btrfs": true, "udevadm": true, "systemctl": true}}
}

func (f *fakeRunner) Has(tool string) bool { return f.tools[tool] }

func (f *fakeRunner) Run(_ context.Context, tool string, args []string, stdin []byte) ([]byte, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.tools[tool] {
		return nil, -1, ErrToolMissing
	}
	call := tool + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if stdin != nil {
		f.stdin[tool] = string(stdin)
	}
	if f.onCall != nil {
		f.onCall(f, tool, args)
	}
	for prefix, err := range f.fail {
		if strings.HasPrefix(call, prefix) {
			return nil, 1, err
		}
	}
	if tool == "lsblk" {
		return f.lsblk, 0, nil
	}
	return nil, 0, nil
}

func (f *fakeRunner) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func newHost(r Runner, root, units string, root0 bool) *Host {
	return New(r, Config{MountRoot: root, UnitDir: units, Privileged: func() bool { return root0 }})
}

// AT-F06-03: formatting a free disk.
func TestFormat(t *testing.T) {
	f := newFake(t, "lsblk-homelab.json")
	// After partitioning, lsblk shows sda1; after mkfs, its UUID.
	f.onCall = func(f *fakeRunner, tool string, args []string) {
		switch tool {
		case "sfdisk":
			f.lsblk = []byte(strings.Replace(string(f.lsblk), `"mountpoints":[null]},
      {"name":"sdb"`, `"mountpoints":[null],"children":[{"name":"sda1","path":"/dev/sda1","type":"part","size":4000785989632,"ro":false,"rm":false,"rota":true,"fstype":null,"uuid":null,"mountpoints":[null]}]},
      {"name":"sdb"`, 1))
		case "mkfs.ext4":
			f.lsblk = []byte(strings.Replace(string(f.lsblk), `"fstype":null,"uuid":null,"mountpoints":[null]}]}`, `"fstype":"ext4","uuid":"new-uuid-0001","mountpoints":[null]}]}`, 1))
		}
	}
	h := newHost(f, "/srv/kernhaven", t.TempDir(), true)
	res, err := h.Format(context.Background(), agentproto.StorageFormat{Path: "/dev/sda", Serial: "WD-FREE0001", WWN: "0x50014ee2b1111111", SizeBytes: 4000787030016, FSType: "ext4", Label: "media"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Partition != "/dev/sda1" || res.UUID != "new-uuid-0001" {
		t.Fatalf("result %+v", res)
	}
	calls := strings.Join(f.callList(), "\n")
	for _, want := range []string{
		"sfdisk --wipe always --wipe-partitions always --quiet /dev/sda",
		"udevadm settle --timeout=30",
		"mkfs.ext4 -F -q -E nodiscard -L media /dev/sda1",
	} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing %q in\n%s", want, calls)
		}
	}
	if f.stdin["sfdisk"] != "label: gpt\n,,L\n" {
		t.Errorf("sfdisk script %q", f.stdin["sfdisk"])
	}
}

// TH-32: the agent refuses every unsafe format request before touching a disk.
func TestFormatRefusals(t *testing.T) {
	ok := agentproto.StorageFormat{Path: "/dev/sda", Serial: "WD-FREE0001", WWN: "0x50014ee2b1111111", SizeBytes: 4000787030016, FSType: "ext4", Label: "media"}
	cases := map[string]func(p *agentproto.StorageFormat){
		"system disk": func(p *agentproto.StorageFormat) {
			p.Path, p.Serial, p.WWN, p.SizeBytes = "/dev/nvme0n1", "S5GXNX0R1", "eui.002538b111b2", 512110190592
		},
		"LVM member": func(p *agentproto.StorageFormat) {
			p.Path, p.Serial, p.WWN, p.SizeBytes = "/dev/sdc", "LVMPV0003", "", 1000204886016
		},
		"mounted elsewhere": func(p *agentproto.StorageFormat) {
			p.Path, p.Serial, p.WWN, p.SizeBytes = "/dev/sde", "USB0005", "", 64023257088
		},
		"managed mount": func(p *agentproto.StorageFormat) {
			p.Path, p.Serial, p.WWN, p.SizeBytes = "/dev/sdh", "FOREIGN8", "", 3000592982016
		},
		"swapped disk":   func(p *agentproto.StorageFormat) { p.Serial = "WD-OTHER" },
		"size changed":   func(p *agentproto.StorageFormat) { p.SizeBytes-- },
		"unknown device": func(p *agentproto.StorageFormat) { p.Path = "/dev/sdz" },
		"path traversal": func(p *agentproto.StorageFormat) { p.Path = "/dev/../etc/shadow" },
		"bad label":      func(p *agentproto.StorageFormat) { p.Label = "too long label!" },
		"missing mkfs":   func(p *agentproto.StorageFormat) { p.FSType = "xfs" },
		"unknown fs":     func(p *agentproto.StorageFormat) { p.FSType = "ntfs" },
	}
	for name, mutate := range cases {
		f := newFake(t, "lsblk-homelab.json")
		h := newHost(f, "/srv/kernhaven", t.TempDir(), true)
		p := ok
		mutate(&p)
		if _, err := h.Format(context.Background(), p); err == nil {
			t.Errorf("%s: accepted", name)
		}
		for _, c := range f.callList() {
			if !strings.HasPrefix(c, "lsblk") {
				t.Errorf("%s: ran %q", name, c)
			}
		}
	}
	f := newFake(t, "lsblk-homelab.json")
	if _, err := newHost(f, "/srv/kernhaven", t.TempDir(), false).Format(context.Background(), ok); err == nil || !strings.Contains(err.Error(), "root") {
		t.Errorf("unprivileged: %v", err)
	}
}

// AT-F06-02: mount units.
func TestMountAndUnmount(t *testing.T) {
	root, units := t.TempDir(), t.TempDir()
	f := newFake(t, "lsblk-homelab.json")
	h := newHost(f, root, units, true)
	ctx := context.Background()
	m, err := h.Mount(ctx, agentproto.StorageMount{Path: "/dev/sdb1", UUID: "9a1e0b2c-2222-4c1d-8e7f-000000000002", Name: "media"})
	if err != nil {
		t.Fatal(err)
	}
	where := filepath.Join(root, "media")
	unit := UnitName(where)
	if m.Path != where || m.Unit != unit || m.FSType != "ext4" {
		t.Fatalf("mount %+v", m)
	}
	content, err := os.ReadFile(filepath.Join(units, unit))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"X-Kernhaven-Managed=yes", "What=/dev/disk/by-uuid/9a1e0b2c-2222-4c1d-8e7f-000000000002",
		"Where=" + where, "Type=ext4", "Options=nofail,nosuid,nodev", "WantedBy=multi-user.target"} {
		if !strings.Contains(string(content), want+"\n") {
			t.Errorf("unit lacks %q:\n%s", want, content)
		}
	}
	if st, err := os.Stat(where); err != nil || !st.IsDir() {
		t.Fatalf("mount point: %v", err)
	}
	calls := strings.Join(f.callList(), "\n")
	if !strings.Contains(calls, "systemctl daemon-reload\nsystemctl enable --now "+unit) {
		t.Fatalf("systemctl calls:\n%s", calls)
	}
	if list := h.managedMounts(); len(list) != 1 || list[0].Name != "media" {
		t.Fatalf("managed mounts %+v", list)
	}
	// The same name twice, other UUID, in-use disk, system disk, bad names.
	for name, p := range map[string]agentproto.StorageMount{
		"duplicate":  {Path: "/dev/sdb1", UUID: "9a1e0b2c-2222-4c1d-8e7f-000000000002", Name: "media"},
		"other uuid": {Path: "/dev/sdb1", UUID: "00000000-0000-0000-0000-000000000000", Name: "other"},
		"in use":     {Path: "/dev/sde1", UUID: "1234-ABCD", Name: "stick"},
		"system":     {Path: "/dev/nvme0n1p1", UUID: "A1B2-C3D4", Name: "efi"},
		"bad name":   {Path: "/dev/sdb1", UUID: "9a1e0b2c-2222-4c1d-8e7f-000000000002", Name: "../etc"},
	} {
		if _, err := h.Mount(ctx, p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	// Busy: the file system stays mounted after the stop; the unit is kept.
	plain := f.lsblk
	f.mu.Lock()
	f.lsblk = []byte(strings.Replace(string(plain), `"uuid":"9a1e0b2c-2222-4c1d-8e7f-000000000002","fssize":null,"fsused":null,"fsavail":null,"mountpoints":[null]`,
		`"uuid":"9a1e0b2c-2222-4c1d-8e7f-000000000002","fssize":null,"fsused":null,"fsavail":null,"mountpoints":["`+where+`"]`, 1))
	f.mu.Unlock()
	if err := h.Unmount(ctx, agentproto.StorageUnmount{Name: "media"}); !errors.Is(err, ErrBusy) {
		t.Fatalf("busy unmount: %v", err)
	}
	if _, err := os.Stat(filepath.Join(units, unit)); err != nil || !strings.HasSuffix(f.callList()[len(f.callList())-1], "systemctl enable "+unit) {
		t.Fatalf("unit not kept or not re-enabled: %v %v", err, f.callList())
	}
	f.mu.Lock()
	f.lsblk = plain
	f.mu.Unlock()
	if err := h.Unmount(ctx, agentproto.StorageUnmount{Name: "media"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(units, unit)); !os.IsNotExist(err) {
		t.Fatal("unit file left behind")
	}
	if !strings.Contains(strings.Join(f.callList(), "\n"), "systemctl disable --now "+unit) {
		t.Fatal("unit not disabled")
	}
	if err := h.Unmount(ctx, agentproto.StorageUnmount{Name: "media"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second unmount: %v", err)
	}
	// Units Kernhaven did not write are never touched.
	foreign := filepath.Join(units, UnitName(filepath.Join(root, "backup")))
	if err := os.WriteFile(foreign, []byte("[Mount]\nWhat=/dev/sdx1\nWhere="+filepath.Join(root, "backup")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var ie *InvalidError
	if err := h.Unmount(ctx, agentproto.StorageUnmount{Name: "backup"}); !errors.As(err, &ie) {
		t.Fatalf("foreign unit: %v", err)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Fatal("foreign unit removed")
	}
}

// A failing `systemctl enable` leaves no unit behind.
func TestMountRollback(t *testing.T) {
	root, units := t.TempDir(), t.TempDir()
	f := newFake(t, "lsblk-homelab.json")
	f.fail["systemctl enable"] = errors.New("mount failed: wrong fs type")
	h := newHost(f, root, units, true)
	if _, err := h.Mount(context.Background(), agentproto.StorageMount{Path: "/dev/sdb1", UUID: "9a1e0b2c-2222-4c1d-8e7f-000000000002", Name: "media"}); err == nil {
		t.Fatal("mount succeeded")
	}
	if entries, _ := os.ReadDir(units); len(entries) != 0 {
		t.Fatalf("units left: %v", entries)
	}
	if _, err := os.Stat(filepath.Join(root, "media")); !os.IsNotExist(err) {
		t.Fatal("mount point left")
	}
}

func TestInventoryWithoutTools(t *testing.T) {
	f := newFake(t, "lsblk-devserver.json")
	delete(f.tools, "mkfs.ext4")
	delete(f.tools, "mkfs.btrfs")
	inv, err := newHost(f, "/srv/kernhaven", t.TempDir(), false).Inventory(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.SMART || inv.Privileged || len(inv.FileSystems) != 0 || len(inv.Disks) != 1 || !strings.Contains(inv.Disks[0].SMART.Message, "not installed") {
		t.Fatalf("inventory %+v", inv)
	}
}
