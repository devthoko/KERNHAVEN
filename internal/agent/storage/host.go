package storage

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Runner executes one host tool. The real runner resolves tools once from a
// fixed search path; tests record calls.
type Runner interface {
	// Run executes tool (a name from the fixed set) and returns stdout and
	// the exit code; err is set when the tool is missing or could not run.
	Run(ctx context.Context, tool string, args []string, stdin []byte) (stdout []byte, exitCode int, err error)
	// Has reports whether tool is installed.
	Has(tool string) bool
}

// ErrToolMissing means a required host tool is not installed.
var ErrToolMissing = errors.New("required host tool is not installed")

// Tools the agent may run (ADR-0022).
var knownTools = []string{"lsblk", "smartctl", "sfdisk", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "udevadm", "systemctl"}

// ExecRunner runs tools found in the fixed search path.
type ExecRunner struct {
	paths map[string]string
}

// NewExecRunner resolves the known tools in /usr/sbin, /usr/bin, /sbin, /bin.
func NewExecRunner() *ExecRunner {
	r := &ExecRunner{paths: map[string]string{}}
	for _, t := range knownTools {
		for _, dir := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
			p := filepath.Join(dir, t)
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
				r.paths[t] = p
				break
			}
		}
	}
	return r
}

// Has reports whether tool was found.
func (r *ExecRunner) Has(tool string) bool { return r.paths[tool] != "" }

// Run executes the tool without a shell, with a minimal environment.
func (r *ExecRunner) Run(ctx context.Context, tool string, args []string, stdin []byte) ([]byte, int, error) {
	p := r.paths[tool]
	if p == "" {
		return nil, -1, fmt.Errorf("%w: %s", ErrToolMissing, tool)
	}
	cmd := exec.CommandContext(ctx, p, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &limitedWriter{w: &errOut, n: 4096}
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		msg := strings.TrimSpace(errOut.String())
		if msg == "" {
			msg = ee.Error()
		}
		return out.Bytes(), ee.ExitCode(), fmt.Errorf("%s: %s", tool, msg)
	}
	if err != nil {
		return nil, -1, fmt.Errorf("%s: %w", tool, err)
	}
	return out.Bytes(), 0, nil
}

type limitedWriter struct {
	w *bytes.Buffer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if room := l.n - l.w.Len(); room > 0 {
		if len(p) > room {
			l.w.Write(p[:room])
		} else {
			l.w.Write(p)
		}
	}
	return len(p), nil
}

// Config configures the storage host.
type Config struct {
	MountRoot   string // absolute, clean, not "/"
	UnitDir     string // default /etc/systemd/system
	IncludeLoop bool   // test only: treat loop devices as disks
	// Privileged reports whether destructive operations may run; nil means
	// "the process runs as root". Tests that use a fake Runner set it.
	Privileged func() bool
}

// Host performs the storage operations.
type Host struct {
	run        Runner
	cfg        Config
	privileged func() bool
}

// DefaultMountRoot is where data disks are mounted.
const DefaultMountRoot = "/srv/kernhaven"

// New returns a storage host.
func New(r Runner, cfg Config) *Host {
	if cfg.UnitDir == "" {
		cfg.UnitDir = "/etc/systemd/system"
	}
	if cfg.MountRoot == "" {
		cfg.MountRoot = DefaultMountRoot
	}
	priv := cfg.Privileged
	if priv == nil {
		priv = func() bool { return os.Geteuid() == 0 }
	}
	return &Host{run: r, cfg: cfg, privileged: priv}
}

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	labelRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,12}$`)
	devRe   = regexp.MustCompile(`^/dev/[a-zA-Z0-9][a-zA-Z0-9_./-]{0,62}$`)
	uuidRe  = regexp.MustCompile(`^[A-Fa-f0-9-]{4,64}$`)
)

func (h *Host) mkfsTools() []string {
	var out []string
	for _, fs := range []string{"btrfs", "ext4", "xfs"} {
		if h.run.Has("mkfs." + fs) {
			out = append(out, fs)
		}
	}
	return out
}

func (h *Host) lsblk(ctx context.Context) ([]blockDevice, error) {
	out, _, err := h.run.Run(ctx, "lsblk", []string{"--json", "--bytes", "--output", lsblkColumns}, nil)
	if err != nil {
		return nil, err
	}
	return parseLsblk(out)
}

func (h *Host) classified(ctx context.Context) ([]agentproto.Disk, []agentproto.ManagedMount, error) {
	devs, err := h.lsblk(ctx)
	if err != nil {
		return nil, nil, err
	}
	mounts := h.managedMounts()
	byPath := map[string]string{}
	for _, m := range mounts {
		byPath[m.Path] = m.Name
	}
	disks := classify(devs, byPath, h.cfg.IncludeLoop, h.mkfsTools())
	active := map[string]bool{}
	for _, d := range disks {
		for _, fs := range d.FileSystems {
			for _, mp := range fs.Mountpoints {
				active[mp] = true
			}
		}
	}
	for i := range mounts {
		mounts[i].Active = active[mounts[i].Path]
	}
	return disks, mounts, nil
}

// Inventory lists disks, file systems, SMART health and Kernhaven mounts
// (AT-F06-01).
func (h *Host) Inventory(ctx context.Context) (agentproto.StorageInventory, error) {
	disks, mounts, err := h.classified(ctx)
	if err != nil {
		return agentproto.StorageInventory{}, err
	}
	inv := agentproto.StorageInventory{Disks: disks, Mounts: mounts, MountRoot: h.cfg.MountRoot, FileSystems: orEmpty(h.mkfsTools()),
		SMART: h.run.Has("smartctl"), Privileged: h.privileged()}
	for i := range inv.Disks {
		d := &inv.Disks[i]
		switch {
		case !inv.SMART:
			d.SMART = agentproto.SMART{Message: "smartmontools is not installed"}
		case strings.HasPrefix(d.Name, "loop"):
			d.SMART = agentproto.SMART{Message: "SMART is not available for loop devices"}
		default:
			sctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			out, code, err := h.run.Run(sctx, "smartctl", []string{"--json=c", "-H", "-A", "-i", d.Path}, nil)
			cancel()
			if err != nil && len(out) == 0 {
				d.SMART = agentproto.SMART{Message: err.Error()}
			} else {
				d.SMART = parseSMART(out, code)
			}
		}
	}
	return inv, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func findDisk(disks []agentproto.Disk, p string) (agentproto.Disk, bool) {
	for _, d := range disks {
		if d.Path == p {
			return d, true
		}
	}
	return agentproto.Disk{}, false
}

// Format creates one GPT partition over a free disk and a file system on it
// (AT-F06-03). The disk is re-classified first; the system disk, disks in
// use and disks whose identity changed are refused.
func (h *Host) Format(ctx context.Context, p agentproto.StorageFormat) (agentproto.StorageFormatResult, error) {
	if !devRe.MatchString(p.Path) || strings.Contains(p.Path, "..") {
		return agentproto.StorageFormatResult{}, invalid("invalid device path")
	}
	if !labelRe.MatchString(p.Label) {
		return agentproto.StorageFormatResult{}, invalid("the label must be 1-12 letters, digits, _ or -")
	}
	if !h.run.Has("mkfs." + p.FSType) {
		return agentproto.StorageFormatResult{}, invalid("file system %q is not available on this host", p.FSType)
	}
	if !h.privileged() {
		return agentproto.StorageFormatResult{}, invalid("formatting needs the agent to run as root")
	}
	disks, _, err := h.classified(ctx)
	if err != nil {
		return agentproto.StorageFormatResult{}, err
	}
	d, ok := findDisk(disks, p.Path)
	if !ok {
		return agentproto.StorageFormatResult{}, ErrNotFound
	}
	if d.SizeBytes != p.SizeBytes || d.Serial != p.Serial || d.WWN != p.WWN {
		return agentproto.StorageFormatResult{}, invalid("%s is not the disk that was confirmed (serial, WWN or size changed); reload and confirm again", p.Path)
	}
	if !d.Formattable {
		reason := d.Reason
		if reason == "" {
			reason = "it is " + d.Class
		}
		return agentproto.StorageFormatResult{}, invalid("%s cannot be formatted: %s", p.Path, reason)
	}
	if _, _, err := h.run.Run(ctx, "sfdisk", []string{"--wipe", "always", "--wipe-partitions", "always", "--quiet", p.Path}, []byte("label: gpt\n,,L\n")); err != nil {
		return agentproto.StorageFormatResult{}, err
	}
	h.settle(ctx)
	part, err := h.onlyPartition(ctx, p.Path)
	if err != nil {
		return agentproto.StorageFormatResult{}, err
	}
	var args []string
	switch p.FSType {
	case "ext4":
		args = []string{"-F", "-q", "-E", "nodiscard", "-L", p.Label, part}
	case "xfs":
		args = []string{"-f", "-q", "-K", "-L", p.Label, part}
	case "btrfs":
		args = []string{"-f", "-q", "--nodiscard", "-L", p.Label, part}
	}
	if _, _, err := h.run.Run(ctx, "mkfs."+p.FSType, args, nil); err != nil {
		return agentproto.StorageFormatResult{}, err
	}
	h.settle(ctx)
	devs, err := h.lsblk(ctx)
	if err != nil {
		return agentproto.StorageFormatResult{}, err
	}
	res := agentproto.StorageFormatResult{Partition: part, FSType: p.FSType}
	var find func([]blockDevice)
	find = func(list []blockDevice) {
		for _, b := range list {
			if b.Path == part {
				res.UUID = str(b.UUID)
			}
			find(b.Children)
		}
	}
	find(devs)
	return res, nil
}

func (h *Host) settle(ctx context.Context) {
	if h.run.Has("udevadm") {
		_, _, _ = h.run.Run(ctx, "udevadm", []string{"settle", "--timeout=30"}, nil)
	}
}

func (h *Host) onlyPartition(ctx context.Context, disk string) (string, error) {
	devs, err := h.lsblk(ctx)
	if err != nil {
		return "", err
	}
	for _, d := range devs {
		if d.Path != disk {
			continue
		}
		if len(d.Children) != 1 || d.Children[0].Type != "part" {
			return "", fmt.Errorf("expected one new partition on %s, found %d", disk, len(d.Children))
		}
		return d.Children[0].Path, nil
	}
	return "", ErrNotFound
}

// UnitName escapes a mount path like `systemd-escape --path --suffix=mount`.
func UnitName(p string) string {
	p = strings.Trim(path.Clean(p), "/")
	if p == "" {
		return "-.mount"
	}
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '/':
			b.WriteByte('-')
		case c == '.' && i == 0:
			fmt.Fprintf(&b, `\x%02x`, c)
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == ':', c == '_', c == '.':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, `\x%02x`, c)
		}
	}
	return b.String() + ".mount"
}

const unitMarker = "X-Kernhaven-Managed=yes"

func (h *Host) unitPath(mountPath string) string {
	return filepath.Join(h.cfg.UnitDir, UnitName(mountPath))
}

// managedMounts reads Kernhaven's mount units below the mount root.
func (h *Host) managedMounts() []agentproto.ManagedMount {
	entries, err := os.ReadDir(h.cfg.UnitDir)
	if err != nil {
		return []agentproto.ManagedMount{}
	}
	out := []agentproto.ManagedMount{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".mount") || !e.Type().IsRegular() {
			continue
		}
		m, ok := h.readUnit(filepath.Join(h.cfg.UnitDir, e.Name()))
		if ok {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (h *Host) readUnit(file string) (agentproto.ManagedMount, bool) {
	f, err := os.Open(file)
	if err != nil {
		return agentproto.ManagedMount{}, false
	}
	defer f.Close()
	var m agentproto.ManagedMount
	marked := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		k, v, _ := strings.Cut(line, "=")
		switch {
		case line == unitMarker:
			marked = true
		case k == "What":
			m.What = v
		case k == "Where":
			m.Path = v
		case k == "Type":
			m.FSType = v
		}
	}
	m.Name = path.Base(m.Path)
	m.Unit = filepath.Base(file)
	ok := marked && underRoot(h.cfg.MountRoot, m.Path) && nameRe.MatchString(m.Name) && m.Unit == UnitName(m.Path)
	return m, ok
}

// Mount mounts a file system persistently below the mount root
// (AT-F06-02).
func (h *Host) Mount(ctx context.Context, p agentproto.StorageMount) (agentproto.ManagedMount, error) {
	if !nameRe.MatchString(p.Name) {
		return agentproto.ManagedMount{}, invalid("the name must be 1-31 characters: lowercase letters, digits and -")
	}
	if !devRe.MatchString(p.Path) || !uuidRe.MatchString(p.UUID) {
		return agentproto.ManagedMount{}, invalid("invalid device or UUID")
	}
	if !h.privileged() {
		return agentproto.ManagedMount{}, invalid("mounting needs the agent to run as root")
	}
	where := path.Join(h.cfg.MountRoot, p.Name)
	unitFile := h.unitPath(where)
	if _, err := os.Lstat(unitFile); err == nil {
		return agentproto.ManagedMount{}, invalid("%s is already used by a mount", where)
	}
	disks, _, err := h.classified(ctx)
	if err != nil {
		return agentproto.ManagedMount{}, err
	}
	var fs *agentproto.FileSystem
	for i := range disks {
		for j := range disks[i].FileSystems {
			if disks[i].FileSystems[j].Path == p.Path {
				fs = &disks[i].FileSystems[j]
			}
		}
	}
	if fs == nil {
		return agentproto.ManagedMount{}, ErrNotFound
	}
	if fs.UUID != p.UUID {
		return agentproto.ManagedMount{}, invalid("%s no longer has the file system that was selected; reload", p.Path)
	}
	if !fs.Mountable {
		return agentproto.ManagedMount{}, invalid("%s cannot be mounted (system disk, in use, already mounted or unsupported file system)", p.Path)
	}
	unit := fmt.Sprintf(`# Managed by Kernhaven. Remove it on the storage page.
[Unit]
Description=Kernhaven data disk %s
%s

[Mount]
What=/dev/disk/by-uuid/%s
Where=%s
Type=%s
Options=nofail,nosuid,nodev

[Install]
WantedBy=multi-user.target
`, p.Name, unitMarker, fs.UUID, where, fs.FSType)
	if err := os.MkdirAll(where, 0o755); err != nil {
		return agentproto.ManagedMount{}, err
	}
	tmp := unitFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(unit), 0o644); err != nil {
		return agentproto.ManagedMount{}, err
	}
	if err := os.Rename(tmp, unitFile); err != nil {
		_ = os.Remove(tmp)
		return agentproto.ManagedMount{}, err
	}
	name := filepath.Base(unitFile)
	if err := h.systemctl(ctx, "daemon-reload"); err != nil {
		_ = os.Remove(unitFile)
		_ = os.Remove(where)
		return agentproto.ManagedMount{}, err
	}
	if err := h.systemctl(ctx, "enable", "--now", name); err != nil {
		// Roll back: no unit may stay behind for a mount that failed.
		_ = h.systemctl(ctx, "disable", "--now", name)
		_ = os.Remove(unitFile)
		_ = h.systemctl(ctx, "daemon-reload")
		_ = os.Remove(where)
		return agentproto.ManagedMount{}, err
	}
	return agentproto.ManagedMount{Name: p.Name, Path: where, Unit: name, What: "/dev/disk/by-uuid/" + fs.UUID, FSType: fs.FSType, Active: true}, nil
}

func (h *Host) systemctl(ctx context.Context, args ...string) error {
	_, _, err := h.run.Run(ctx, "systemctl", args, nil)
	return err
}

// Unmount stops and removes a Kernhaven mount unit. Busy file systems are
// reported, not forced.
func (h *Host) Unmount(ctx context.Context, p agentproto.StorageUnmount) error {
	if !nameRe.MatchString(p.Name) {
		return invalid("invalid mount name")
	}
	if !h.privileged() {
		return invalid("unmounting needs the agent to run as root")
	}
	where := path.Join(h.cfg.MountRoot, p.Name)
	unitFile := h.unitPath(where)
	m, ok := h.readUnit(unitFile)
	if !ok {
		if _, err := os.Lstat(unitFile); err == nil {
			return invalid("%s was not created by Kernhaven", filepath.Base(unitFile))
		}
		return ErrNotFound
	}
	stopErr := h.systemctl(ctx, "disable", "--now", m.Unit)
	// systemd reports a busy mount only as a failed job: decide by the actual
	// mount state, and keep the unit enabled if the file system stays mounted.
	if h.isMounted(ctx, where) {
		_ = h.systemctl(ctx, "enable", m.Unit)
		return fmt.Errorf("%w: %s is still in use; stop the apps that use it first", ErrBusy, where)
	}
	if stopErr != nil {
		return stopErr
	}
	if err := os.Remove(unitFile); err != nil {
		return err
	}
	_ = h.systemctl(ctx, "daemon-reload")
	_ = os.Remove(where) // only succeeds when empty
	return nil
}

func (h *Host) isMounted(ctx context.Context, where string) bool {
	devs, err := h.lsblk(ctx)
	if err != nil {
		return false
	}
	var walk func([]blockDevice) bool
	walk = func(list []blockDevice) bool {
		for _, b := range list {
			for _, mp := range b.mounts() {
				if mp == where {
					return true
				}
			}
			if walk(b.Children) {
				return true
			}
		}
		return false
	}
	return walk(devs)
}
