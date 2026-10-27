//go:build storage_integration

package agent

// These tests talk to a real kernhaven-agent in the storage role, started by
// systemd as root with deploy/systemd/kernhaven-storage.service, on a
// disposable CI runner. The "disk" is a loop device backed by a file.
//
//	KH_STORAGE_KEYDIR  directory for the Core grant key (agent-grant.pub is read by the service)
//	KH_STORAGE_SOCKET  the service's socket
//	KH_STORAGE_LOOP    the loop device, e.g. /dev/loop7
//	KH_STORAGE_ROOT    the configured mount_root

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

func mustEnv(t *testing.T, name string) string {
	t.Helper()
	v := os.Getenv(name)
	if v == "" {
		t.Fatalf("%s must be set for storage integration tests", name)
	}
	return v
}

// TestM9WriteKey creates the Core's grant key before the service starts.
func TestM9WriteKey(t *testing.T) {
	if _, err := agentclient.LoadOrCreateKey(mustEnv(t, "KH_STORAGE_KEYDIR")); err != nil {
		t.Fatal(err)
	}
}

func storageClient(t *testing.T) func(op string, params, out any) error {
	t.Helper()
	key, err := agentclient.LoadOrCreateKey(mustEnv(t, "KH_STORAGE_KEYDIR"))
	if err != nil {
		t.Fatal(err)
	}
	cl := agentclient.New(mustEnv(t, "KH_STORAGE_SOCKET"), key)
	return func(op string, params, out any) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		return cl.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: "it", RequestID: "it"}, out)
	}
}

func inventory(t *testing.T, do func(string, any, any) error) agentproto.StorageInventory {
	t.Helper()
	var inv agentproto.StorageInventory
	if err := do(agentproto.OpStorageInventory, nil, &inv); err != nil {
		t.Fatalf("inventory: %v", err)
	}
	return inv
}

func diskByPath(t *testing.T, inv agentproto.StorageInventory, p string) agentproto.Disk {
	t.Helper()
	for _, d := range inv.Disks {
		if d.Path == p {
			return d
		}
	}
	t.Fatalf("%s not in inventory %+v", p, inv.Disks)
	return agentproto.Disk{}
}

func mounted(where string) string {
	b, _ := os.ReadFile("/proc/mounts")
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) > 2 && f[1] == where {
			return f[2]
		}
	}
	return ""
}

// AT-F06-01..03 and TH-32 with real tools, systemd and the unit's sandbox.
func TestM9StorageService(t *testing.T) {
	do := storageClient(t)
	loop, root := mustEnv(t, "KH_STORAGE_LOOP"), mustEnv(t, "KH_STORAGE_ROOT")

	// Docker operations do not exist in the storage role.
	if err := do(agentproto.OpContainersList, agentproto.ContainersList{}, nil); errCode(err) != agentproto.CodeUnknownOp {
		t.Fatalf("containers.list in the storage role: %v", err)
	}

	inv := inventory(t, do)
	if !inv.Privileged || inv.MountRoot != root || len(inv.FileSystems) != 3 {
		t.Fatalf("inventory header %+v", inv)
	}
	// TH-32: the runner's system disk is classified and refused.
	var sys *agentproto.Disk
	for i := range inv.Disks {
		if inv.Disks[i].Class == agentproto.DiskSystem {
			sys = &inv.Disks[i]
		}
	}
	if sys == nil || sys.Formattable {
		t.Fatalf("no system disk found or it is formattable: %+v", inv.Disks)
	}
	err := do(agentproto.OpStorageFormat, agentproto.StorageFormat{Path: sys.Path, Serial: sys.Serial, WWN: sys.WWN, SizeBytes: sys.SizeBytes, FSType: "ext4", Label: "never"}, nil)
	if errCode(err) != agentproto.CodeInvalidParams || !strings.Contains(err.Error(), "operating system") {
		t.Fatalf("formatting the system disk: %v", err)
	}

	for _, fs := range []string{"ext4", "xfs", "btrfs"} {
		t.Run(fs, func(t *testing.T) {
			d := diskByPath(t, inventory(t, do), loop)
			if !d.Formattable {
				t.Fatalf("loop disk not formattable: %+v", d)
			}
			if err := do(agentproto.OpStorageFormat, agentproto.StorageFormat{Path: loop, SizeBytes: d.SizeBytes + 512, FSType: fs, Label: "it"}, nil); errCode(err) != agentproto.CodeInvalidParams {
				t.Fatalf("changed identity accepted: %v", err)
			}
			var res agentproto.StorageFormatResult
			if err := do(agentproto.OpStorageFormat, agentproto.StorageFormat{Path: loop, Serial: d.Serial, WWN: d.WWN, SizeBytes: d.SizeBytes, FSType: fs, Label: "kh-" + fs}, &res); err != nil {
				t.Fatalf("format: %v", err)
			}
			if res.UUID == "" || !strings.HasPrefix(res.Partition, loop) {
				t.Fatalf("format result %+v", res)
			}
			name := "it-" + fs
			var m agentproto.ManagedMount
			if err := do(agentproto.OpStorageMount, agentproto.StorageMount{Path: res.Partition, UUID: res.UUID, Name: name}, &m); err != nil {
				t.Fatalf("mount: %v", err)
			}
			where := filepath.Join(root, name)
			if got := mounted(where); got != fs {
				t.Fatalf("%s mounted as %q", where, got)
			}
			if err := os.WriteFile(filepath.Join(where, "hello"), []byte(fs), 0o600); err != nil {
				t.Fatalf("write to the disk: %v", err)
			}
			if out, err := exec.Command("systemctl", "is-enabled", m.Unit).Output(); err != nil || strings.TrimSpace(string(out)) != "enabled" {
				t.Fatalf("unit %s not enabled: %s %v", m.Unit, out, err)
			}
			unit, _ := os.ReadFile(filepath.Join("/etc/systemd/system", m.Unit))
			if !strings.Contains(string(unit), "Options=nofail,nosuid,nodev") || !strings.Contains(string(unit), "by-uuid/"+res.UUID) {
				t.Fatalf("unit:\n%s", unit)
			}
			// A mounted disk is not offered for formatting.
			d = diskByPath(t, inventory(t, do), loop)
			if d.Formattable || d.Class != agentproto.DiskManaged {
				t.Fatalf("mounted disk: %+v", d)
			}
			if err := do(agentproto.OpStorageFormat, agentproto.StorageFormat{Path: loop, Serial: d.Serial, WWN: d.WWN, SizeBytes: d.SizeBytes, FSType: fs, Label: "x"}, nil); errCode(err) != agentproto.CodeInvalidParams {
				t.Fatalf("formatting a mounted disk: %v", err)
			}
			// Busy: a process keeps the mount open.
			hold := exec.Command("sleep", "30")
			hold.Dir = where
			if err := hold.Start(); err != nil {
				t.Fatal(err)
			}
			busy := do(agentproto.OpStorageUnmount, agentproto.StorageUnmount{Name: name}, nil)
			_ = hold.Process.Kill()
			_ = hold.Wait()
			if errCode(busy) != agentproto.CodeConflict || mounted(where) == "" {
				t.Fatalf("busy unmount: %v (mounted: %q)", busy, mounted(where))
			}
			if err := do(agentproto.OpStorageUnmount, agentproto.StorageUnmount{Name: name}, nil); err != nil {
				t.Fatalf("unmount: %v", err)
			}
			if mounted(where) != "" {
				t.Fatal("still mounted")
			}
			if _, err := os.Stat(filepath.Join("/etc/systemd/system", m.Unit)); !os.IsNotExist(err) {
				t.Fatal("unit file left behind")
			}
		})
	}
}

func errCode(err error) string {
	var ae *agentclient.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}
