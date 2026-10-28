package app

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	"github.com/devthoko/KERNHAVEN/internal/agent/storage"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
)

// hostTools plays the host tools for a storage service: it serves recorded
// lsblk output and reflects partitioning and mkfs in later output.
type hostTools struct {
	mu    sync.Mutex
	lsblk string
	calls []string
}

func (h *hostTools) Has(tool string) bool { return tool != "smartctl" && tool != "mkfs.xfs" }

func (h *hostTools) Run(_ context.Context, tool string, args []string, _ []byte) ([]byte, int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, tool+" "+strings.Join(args, " "))
	switch tool {
	case "lsblk":
		return []byte(h.lsblk), 0, nil
	case "sfdisk":
		h.lsblk = strings.Replace(h.lsblk, `"mountpoints":[null]},
      {"name":"sdb"`, `"mountpoints":[null],"children":[{"name":"sda1","path":"/dev/sda1","type":"part","size":4000785989632,"fstype":null,"uuid":null,"mountpoints":[null]}]},
      {"name":"sdb"`, 1)
	case "mkfs.ext4":
		h.lsblk = strings.Replace(h.lsblk, `"fstype":null,"uuid":null,"mountpoints":[null]}]}`, `"fstype":"ext4","uuid":"4f00d000-0000-4000-8000-00000000000a","mountpoints":[null]}]}`, 1)
	}
	return nil, 0, nil
}

func (h *hostTools) ran(prefix string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, c := range h.calls {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// withStorage starts a Core and a storage service (agent in the storage role)
// on the recorded homelab disks.
func withStorage(t *testing.T) (*harness, *hostTools, string) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "storage.sock")
	h := newHarnessWith(t, func(c *config.Config) { c.Agent.StorageSocket = sock })
	pub, err := agentproto.ReadPublicKey(filepath.Join(h.dataDir, "agent-grant.pub"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../../agent/storage/testdata/lsblk-homelab.json")
	if err != nil {
		t.Fatal(err)
	}
	tools := &hostTools{lsblk: string(b)}
	root := t.TempDir()
	host := storage.New(tools, storage.Config{MountRoot: root, UnitDir: t.TempDir(), Privileged: func() bool { return true }})
	srv := agent.NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, nil, agent.Options{Storage: host})
	ln, err := agent.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return h, tools, root
}

// AT-F06-01: inventory through the Core, by role.
func TestStorageInventory(t *testing.T) {
	h, _, root := withStorage(t)
	owner := h.setupOwner()
	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer", authz.Viewer)
	var inv agentproto.StorageInventory
	h.loginAs("operator1").do("GET", "/api/v1/storage", nil).expect(200).json(&inv)
	if len(inv.Disks) != 9 || inv.MountRoot != root || !inv.Privileged || inv.SMART || strings.Join(inv.FileSystems, ",") != "btrfs,ext4" {
		t.Fatalf("inventory %+v", inv)
	}
	h.loginAs("viewer").do("GET", "/api/v1/storage", nil).expect(403)

	// The Docker agent does not offer storage operations.
	h2, _ := withAgent(t)
	o2 := h2.setupOwner()
	if r := o2.do("GET", "/api/v1/storage", nil); r.Code != 503 || r.errorCode() != "storage_unavailable" {
		t.Fatalf("without storage service: %d %s", r.Code, r.Body)
	}
}

// AT-F06-03, TH-32, AT-F09-04: confirmation, step-up and the agent's own checks.
func TestStorageFormat(t *testing.T) {
	h, tools, _ := withStorage(t)
	owner := h.setupOwner()
	h.startJobs()
	sda := map[string]any{"path": "/dev/sda", "serial": "WD-FREE0001", "wwn": "0x50014ee2b1111111", "size_bytes": 4000787030016, "fstype": "ext4", "label": "media"}
	with := func(kv ...any) map[string]any {
		m := map[string]any{}
		for k, v := range sda {
			m[k] = v
		}
		for i := 0; i+1 < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	if r := owner.do("POST", "/api/v1/storage/format", with("confirm", "sdb")); r.Code != 422 || r.errorCode() != "confirmation_required" {
		t.Fatalf("wrong confirmation: %d %s", r.Code, r.Body)
	}
	h.clock.Advance(11 * time.Minute)
	if r := owner.do("POST", "/api/v1/storage/format", with("confirm", "sda")); r.Code != 403 || r.errorCode() != "step_up_required" {
		t.Fatalf("without step-up: %d %s", r.Code, r.Body)
	}
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": "not the password"}).expect(401)
	owner.do("POST", "/api/v1/auth/step-up", map[string]string{"password": strongPassword}).expect(204)
	if tools.ran("sfdisk") {
		t.Fatal("disk touched before confirmation")
	}
	// The system disk: the Core accepts the request, the storage service refuses it.
	var res struct {
		JobID int64 `json:"job_id"`
	}
	owner.do("POST", "/api/v1/storage/format", map[string]any{"path": "/dev/nvme0n1", "serial": "S5GXNX0R1", "wwn": "eui.002538b111b2", "size_bytes": 512110190592,
		"fstype": "ext4", "label": "x", "confirm": "nvme0n1"}).expect(202).json(&res)
	j := h.waitJob(res.JobID, jobs.Failed)
	if !strings.Contains(j.Error, "holds the operating system") || tools.ran("sfdisk") {
		t.Fatalf("system disk job: %s", j.Error)
	}
	owner.do("POST", "/api/v1/storage/format", with("confirm", "sda")).expect(202).json(&res)
	h.waitJob(res.JobID, jobs.Succeeded)
	if !tools.ran("mkfs.ext4 -F -q -E nodiscard -L media /dev/sda1") {
		t.Fatalf("mkfs not run: %v", tools.calls)
	}
	if auditCount(t, h, "storage.format", "failure") != 1 || auditCount(t, h, "storage.format", "success") != 2 ||
		auditCount(t, h, "storage.format.result", "failure") != 1 || auditCount(t, h, "storage.format.result", "success") != 1 ||
		auditCount(t, h, "auth.step_up", "failure") != 1 {
		t.Fatal("format not audited")
	}
	// Admins may format; operators may not.
	h.createUser(owner, "operator1", authz.Operator)
	if r := h.loginAs("operator1").do("POST", "/api/v1/storage/format", with("confirm", "sda")); r.Code != 403 {
		t.Fatalf("operator: %d", r.Code)
	}
}

// AT-F06-02: mount and unmount through the Core.
func TestStorageMounts(t *testing.T) {
	h, tools, root := withStorage(t)
	owner := h.setupOwner()
	var m agentproto.ManagedMount
	owner.do("POST", "/api/v1/storage/mounts", map[string]string{"path": "/dev/sdb1", "uuid": "9a1e0b2c-2222-4c1d-8e7f-000000000002", "name": "media"}).expect(201).json(&m)
	if m.Path != filepath.Join(root, "media") || !tools.ran("systemctl enable --now") {
		t.Fatalf("mount %+v", m)
	}
	var inv agentproto.StorageInventory
	owner.do("GET", "/api/v1/storage", nil).expect(200).json(&inv)
	if len(inv.Mounts) != 1 || inv.Mounts[0].Name != "media" {
		t.Fatalf("mounts %+v", inv.Mounts)
	}
	if r := owner.do("POST", "/api/v1/storage/mounts", map[string]string{"path": "/dev/nvme0n1p1", "uuid": "A1B2-C3D4", "name": "efi"}); r.Code != 422 {
		t.Fatalf("system partition mounted: %d", r.Code)
	}
	owner.do("DELETE", "/api/v1/storage/mounts/media", nil).expect(204)
	owner.do("DELETE", "/api/v1/storage/mounts/media", nil).expect(404)
	if auditCount(t, h, "storage.mount", "success") != 1 || auditCount(t, h, "storage.mount", "failure") != 1 || auditCount(t, h, "storage.unmount", "success") != 1 {
		t.Fatal("mounts not audited")
	}
}
