package app

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/backup"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

// memDocker volumes as tar streams: one file "content" per volume (M16).
func (m *memDocker) helperVolume(ref string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.specs[m.key(ref)].Mounts[0].Source
}

func (m *memDocker) ArchiveGet(_ context.Context, ref, _ string) (io.ReadCloser, error) {
	vol := m.helperVolume(ref)
	m.mu.Lock()
	content := m.data[vol]
	m.mu.Unlock()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o750, Uid: 999})
	_ = tw.WriteHeader(&tar.Header{Name: "data/content", Typeflag: tar.TypeReg, Mode: 0o640, Size: int64(len(content)), Uid: 999})
	_, _ = tw.Write([]byte(content))
	_ = tw.Close()
	return io.NopCloser(&buf), nil
}

func (m *memDocker) ArchivePut(_ context.Context, ref, _ string, r io.Reader) error {
	vol := m.helperVolume(ref)
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if h.Name == "data/content" {
			b, err := io.ReadAll(tr)
			if err != nil {
				return err
			}
			m.mu.Lock()
			m.data[vol] = string(b)
			m.mu.Unlock()
		}
	}
}

const backupPass = "correct horse battery staple"

func backupHarness(t *testing.T) (*harness, *memDocker, string) {
	t.Helper()
	root := t.TempDir()
	h, md := withAgentConfig(t, func(c *config.Config) { c.Backup.LocalRoots = []string{root} }, func(o *Options) { o.BackupHealthTimeout = 3 * time.Second })
	return h, md, root
}

func stackVolume(t *testing.T, md *memDocker, stack string) string {
	t.Helper()
	md.mu.Lock()
	defer md.mu.Unlock()
	for v, l := range md.volLabels {
		if l["io.kernhaven.stack"] == stack && l["io.kernhaven.snapshot.of"] == "" && md.volumes[v] {
			return v
		}
	}
	t.Fatalf("no volume of %s", stack)
	return ""
}

func runningContainers(md *memDocker, stack string) int {
	md.mu.Lock()
	defer md.mu.Unlock()
	n := 0
	for name, c := range md.containers {
		if md.labels[name]["io.kernhaven.stack"] == stack && c.State == "running" {
			n++
		}
	}
	return n
}

type jobRef struct {
	JobID int64 `json:"job_id"`
}

// AT-F14-01..06 through the API with a local repository.
func TestBackupAndRestoreThroughCore(t *testing.T) {
	h, md, root := backupHarness(t)
	ctx := context.Background()
	owner := h.setupOwner()
	createStack(t, owner)
	h.startJobs()
	var job jobRef
	owner.do("POST", "/api/v1/stacks/shop/deploy", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	vol := stackVolume(t, md, "shop")
	md.mu.Lock()
	md.data[vol] = "orders v1"
	md.mu.Unlock()

	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer", authz.Viewer)
	op, viewer := h.loginAs("operator1"), h.loginAs("viewer")
	viewer.do("GET", "/api/v1/backup/repositories", nil).expect(403)

	repoDir := filepath.Join(root, "repo")
	if err := os.Mkdir(repoDir, 0o700); err != nil {
		t.Fatal(err)
	}
	local := map[string]any{"path": repoDir}
	op.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb", "kind": "local", "config": local, "passphrase": backupPass}).expect(403)
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb", "kind": "local", "config": local, "passphrase": "short"}).expect(422)
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb", "kind": "local", "config": map[string]any{"path": t.TempDir()}, "passphrase": backupPass}).expect(422)
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb", "kind": "local", "config": map[string]any{"path": repoDir, "extra": 1}, "passphrase": backupPass}).expect(422)
	var repo backup.Repository
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb", "kind": "local", "config": local, "passphrase": backupPass}).expect(201).json(&repo)
	// The same target: a second init is refused, connecting needs the passphrase.
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb2", "kind": "local", "config": local, "passphrase": backupPass}).expect(409)
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb2", "kind": "local", "config": local, "passphrase": "wrong passphrase!", "connect": true}).expect(422)
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb2", "kind": "local", "config": local, "passphrase": backupPass, "connect": true}).expect(409)
	// SSRF guard for remote targets.
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "meta", "kind": "s3", "config": map[string]any{"endpoint": "http://169.254.169.254", "bucket": "bucket", "access_key_id": "key"}, "secret": map[string]any{"secret_access_key": "x"}, "passphrase": backupPass}).expect(422)
	var sealed []byte
	if err := h.db.QueryRow(`SELECT data_key FROM backup_repos WHERE id = ?`, repo.ID).Scan(&sealed); err != nil || len(sealed) < 40 {
		t.Fatalf("data key not stored sealed: %v", err)
	}

	planIn := map[string]any{"name": "nightly", "repo": repo.ID, "schedule": "0 3 * * *", "platform": true, "stacks": []string{"*"}, "retention": map[string]int{"keep_last": 2}}
	op.do("POST", "/api/v1/backup/plans", planIn).expect(403)
	owner.do("POST", "/api/v1/backup/plans", map[string]any{"name": "x", "repo": repo.ID, "schedule": "* * * * *", "platform": true, "retention": map[string]int{"keep_last": 1}}).expect(422)
	owner.do("POST", "/api/v1/backup/plans", map[string]any{"name": "x", "repo": repo.ID, "schedule": "@daily", "stacks": []string{"nope"}, "retention": map[string]int{"keep_last": 1}}).expect(422)
	owner.do("POST", "/api/v1/backup/plans", map[string]any{"name": "x", "repo": repo.ID, "schedule": "@daily", "platform": true, "retention": map[string]int{}}).expect(422)
	var plan backup.Plan
	owner.do("POST", "/api/v1/backup/plans", planIn).expect(201).json(&plan)
	if plan.Next == nil || !plan.Next.After(h.clock.Now()) {
		t.Fatalf("next run %v", plan.Next)
	}

	// An operator may trigger a backup (AT-F14-03).
	op.do("POST", "/api/v1/backup/plans/"+itoa(plan.ID)+"/run", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	if runningContainers(md, "shop") != 2 {
		t.Fatal("stack not running again after the backup")
	}
	var snaps struct{ Snapshots []backup.Snapshot }
	op.do("GET", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/snapshots", nil).expect(200).json(&snaps)
	if len(snaps.Snapshots) != 1 || !snaps.Snapshots[0].Platform || strings.Join(snaps.Snapshots[0].Stacks, ",") != "shop" || snaps.Snapshots[0].Objects != 3 {
		t.Fatalf("snapshots %+v", snaps)
	}
	first := snaps.Snapshots[0].ID
	var m backup.Manifest
	op.do("GET", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/snapshots/"+first, nil).expect(200).json(&m)
	if len(m.Stacks) != 1 || m.Stacks[0].DeployedRevision != 1 || m.Stacks[0].Volumes[0] != vol {
		t.Fatalf("manifest %+v", m)
	}
	// AT-F14-01: nothing readable on the target, the key only wrapped.
	_ = filepath.WalkDir(repoDir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p)
			for _, secret := range []string{"orders v1", "owner", secretValue, "CREATE TABLE"} {
				if bytes.Contains(b, []byte(secret)) {
					t.Errorf("%s contains %q in clear", p, secret)
				}
			}
		}
		return nil
	})

	// AT-F14-05: restore one stack.
	md.mu.Lock()
	md.data[vol] = "orders v2, damaged"
	md.mu.Unlock()
	op.do("POST", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/snapshots/"+first+"/restore", map[string]string{"stack": "shop"}).expect(403)
	owner.do("POST", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/snapshots/"+first+"/restore", map[string]string{"stack": "nope"}).expect(422)
	owner.do("POST", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/snapshots/"+first+"/restore", map[string]string{"stack": "shop"}).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	md.mu.Lock()
	got, kept := md.data[vol], md.volumes[vol+".pre-restore"]
	md.mu.Unlock()
	if got != "orders v1" || kept {
		t.Fatalf("after restore: %q, kept copy %v", got, kept)
	}
	if runningContainers(md, "shop") != 2 {
		t.Fatal("stack not running after the restore")
	}

	// AT-F14-04: retention keeps the last two.
	for range 3 {
		h.clock.Advance(time.Minute) // new snapshot IDs; sessions stay valid
		owner.do("POST", "/api/v1/backup/plans/"+itoa(plan.ID)+"/run", nil).expect(202).json(&job)
		h.waitJob(job.JobID, jobs.Succeeded)
	}
	owner.do("GET", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/snapshots", nil).expect(200).json(&snaps)
	if len(snaps.Snapshots) != 2 || snaps.Snapshots[0].ID == first || snaps.Snapshots[1].ID == first {
		t.Fatalf("after retention %+v", snaps.Snapshots)
	}
	dirs, _ := os.ReadDir(filepath.Join(repoDir, "snapshots"))
	if len(dirs) != 2 {
		t.Fatalf("%d snapshot directories on the target", len(dirs))
	}

	// AT-F14-06: verification passes, then detects tampering and deletion.
	owner.do("POST", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/verify", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	newest, older := snaps.Snapshots[0].ID, snaps.Snapshots[1].ID
	objFile := filepath.Join(repoDir, "snapshots", newest, "2000.khb") // the stack's volume
	b, err := os.ReadFile(objFile)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-20] ^= 0x40
	if err := os.WriteFile(objFile, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(repoDir, "snapshots", older)); err != nil {
		t.Fatal(err)
	}
	owner.do("POST", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/verify", nil).expect(202).json(&job)
	j := h.waitJob(job.JobID, jobs.Failed)
	if !strings.Contains(j.Error, "2 of 2 snapshots failed") || !strings.Contains(j.Error, "missing on the target") || !strings.Contains(j.Error, "corrupted") {
		t.Fatalf("verification error %q", j.Error)
	}
	var repos struct{ Repositories []backup.Repository }
	owner.do("GET", "/api/v1/backup/repositories", nil).expect(200).json(&repos)
	if r := repos.Repositories[0]; r.VerifyOK == nil || *r.VerifyOK || r.Snapshots != 2 {
		t.Fatalf("repository %+v", r)
	}
	if auditCount(t, h, "backup.verify_failed", "failure") != 1 {
		t.Fatal("failed verification not audited")
	}

	// A restore from the damaged snapshot fails and puts the data back.
	md.mu.Lock()
	md.data[vol] = "orders v3"
	md.mu.Unlock()
	owner.do("POST", "/api/v1/backup/repositories/"+itoa(repo.ID)+"/snapshots/"+newest+"/restore", map[string]string{"stack": "shop"}).expect(202).json(&job)
	j = h.waitJob(job.JobID, jobs.Failed)
	md.mu.Lock()
	got = md.data[vol]
	md.mu.Unlock()
	if got != "orders v3" || !strings.Contains(j.Error, "corrupted") {
		t.Fatalf("after failed restore: %q (%s)", got, j.Error)
	}
	if runningContainers(md, "shop") != 2 {
		t.Fatal("stack not running after the failed restore")
	}

	// A repository in use cannot be forgotten; changes are audited.
	owner.do("DELETE", "/api/v1/backup/repositories/"+itoa(repo.ID), nil).expect(409)
	for _, a := range []string{"backup.repo_create", "backup.plan_save", "backup.run", "backup.restore", "backup.verify"} {
		if auditCount(t, h, a, "success") == 0 {
			t.Errorf("%s not audited", a)
		}
	}
	_ = ctx
}

// AT-F14-04: missed runs are made once after downtime.
func TestBackupSchedule(t *testing.T) {
	h, _, root := backupHarness(t)
	ctx := context.Background()
	owner := h.setupOwner()
	var repo backup.Repository
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb", "kind": "local", "config": map[string]any{"path": root}, "passphrase": backupPass}).expect(201).json(&repo)
	var plan backup.Plan
	owner.do("POST", "/api/v1/backup/plans", map[string]any{"name": "nightly", "repo": repo.ID, "schedule": "0 3 * * *", "platform": true, "retention": map[string]int{"keep_daily": 7}}).expect(201).json(&plan)
	count := func() int {
		var n int
		_ = h.db.QueryRow(`SELECT count(*) FROM jobs WHERE kind = 'backup.run'`).Scan(&n)
		return n
	}
	h.app.Backup.Tick(ctx)
	if count() != 0 {
		t.Fatal("ran before it was due")
	}
	h.clock.Advance(3 * 24 * time.Hour) // the Core was down for three nights
	h.app.Backup.Tick(ctx)
	h.app.Backup.Tick(ctx)
	if count() != 1 {
		t.Fatalf("%d runs after downtime, want one", count())
	}
	var payload string
	_ = h.db.QueryRow(`SELECT payload FROM jobs WHERE kind = 'backup.run'`).Scan(&payload)
	if !strings.Contains(payload, `"trigger":"catch-up"`) {
		t.Fatalf("payload %s", payload)
	}
	got, _ := h.app.Backup.GetPlan(ctx, plan.ID)
	if got.Next == nil || !got.Next.After(h.clock.Now()) {
		t.Fatalf("next %v", got.Next)
	}
	// Verification is scheduled too (weekly by default).
	h.clock.Advance(8 * 24 * time.Hour)
	h.app.Backup.Tick(ctx)
	var n int
	_ = h.db.QueryRow(`SELECT count(*) FROM jobs WHERE kind = 'backup.verify'`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d verifications", n)
	}
}

// AT-F14-05: a full platform restore into an empty data directory, as on a
// fresh host: database, secret key, users, then the stacks' data.
func TestPlatformRestore(t *testing.T) {
	h, md, root := backupHarness(t)
	ctx := context.Background()
	owner := h.setupOwner()
	createStack(t, owner)
	h.startJobs()
	var job jobRef
	owner.do("POST", "/api/v1/stacks/shop/deploy", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	vol := stackVolume(t, md, "shop")
	md.mu.Lock()
	md.data[vol] = "orders v1"
	md.mu.Unlock()
	var repo backup.Repository
	owner.do("POST", "/api/v1/backup/repositories", map[string]any{"name": "usb", "kind": "local", "config": map[string]any{"path": root}, "passphrase": backupPass}).expect(201).json(&repo)
	var plan backup.Plan
	owner.do("POST", "/api/v1/backup/plans", map[string]any{"name": "nightly", "repo": repo.ID, "schedule": "@daily", "platform": true, "stacks": []string{"shop"}, "retention": map[string]int{"keep_last": 3}}).expect(201).json(&plan)
	owner.do("POST", "/api/v1/backup/plans/"+itoa(plan.ID)+"/run", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)

	// The new host: an empty data directory and an empty Docker.
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	opts := backup.RestoreOptions{DataDir: dir, LocalRoots: []string{root}, Target: backup.TargetFile{Kind: "local", Config: []byte(`{"path":"` + root + `"}`)},
		Passphrase: backupPass, Snapshot: "latest"}
	bad := opts
	bad.Passphrase = "not the passphrase"
	if err := backup.RestorePlatform(ctx, bad); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
	var listing bytes.Buffer
	list := opts
	list.List, list.Out = true, &listing
	if err := backup.RestorePlatform(ctx, list); err != nil || !strings.Contains(listing.String(), "platform=true stacks=shop") {
		t.Fatalf("list: %v %s", err, listing.String())
	}
	if err := backup.RestorePlatform(ctx, opts); err != nil {
		t.Fatal(err)
	}
	if err := backup.RestorePlatform(ctx, opts); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Fatalf("second restore without -replace: %v", err)
	}
	if k1, _ := os.ReadFile(filepath.Join(h.dataDir, "secrets.key")); !bytes.Equal(k1, mustRead(t, filepath.Join(dir, "secrets.key"))) {
		t.Fatal("secret key not restored")
	}

	h2 := newHarnessAt(t, dir, func(c *config.Config) {
		c.Agent.Socket = filepath.Join(t.TempDir(), "agent.sock")
		c.Backup.LocalRoots = []string{root}
	}, func(o *Options) { o.BackupHealthTimeout = 3 * time.Second })
	md2 := newMemDocker()
	serveAgent(t, h2, h2.cfg.Agent.Socket, md2, agent.Options{})
	var sessions, pending int
	_ = h2.db.QueryRow(`SELECT count(*) FROM sessions`).Scan(&sessions)
	_ = h2.db.QueryRow(`SELECT count(*) FROM backup_restore_pending`).Scan(&pending)
	if sessions != 0 || pending != 1 {
		t.Fatalf("sessions %d, pending %d", sessions, pending)
	}
	h2.startJobs()
	h2.app.Backup.Tick(ctx)
	var id int64
	if err := h2.db.QueryRow(`SELECT id FROM jobs WHERE kind = 'backup.restore_platform'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	j := h2.waitJob(id, jobs.Succeeded)
	md2.mu.Lock()
	got := md2.data[vol]
	md2.mu.Unlock()
	if got != "orders v1" || runningContainers(md2, "shop") != 2 {
		t.Fatalf("restored data %q, %d containers (%s)", got, runningContainers(md2, "shop"), j.Error)
	}
	// The owner signs in on the restored platform with the old password.
	h2.owner = nil
	if c := h2.loginAs("owner"); c == nil {
		t.Fatal("owner cannot sign in")
	}
	_ = h2.db.QueryRow(`SELECT count(*) FROM backup_restore_pending`).Scan(&pending)
	if pending != 0 {
		t.Fatal("restore runs again on the next start")
	}
	var n int
	_ = h2.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'backup.restore_platform_offline'`).Scan(&n)
	if n != 1 {
		t.Fatal("offline restore not audited")
	}
	// The data directory lock keeps a restore away from a running Core.
	unlock, err := store.LockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.LockDir(dir); err != store.ErrLocked {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	_ = agentproto.OpVolumesImport
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
