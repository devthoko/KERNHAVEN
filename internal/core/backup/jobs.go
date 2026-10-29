package backup

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/stacks"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
	"github.com/devthoko/KERNHAVEN/internal/platform/version"
)

// Job kinds.
const (
	KindRun             = "backup.run"
	KindVerify          = "backup.verify"
	KindRestoreStack    = "backup.restore_stack"
	KindRestorePlatform = "backup.restore_platform"
)

const (
	labelStack      = "io.kernhaven.stack"
	labelSnapshotOf = "io.kernhaven.snapshot.of"
	// filesPerStep numbers objects: step i writes files i*filesPerStep + j.
	filesPerStep = 1000
	// incompleteAge is when an unfinished snapshot is removed.
	incompleteAge = 24 * time.Hour
)

func (s *Service) registerJobs() {
	s.jobs.Register(jobs.Kind{Name: KindRun, MaxAttempts: 3, Plan: s.planRun})
	s.jobs.Register(jobs.Kind{Name: KindVerify, MaxAttempts: 2, Plan: s.planVerify})
	s.jobs.Register(jobs.Kind{Name: KindRestoreStack, MaxAttempts: 2, Plan: s.planRestoreStack})
	s.jobs.Register(jobs.Kind{Name: KindRestorePlatform, MaxAttempts: 3, Plan: s.planRestorePlatform})
}

// call runs an agent operation for a job; errors that cannot succeed on
// retry are permanent.
func (s *Service) call(ctx context.Context, sc *jobs.StepContext, actor, op string, params, out any) error {
	if s.agent == nil {
		return jobs.Permanent(errors.New("no host agent is configured"))
	}
	err := s.agent.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}, out)
	return permanentAgentError(err)
}

func permanentAgentError(err error) error {
	var ae *agentclient.Error
	if errors.As(err, &ae) {
		switch ae.Code {
		case agentproto.CodeInvalidParams, agentproto.CodePolicyViolation, agentproto.CodeNotFound, agentproto.CodeInvalidGrant:
			return jobs.Permanent(err)
		}
	}
	return err
}

func (s *Service) stackVolumes(ctx context.Context, sc *jobs.StepContext, actor, stack string) (map[string]bool, error) {
	var vols []agentproto.VolumeSummary
	if err := s.call(ctx, sc, actor, agentproto.OpVolumesList, nil, &vols); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, v := range vols {
		if v.Labels[labelStack] == stack && v.Labels[labelSnapshotOf] == "" {
			out[v.Name] = true
		}
	}
	return out, nil
}

func (s *Service) stackContainers(ctx context.Context, sc *jobs.StepContext, actor, stack string) ([]agentproto.ContainerSummary, error) {
	var list []agentproto.ContainerSummary
	if err := s.call(ctx, sc, actor, agentproto.OpContainersList, agentproto.ContainersList{All: true}, &list); err != nil {
		return nil, err
	}
	var out []agentproto.ContainerSummary
	for _, c := range list {
		if c.Labels[labelStack] == stack {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *Service) stackStatus(ctx context.Context, stack string) (string, int) {
	var status string
	var rev int
	_ = s.db.QueryRowContext(ctx, `SELECT status, deployed_revision FROM stacks WHERE name = ?`, stack).Scan(&status, &rev)
	return status, rev
}

// stopStack stops the stack's running containers; it reports whether the
// stack should run afterwards. A deployed stack is restarted even
// when a crash interrupted an earlier attempt after stopping it.
func (s *Service) stopStack(ctx context.Context, sc *jobs.StepContext, actor, stack string) (bool, error) {
	list, err := s.stackContainers(ctx, sc, actor, stack)
	if err != nil {
		return false, err
	}
	status, _ := s.stackStatus(ctx, stack)
	restart := status == "deployed"
	for _, c := range list {
		if c.State != "running" {
			continue
		}
		restart = true
		if err := s.call(ctx, sc, actor, agentproto.OpContainersStop, agentproto.ContainerStop{ID: c.ID, TimeoutSeconds: 60}, nil); err != nil {
			return restart, fmt.Errorf("stop %s: %w", c.ID, err)
		}
	}
	if restart {
		sc.Logf("stopped stack %s", stack)
	}
	return restart, nil
}

func (s *Service) startStack(ctx context.Context, sc *jobs.StepContext, actor, stack string) error {
	list, err := s.stackContainers(ctx, sc, actor, stack)
	if err != nil {
		return err
	}
	for _, c := range list {
		if c.State == "running" {
			continue
		}
		if err := s.call(ctx, sc, actor, agentproto.OpContainersStart, agentproto.ContainerRef{ID: c.ID}, nil); err != nil {
			return fmt.Errorf("start %s: %w", c.ID, err)
		}
	}
	sc.Logf("started stack %s", stack)
	return nil
}

// waitHealthy waits until every container of the stack runs and, if it has
// a health check, is healthy (AT-F14-05).
func (s *Service) waitHealthy(ctx context.Context, sc *jobs.StepContext, actor, stack string) error {
	deadline := time.Now().Add(s.cfg.HealthTimeout) // wall time, not the injectable clock
	for {
		list, err := s.stackContainers(ctx, sc, actor, stack)
		if err != nil {
			return err
		}
		var pending []string
		for _, c := range list {
			var d agentproto.ContainerDetail
			if err := s.call(ctx, sc, actor, agentproto.OpContainersInspect, agentproto.ContainerRef{ID: c.ID}, &d); err != nil {
				return err
			}
			if !d.Running || (d.Health != "" && d.Health != "healthy") {
				pending = append(pending, fmt.Sprintf("%s (%s%s)", strings.Join(c.Names, ","), d.Status, map[bool]string{true: ", " + d.Health}[d.Health != ""]))
			}
		}
		if len(pending) == 0 {
			sc.Logf("stack %s is running and healthy", stack)
			return nil
		}
		if time.Now().After(deadline) {
			return jobs.Permanent(fmt.Errorf("stack %s did not become healthy: %s", stack, strings.Join(pending, "; ")))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.poll):
		}
	}
}

// ---- backup ----

type runPayload struct {
	Plan      int64     `json:"plan"`
	PlanName  string    `json:"plan_name"`
	Repo      int64     `json:"repo"`
	Snapshot  string    `json:"snapshot"`
	Platform  bool      `json:"platform"`
	Stacks    []string  `json:"stacks"`
	Quiesce   bool      `json:"quiesce"`
	Retention Retention `json:"retention"`
	Actor     string    `json:"actor"`
	Trigger   string    `json:"trigger"`
}

// StartBackup queues a run of a plan (AT-F14-03, AT-F14-04).
func (s *Service) StartBackup(ctx context.Context, a Actor, planID int64, trigger string) (int64, error) {
	p, err := s.GetPlan(ctx, planID)
	if err != nil {
		return 0, err
	}
	names := p.Stacks
	if len(names) == 1 && names[0] == "*" {
		known, err := s.stackNames(ctx)
		if err != nil {
			return 0, err
		}
		names = names[:0:0]
		for n, rev := range known {
			if rev > 0 {
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	pl := runPayload{Plan: p.ID, PlanName: p.Name, Repo: p.Repo, Snapshot: NewSnapshotID(s.now()), Platform: p.Platform, Stacks: names,
		Quiesce: p.Quiesce, Retention: p.Retention, Actor: a.Name, Trigger: trigger}
	var id int64
	err = withTx(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		id, err = s.jobs.EnqueueTx(ctx, tx, jobs.Request{Kind: KindRun, Payload: pl, CreatedBy: a.ID, DedupeKey: fmt.Sprintf("backup:plan:%d", p.ID)})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_plans SET last_job = ? WHERE id = ?`, id, p.ID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), s.event(a, "backup.run", "backup-plan:"+p.Name, nil, "job", fmt.Sprint(id), "snapshot", pl.Snapshot, "trigger", trigger))
		return err
	})
	if err == nil {
		s.wakeup()
	}
	return id, err
}

func (s *Service) wakeup() {
	if s.wake != nil {
		s.wake()
	}
}

func (s *Service) planRun(raw json.RawMessage) ([]jobs.Step, error) {
	var p runPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Repo <= 0 || !ValidSnapshotID(p.Snapshot) {
		return nil, errors.New("invalid backup payload")
	}
	steps := []jobs.Step{{Name: "check the repository", Run: func(ctx context.Context, sc *jobs.StepContext) error {
		r, _, err := s.OpenRepository(ctx, p.Repo)
		if err != nil {
			return err
		}
		r.T.Close()
		sc.Logf("snapshot %s (%s)", p.Snapshot, p.Trigger)
		return nil
	}}}
	if p.Platform {
		idx := len(steps)
		steps = append(steps, jobs.Step{Name: "back up the platform", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			return s.backupPlatform(ctx, sc, p, idx)
		}})
	}
	for _, name := range p.Stacks {
		idx, name := len(steps), name
		steps = append(steps, jobs.Step{Name: "back up stack " + name,
			Run: func(ctx context.Context, sc *jobs.StepContext) error { return s.backupStack(ctx, sc, p, idx, name) },
			Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
				if status, _ := s.stackStatus(ctx, name); p.Quiesce && status == "deployed" {
					return s.startStack(ctx, sc, p.Actor, name)
				}
				return nil
			}})
	}
	objectSteps := len(steps)
	steps = append(steps,
		jobs.Step{Name: "write the manifest", Run: func(ctx context.Context, sc *jobs.StepContext) error { return s.writeManifest(ctx, sc, p, objectSteps) }},
		jobs.Step{Name: "apply retention", Run: func(ctx context.Context, sc *jobs.StepContext) error { return s.applyRetention(ctx, sc, p) }},
	)
	return steps, nil
}

func (s *Service) backupPlatform(ctx context.Context, sc *jobs.StepContext, p runPayload, idx int) error {
	r, _, err := s.OpenRepository(ctx, p.Repo)
	if err != nil {
		return err
	}
	defer r.T.Close()
	// VACUUM INTO writes a consistent copy while the Core keeps running.
	tmp := filepath.Join(s.cfg.DataDir, "backup-db.tmp")
	_ = os.Remove(tmp)
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		return fmt.Errorf("database copy: %w", err)
	}
	defer os.Remove(tmp)
	var out []ObjectEntry
	put := func(kind, path string, required bool) error {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) && !required {
			return nil
		}
		if err != nil {
			return err
		}
		defer f.Close()
		e, err := r.WriteObject(ctx, p.Snapshot, ObjectEntry{File: idx*filesPerStep + len(out), Kind: kind}, f)
		if err != nil {
			return fmt.Errorf("%s: %w", kind, err)
		}
		sc.Logf("%s: %d bytes", kind, e.Size)
		out = append(out, e)
		return nil
	}
	if err := put(KindDatabase, tmp, true); err != nil {
		return err
	}
	// Without the secret key the database's encrypted values are lost
	// (ADR-0019); inside the encrypted snapshot it is protected.
	if err := put(KindSecrets, filepath.Join(s.cfg.DataDir, secretbox.KeyFile), true); err != nil {
		return err
	}
	if s.cfg.ConfigPath != "" {
		if err := put(KindConfig, s.cfg.ConfigPath, false); err != nil {
			return err
		}
	}
	return sc.SetOutput("objects", out)
}

// errTracker records a stream's read error, which the HTTP client may
// report only as a broken request.
type errTracker struct {
	r   io.Reader
	err error
}

func (t *errTracker) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		t.err = err
	}
	return n, err
}

func (s *Service) backupStack(ctx context.Context, sc *jobs.StepContext, p runPayload, idx int, name string) (err error) {
	vols, err := s.stackVolumes(ctx, sc, p.Actor, name)
	if err != nil {
		return err
	}
	_, rev := s.stackStatus(ctx, name)
	if p.Quiesce && len(vols) > 0 {
		restart, err := s.stopStack(ctx, sc, p.Actor, name)
		if restart {
			defer func() {
				if serr := s.startStack(context.WithoutCancel(ctx), sc, p.Actor, name); serr != nil && err == nil {
					err = serr
				}
			}()
		}
		if err != nil {
			return err
		}
	}
	r, _, err := s.OpenRepository(ctx, p.Repo)
	if err != nil {
		return err
	}
	defer r.T.Close()
	names := make([]string, 0, len(vols))
	for v := range vols {
		names = append(names, v)
	}
	sort.Strings(names)
	var out []ObjectEntry
	for j, v := range names {
		st, err := s.agent.DoStream(ctx, agentclient.Call{Op: agentproto.OpVolumesExport, Params: agentproto.VolumeArchive{Stack: name, Volume: v}, Actor: p.Actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}, nil)
		if err != nil {
			return permanentAgentError(fmt.Errorf("export %s: %w", v, err))
		}
		e, err := r.WriteObject(ctx, p.Snapshot, ObjectEntry{File: idx*filesPerStep + j, Kind: KindVolume, Stack: name, Volume: v}, st.Body)
		st.Body.Close()
		if err != nil {
			return fmt.Errorf("export %s: %w", v, err)
		}
		sc.Logf("volume %s: %d bytes", v, e.Size)
		out = append(out, e)
	}
	if err := sc.SetOutput("objects", out); err != nil {
		return err
	}
	return sc.SetOutput("stack", StackEntry{Name: name, DeployedRevision: rev, Volumes: names})
}

func (s *Service) writeManifest(ctx context.Context, sc *jobs.StepContext, p runPayload, objectSteps int) error {
	r, _, err := s.OpenRepository(ctx, p.Repo)
	if err != nil {
		return err
	}
	defer r.T.Close()
	host, _ := os.Hostname()
	m := Manifest{ID: p.Snapshot, Plan: p.PlanName, CreatedMS: s.now().UnixMilli(), Host: host, Kernhaven: version.Get().Version, Platform: p.Platform, Objects: []ObjectEntry{}, Stacks: []StackEntry{}}
	if t, err := time.Parse("20060102T150405Z", p.Snapshot[:16]); err == nil {
		m.CreatedMS = t.UnixMilli()
	}
	for i := 1; i < objectSteps; i++ {
		var objs []ObjectEntry
		if _, err := sc.Output(i, "objects", &objs); err != nil {
			return err
		}
		m.Objects = append(m.Objects, objs...)
		var st StackEntry
		if ok, err := sc.Output(i, "stack", &st); err != nil {
			return err
		} else if ok {
			m.Stacks = append(m.Stacks, st)
		}
	}
	if err := r.WriteManifest(ctx, m); err != nil {
		return err
	}
	plan := p.Plan
	if err := insertSnapshot(ctx, s.db, p.Repo, &plan, m); err != nil {
		return err
	}
	sc.Logf("snapshot %s: %d objects, %d bytes stored", m.ID, len(m.Objects), m.Size())
	return nil
}

func snapshotTime(id string) time.Time {
	t, _ := time.Parse("20060102T150405Z", id[:min(16, len(id))])
	return t
}

func (s *Service) applyRetention(ctx context.Context, sc *jobs.StepContext, p runPayload) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id, created_ms FROM backup_snapshots WHERE repo = ? AND plan = ?`, p.Repo, p.Plan)
	if err != nil {
		return err
	}
	times := map[string]time.Time{}
	for rows.Next() {
		var id string
		var ms int64
		if err := rows.Scan(&id, &ms); err != nil {
			rows.Close()
			return err
		}
		times[id] = time.UnixMilli(ms)
	}
	rows.Close()
	r, _, err := s.OpenRepository(ctx, p.Repo)
	if err != nil {
		return err
	}
	defer r.T.Close()
	for _, id := range p.Retention.Forget(times) {
		if err := r.DeleteSnapshot(ctx, id); err != nil {
			return fmt.Errorf("forget %s: %w", id, err)
		}
		if _, err := s.db.ExecContext(ctx, `DELETE FROM backup_snapshots WHERE repo = ? AND id = ?`, p.Repo, id); err != nil {
			return err
		}
		sc.Logf("forgot snapshot %s", id)
	}
	list, err := r.ListSnapshots(ctx)
	if err != nil {
		return err
	}
	for _, id := range list.Incomplete {
		if id != p.Snapshot && s.now().Sub(snapshotTime(id)) > incompleteAge {
			if err := r.DeleteSnapshot(ctx, id); err != nil {
				return err
			}
			sc.Logf("removed incomplete snapshot %s", id)
		}
	}
	return nil
}

// ---- verification ----

type verifyPayload struct {
	Repo  int64  `json:"repo"`
	Actor string `json:"actor"`
}

// StartVerify queues a verification of every snapshot (AT-F14-06).
func (s *Service) StartVerify(ctx context.Context, a Actor, repo int64) (int64, error) {
	r, err := s.Repository(ctx, repo)
	if err != nil {
		return 0, err
	}
	var id int64
	err = withTx(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		id, err = s.jobs.EnqueueTx(ctx, tx, jobs.Request{Kind: KindVerify, Payload: verifyPayload{Repo: repo, Actor: a.Name}, CreatedBy: a.ID, DedupeKey: fmt.Sprintf("backup:verify:%d", repo)})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE backup_repos SET verify_job = ? WHERE id = ?`, id, repo); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), s.event(a, "backup.verify", "backup-repo:"+r.Name, nil, "job", fmt.Sprint(id)))
		return err
	})
	if err == nil {
		s.wakeup()
	}
	return id, err
}

func (s *Service) planVerify(raw json.RawMessage) ([]jobs.Step, error) {
	var p verifyPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.Repo <= 0 {
		return nil, errors.New("invalid verification payload")
	}
	return []jobs.Step{{Name: "verify snapshots", Run: func(ctx context.Context, sc *jobs.StepContext) error {
		return s.verify(ctx, sc, p.Repo)
	}}}, nil
}

// VerifySnapshot reads and authenticates every object of a snapshot.
func VerifySnapshot(ctx context.Context, r *Repo, id string) (Manifest, error) {
	m, err := r.ReadManifest(ctx, id)
	if err != nil {
		return m, fmt.Errorf("manifest: %w", err)
	}
	for _, e := range m.Objects {
		rc, err := r.OpenObject(ctx, id, e)
		if err != nil {
			return m, err
		}
		_, err = io.Copy(io.Discard, rc)
		rc.Close()
		if err != nil {
			return m, fmt.Errorf("object %d (%s %s): %w", e.File, e.Kind, e.Volume, err)
		}
	}
	return m, nil
}

func (s *Service) verify(ctx context.Context, sc *jobs.StepContext, repo int64) error {
	r, info, err := s.OpenRepository(ctx, repo)
	if err != nil {
		s.setRepoVerify(ctx, repo, false, err.Error())
		return err
	}
	defer r.T.Close()
	if err := s.syncSnapshots(ctx, repo, r); err != nil {
		return err
	}
	list, err := r.ListSnapshots(ctx)
	if err != nil {
		return err
	}
	onTarget := map[string]bool{}
	for _, id := range list.Complete {
		onTarget[id] = true
	}
	snaps, err := s.Snapshots(ctx, repo)
	if err != nil {
		return err
	}
	var failed []string
	for _, sn := range snaps {
		msg := ""
		if !onTarget[sn.ID] {
			msg = "missing on the target"
		} else if _, err := VerifySnapshot(ctx, r, sn.ID); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			msg = err.Error()
		}
		ok := msg == ""
		if !ok {
			failed = append(failed, sn.ID+": "+msg)
			sc.Logf("snapshot %s FAILED: %s", sn.ID, msg)
		} else {
			sc.Logf("snapshot %s verified", sn.ID)
		}
		if _, err := s.db.ExecContext(ctx, `UPDATE backup_snapshots SET verified_ms = ?, verify_ok = ?, verify_msg = ? WHERE repo = ? AND id = ?`,
			s.now().UnixMilli(), ok, msg, repo, sn.ID); err != nil {
			return err
		}
	}
	if len(failed) > 0 {
		msg := fmt.Sprintf("%d of %d snapshots failed verification", len(failed), len(snaps))
		s.setRepoVerify(ctx, repo, false, msg)
		_ = s.audit.Record(context.WithoutCancel(ctx), s.event(Actor{Name: "system"}, "backup.verify_failed", "backup-repo:"+info.Name, errors.New(strings.Join(failed, "; "))))
		return jobs.Permanent(fmt.Errorf("%s: %s", msg, strings.Join(failed, "; ")))
	}
	s.setRepoVerify(ctx, repo, true, fmt.Sprintf("%d snapshots verified", len(snaps)))
	return nil
}

func (s *Service) setRepoVerify(ctx context.Context, repo int64, ok bool, msg string) {
	_, _ = s.db.ExecContext(context.WithoutCancel(ctx), `UPDATE backup_repos SET verified_ms = ?, verify_ok = ?, verify_msg = ? WHERE id = ?`, s.now().UnixMilli(), ok, msg, repo)
}

// ---- restore one stack ----

type restorePayload struct {
	Repo     int64  `json:"repo"`
	Snapshot string `json:"snapshot"`
	Stack    string `json:"stack"`
	Actor    string `json:"actor"`
}

type savedPair struct {
	Volume string `json:"volume"`
	Saved  string `json:"saved"`
}

// preRestoreName is the volume keeping a stack's data during a restore.
func preRestoreName(vol string) string {
	const suffix = ".pre-restore"
	if len(vol)+len(suffix) <= 63 {
		return vol + suffix
	}
	sum := sha256.Sum256([]byte(vol))
	return vol[:40] + "." + hex.EncodeToString(sum[:4]) + suffix
}

// StartRestore queues the restore of one stack's volumes (AT-F14-05).
func (s *Service) StartRestore(ctx context.Context, a Actor, repo int64, snapshot, stack string) (int64, error) {
	m, err := s.SnapshotDetail(ctx, repo, snapshot)
	if err != nil {
		return 0, err
	}
	found := false
	for _, st := range m.Stacks {
		found = found || st.Name == stack
	}
	if !found {
		return 0, invalid("snapshot %s does not contain stack %q", snapshot, stack)
	}
	if _, err := s.stacks.Get(ctx, s.db, stack); err != nil {
		return 0, invalid("stack %q does not exist on this host; restore the platform instead", stack)
	}
	var id int64
	err = withTx(ctx, s.db, func(tx *sql.Tx) error {
		var err error
		id, err = s.jobs.EnqueueTx(ctx, tx, jobs.Request{Kind: KindRestoreStack, Payload: restorePayload{Repo: repo, Snapshot: snapshot, Stack: stack, Actor: a.Name}, CreatedBy: a.ID, DedupeKey: "stack:" + stack})
		if err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), s.event(a, "backup.restore", "stack:"+stack, nil, "snapshot", snapshot, "repo", fmt.Sprint(repo), "job", fmt.Sprint(id)))
		return err
	})
	if err == nil {
		s.wakeup()
	}
	return id, err
}

func (s *Service) restoreManifest(ctx context.Context, repo int64, snapshot, stack string) (*Repo, Manifest, StackEntry, error) {
	r, _, err := s.OpenRepository(ctx, repo)
	if err != nil {
		return nil, Manifest{}, StackEntry{}, err
	}
	m, err := r.ReadManifest(ctx, snapshot)
	if err != nil {
		r.T.Close()
		return nil, m, StackEntry{}, jobs.Permanent(err)
	}
	for _, st := range m.Stacks {
		if st.Name == stack {
			return r, m, st, nil
		}
	}
	r.T.Close()
	return nil, m, StackEntry{}, jobs.Permanent(fmt.Errorf("snapshot %s does not contain stack %s", snapshot, stack))
}

// importVolumes streams every volume of the stack from the snapshot to the
// agent; damaged data fails before or while it is written.
func (s *Service) importVolumes(ctx context.Context, sc *jobs.StepContext, actor string, r *Repo, m Manifest, stack string) error {
	for _, e := range m.Objects {
		if e.Kind != KindVolume || e.Stack != stack {
			continue
		}
		rc, err := r.OpenObject(ctx, m.ID, e)
		if err != nil {
			return jobs.Permanent(err)
		}
		tr := &errTracker{r: rc}
		var res agentproto.VolumeImportResult
		err = s.agent.DoStreamJSON(ctx, agentclient.Call{Op: agentproto.OpVolumesImport, Params: agentproto.VolumeArchive{Stack: stack, Volume: e.Volume}, Actor: actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}, tr, &res)
		rc.Close()
		if tr.err != nil {
			if errors.Is(tr.err, ErrCorrupt) {
				return jobs.Permanent(fmt.Errorf("volume %s: %w", e.Volume, tr.err))
			}
			return fmt.Errorf("volume %s: %w", e.Volume, tr.err)
		}
		if err != nil {
			return permanentAgentError(fmt.Errorf("import %s: %w", e.Volume, err))
		}
		sc.Logf("restored volume %s: %d entries, %d bytes", e.Volume, res.Entries, res.Bytes)
	}
	return nil
}

func (s *Service) ensureVolumes(ctx context.Context, sc *jobs.StepContext, actor string, st StackEntry) (map[string]bool, error) {
	have, err := s.stackVolumes(ctx, sc, actor, st.Name)
	if err != nil {
		return nil, err
	}
	for _, v := range st.Volumes {
		if have[v] {
			continue
		}
		if err := s.call(ctx, sc, actor, agentproto.OpVolumesCreate, agentproto.VolumeCreate{Name: v, Stack: &agentproto.StackRef{Name: st.Name}}, nil); err != nil {
			return nil, fmt.Errorf("create volume %s: %w", v, err)
		}
		sc.Logf("created volume %s", v)
	}
	return have, nil
}

func (s *Service) planRestoreStack(raw json.RawMessage) ([]jobs.Step, error) {
	var p restorePayload
	if err := json.Unmarshal(raw, &p); err != nil || p.Repo <= 0 || !ValidSnapshotID(p.Snapshot) || p.Stack == "" {
		return nil, errors.New("invalid restore payload")
	}
	return []jobs.Step{
		{Name: "check the snapshot", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			r, m, st, err := s.restoreManifest(ctx, p.Repo, p.Snapshot, p.Stack)
			if err != nil {
				return err
			}
			defer r.T.Close()
			sc.Logf("snapshot %s from %s: %d volumes of %s", m.ID, time.UnixMilli(m.CreatedMS).UTC().Format(time.RFC3339), len(st.Volumes), p.Stack)
			return nil
		}},
		{Name: "stop the stack", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			_, err := s.stopStack(ctx, sc, p.Actor, p.Stack)
			return err
		}, Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
			if status, _ := s.stackStatus(ctx, p.Stack); status == "deployed" {
				return s.startStack(ctx, sc, p.Actor, p.Stack)
			}
			return nil
		}},
		{Name: "keep the current data", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			r, _, st, err := s.restoreManifest(ctx, p.Repo, p.Snapshot, p.Stack)
			if err != nil {
				return err
			}
			r.T.Close()
			have, err := s.ensureVolumes(ctx, sc, p.Actor, st)
			if err != nil {
				return err
			}
			pairs := []savedPair{}
			for _, v := range st.Volumes {
				if !have[v] {
					continue
				}
				pair := savedPair{Volume: v, Saved: preRestoreName(v)}
				if err := s.stacks.CopyVolume(ctx, sc, p.Actor, p.Stack, pair.Volume, pair.Saved); err != nil {
					return err
				}
				sc.Logf("kept %s in %s", pair.Volume, pair.Saved)
				pairs = append(pairs, pair)
			}
			return sc.SetOutput("saved", pairs)
		}, Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
			var pairs []savedPair
			if _, err := sc.Output(2, "saved", &pairs); err != nil {
				return err
			}
			if _, err := s.stopStack(ctx, sc, p.Actor, p.Stack); err != nil {
				return err
			}
			for _, pair := range pairs {
				if err := s.stacks.CopyVolume(ctx, sc, p.Actor, p.Stack, pair.Saved, pair.Volume); err != nil {
					return err
				}
				sc.Logf("put back the previous data of %s", pair.Volume)
			}
			return nil
		}},
		{Name: "restore the volumes", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			r, m, _, err := s.restoreManifest(ctx, p.Repo, p.Snapshot, p.Stack)
			if err != nil {
				return err
			}
			defer r.T.Close()
			return s.importVolumes(ctx, sc, p.Actor, r, m, p.Stack)
		}},
		{Name: "start and check the stack", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			if status, _ := s.stackStatus(ctx, p.Stack); status != "deployed" {
				sc.Logf("stack %s was not running; it stays stopped", p.Stack)
				return nil
			}
			if err := s.startStack(ctx, sc, p.Actor, p.Stack); err != nil {
				return err
			}
			return s.waitHealthy(ctx, sc, p.Actor, p.Stack)
		}},
		{Name: "remove the kept data", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			var pairs []savedPair
			if _, err := sc.Output(2, "saved", &pairs); err != nil {
				return err
			}
			for _, pair := range pairs {
				err := s.call(ctx, sc, p.Actor, agentproto.OpVolumesRemove, agentproto.NamedObject{Name: pair.Saved}, nil)
				var ae *agentclient.Error
				if err != nil && !(errors.As(err, &ae) && ae.Code == agentproto.CodeNotFound) {
					return err
				}
			}
			return nil
		}},
	}, nil
}

// ---- restore the platform's stacks after `kernhaven-core restore` ----

type platformPayload struct {
	Repo     int64    `json:"repo"`
	Snapshot string   `json:"snapshot"`
	Stacks   []string `json:"stacks"`
}

// startPendingRestore queues the restore of the stacks once after an
// offline platform restore.
func (s *Service) startPendingRestore(ctx context.Context) error {
	var repo int64
	var snap string
	err := s.db.QueryRowContext(ctx, `SELECT repo, snapshot FROM backup_restore_pending WHERE id = 1`).Scan(&repo, &snap)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var queued int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM jobs WHERE kind = ? AND state IN ('queued', 'running', 'compensating')`, KindRestorePlatform).Scan(&queued); err != nil {
		return err
	}
	if queued > 0 {
		return nil
	}
	m, err := s.SnapshotDetail(ctx, repo, snap)
	if err != nil {
		return err
	}
	known, err := s.stackNames(ctx)
	if err != nil {
		return err
	}
	var names []string
	for _, st := range m.Stacks {
		if _, ok := known[st.Name]; ok && st.DeployedRevision > 0 {
			names = append(names, st.Name)
		}
	}
	return withTx(ctx, s.db, func(tx *sql.Tx) error {
		id, err := s.jobs.EnqueueTx(ctx, tx, jobs.Request{Kind: KindRestorePlatform, Payload: platformPayload{Repo: repo, Snapshot: snap, Stacks: names}, DedupeKey: "backup:restore-platform"})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM backup_restore_pending WHERE id = 1`); err != nil {
			return err
		}
		s.log.Info("restoring the stacks of the restored platform", "snapshot", snap, "stacks", len(names), "job", id)
		_, err = audit.Append(ctx, tx, s.now(), s.event(Actor{Name: "system"}, "backup.restore_platform", "backup-repo:"+fmt.Sprint(repo), nil, "snapshot", snap, "job", fmt.Sprint(id)))
		return err
	})
}

func (s *Service) planRestorePlatform(raw json.RawMessage) ([]jobs.Step, error) {
	var p platformPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.Repo <= 0 || !ValidSnapshotID(p.Snapshot) {
		return nil, errors.New("invalid restore payload")
	}
	const actor = "system"
	var steps []jobs.Step
	for _, name := range p.Stacks {
		idx, name := len(steps), name
		steps = append(steps, jobs.Step{Name: "restore stack " + name, Run: func(ctx context.Context, sc *jobs.StepContext) error {
			var job int64
			if ok, _ := sc.Output(idx, "job", &job); ok {
				return nil
			}
			r, m, st, err := s.restoreManifest(ctx, p.Repo, p.Snapshot, name)
			if err != nil {
				return err
			}
			defer r.T.Close()
			if _, err := s.ensureVolumes(ctx, sc, actor, st); err != nil {
				return err
			}
			if err := s.importVolumes(ctx, sc, actor, r, m, name); err != nil {
				return err
			}
			job, err = s.redeploy(ctx, name, st.DeployedRevision)
			if err != nil {
				return err
			}
			sc.Logf("deploying %s revision %d (job %d)", name, st.DeployedRevision, job)
			return sc.SetOutput("job", job)
		}})
	}
	steps = append(steps, jobs.Step{Name: "check the stacks", Run: func(ctx context.Context, sc *jobs.StepContext) error {
		var failed []string
		for i, name := range p.Stacks {
			var job int64
			if _, err := sc.Output(i, "job", &job); err != nil {
				return err
			}
			state, err := s.waitJob(ctx, job)
			if err != nil {
				return err
			}
			if state != jobs.Succeeded {
				failed = append(failed, name)
			}
		}
		if len(failed) > 0 {
			return jobs.Permanent(fmt.Errorf("stacks did not start healthy after the restore: %s", strings.Join(failed, ", ")))
		}
		sc.Logf("%d stacks restored and healthy", len(p.Stacks))
		return nil
	}})
	return steps, nil
}

// redeploy queues a deployment of the stack's revision; the deployment
// waits for its health checks.
func (s *Service) redeploy(ctx context.Context, name string, rev int) (int64, error) {
	var id int64
	err := withTx(ctx, s.db, func(tx *sql.Tx) error {
		st, err := s.stacks.Get(ctx, tx, name)
		if err != nil {
			return jobs.Permanent(err)
		}
		id, err = s.stacks.DeployManaged(ctx, tx, stacks.Actor{Name: "system"}, st, rev, false)
		if errors.Is(err, jobs.ErrDuplicate) {
			// An earlier attempt queued it.
			return tx.QueryRowContext(ctx, `SELECT id FROM jobs WHERE dedupe_key = ? ORDER BY id DESC LIMIT 1`, "stack:"+name).Scan(&id)
		}
		return err
	})
	if err == nil {
		s.stacks.Wake()
	}
	return id, err
}

func (s *Service) waitJob(ctx context.Context, id int64) (jobs.State, error) {
	deadline := time.Now().Add(s.cfg.HealthTimeout * 6)
	for {
		var state string
		if err := s.db.QueryRowContext(ctx, `SELECT state FROM jobs WHERE id = ?`, id).Scan(&state); err != nil {
			return "", err
		}
		if jobs.State(state).Terminal() {
			return jobs.State(state), nil
		}
		if time.Now().After(deadline) {
			return "", jobs.Permanent(fmt.Errorf("job %d did not finish", id))
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(s.poll):
		}
	}
}
