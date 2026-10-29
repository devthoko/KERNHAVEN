package stacks

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/compose"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

type deployPayload struct {
	StackID  int64  `json:"stack_id"`
	Revision int    `json:"revision"`
	Actor    string `json:"actor"`
	// Snapshot copies the stack's volumes before the new revision starts (M8).
	Snapshot bool `json:"snapshot,omitempty"`
}

type downPayload struct {
	StackID       int64  `json:"stack_id"`
	RemoveVolumes bool   `json:"remove_volumes"`
	Actor         string `json:"actor"`
	// DeleteStack deletes the stack record at the end (app removal, M8).
	DeleteStack bool `json:"delete_stack,omitempty"`
}

// call runs an agent operation for a job. Errors that cannot succeed on retry
// are marked permanent.
func (s *Service) call(ctx context.Context, sc *jobs.StepContext, actor, op string, params, out any) error {
	if s.agent == nil {
		return jobs.Permanent(errors.New("no host agent is configured"))
	}
	err := s.agent.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: actor, RequestID: fmt.Sprintf("job-%d", sc.JobID)}, out)
	var ae *agentclient.Error
	if errors.As(err, &ae) {
		switch ae.Code {
		case agentproto.CodeInvalidParams, agentproto.CodePolicyViolation, agentproto.CodeNotFound, agentproto.CodeInvalidGrant:
			return jobs.Permanent(err)
		}
	}
	return err
}

func isCode(err error, code string) bool {
	var ae *agentclient.Error
	return errors.As(err, &ae) && ae.Code == code
}

// render loads and parses revision n of a stack with its current variables.
func (s *Service) render(ctx context.Context, stackID int64, n int) (Stack, Revision, *compose.Project, error) {
	st, err := s.st.byID(ctx, s.st.db, stackID)
	if err != nil {
		return st, Revision{}, nil, jobs.Permanent(err)
	}
	rev, err := s.st.revision(ctx, s.st.db, stackID, n)
	if err != nil {
		return st, rev, nil, jobs.Permanent(err)
	}
	vars, err := s.st.variables(ctx, s.st.db, stackID)
	if err != nil {
		return st, rev, nil, jobs.Permanent(err)
	}
	proj, errs := compose.Parse([]byte(rev.Compose), st.Name, varMap(vars))
	if errs != nil {
		return st, rev, nil, jobs.Permanent(fmt.Errorf("revision %d is invalid with the current variables: %v", n, errs))
	}
	return st, rev, proj, nil
}

func (s *Service) listContainers(ctx context.Context, sc *jobs.StepContext, actor, stack string) ([]agentproto.ContainerSummary, error) {
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

func (s *Service) removeContainer(ctx context.Context, sc *jobs.StepContext, actor, ref string) error {
	err := s.call(ctx, sc, actor, agentproto.OpContainersRemove, agentproto.RemoveContainer{ID: ref, Force: true}, nil)
	if err != nil && isCode(err, agentproto.CodeNotFound) {
		return nil
	}
	return err
}

// startServices creates and starts every service of revision n in dependency order.
func (s *Service) startServices(ctx context.Context, sc *jobs.StepContext, actor string, st Stack, rev Revision, proj *compose.Project) error {
	order, err := compose.Order(proj)
	if err != nil {
		return jobs.Permanent(err)
	}
	for _, svc := range order {
		if err := s.removeContainer(ctx, sc, actor, svc.Spec.Name); err != nil {
			return err
		}
		req := agentproto.CreateContainer{Spec: svc.Spec, Exceptions: rulesFor(rev.Exceptions, svc.Name), Start: true,
			Stack: &agentproto.StackRef{Name: st.Name, Service: svc.Name, Revision: rev.Number}}
		if err := s.call(ctx, sc, actor, agentproto.OpContainersCreate, req, nil); err != nil {
			return fmt.Errorf("service %s: %w", svc.Name, err)
		}
		sc.Logf("started %s (revision %d)", svc.Spec.Name, rev.Number)
	}
	return nil
}

func (s *Service) planDeploy(raw json.RawMessage) ([]jobs.Step, error) {
	var p deployPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.StackID <= 0 || p.Revision <= 0 {
		return nil, errors.New("invalid deployment payload")
	}
	fail := func(ctx context.Context, msg string) {
		_ = s.st.setStatus(context.WithoutCancel(ctx), p.StackID, "failed", msg, nil)
	}
	// Steps 0-3 keep their indexes: later steps read their outputs by index.
	steps := []jobs.Step{
		{
			Name: "validate revision and policy",
			Run: func(ctx context.Context, sc *jobs.StepContext) error {
				_, rev, proj, err := s.render(ctx, p.StackID, p.Revision)
				if err == nil {
					for _, svc := range proj.Services {
						if _, perr := policy.Check(svc.Spec, rulesFor(rev.Exceptions, svc.Name), policy.Options{AllowedBindRoots: s.bindRoots}); perr != nil {
							err = jobs.Permanent(fmt.Errorf("service %s: %w", svc.Name, perr))
							break
						}
					}
				}
				if err != nil {
					fail(ctx, err.Error())
					return err
				}
				sc.Logf("revision %d: %d services", p.Revision, len(proj.Services))
				return nil
			},
			Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
				var prev int
				if ok, _ := sc.Output(3, "previous", &prev); !ok {
					st, err := s.st.byID(ctx, s.st.db, p.StackID)
					if err != nil {
						return err
					}
					prev = st.DeployedRevision
				}
				msg := fmt.Sprintf("deployment of revision %d failed; nothing was running before", p.Revision)
				if prev > 0 {
					msg = fmt.Sprintf("deployment of revision %d failed; rolled back to revision %d", p.Revision, prev)
				}
				status := "failed"
				return s.st.setStatus(ctx, p.StackID, status, msg, nil)
			},
		},
		{
			Name: "pull images",
			Run: func(ctx context.Context, sc *jobs.StepContext) error {
				_, _, proj, err := s.render(ctx, p.StackID, p.Revision)
				if err != nil {
					return err
				}
				seen := map[string]bool{}
				for _, svc := range proj.Services {
					if seen[svc.Spec.Image] {
						continue
					}
					seen[svc.Spec.Image] = true
					pctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
					var res agentproto.PullResult
					err := s.call(pctx, sc, p.Actor, agentproto.OpImagesPull, agentproto.ImageRef{Reference: svc.Spec.Image}, &res)
					cancel()
					if err != nil {
						return fmt.Errorf("pull %s: %w", svc.Spec.Image, err)
					}
					sc.Logf("pulled %s → %s", svc.Spec.Image, res.Digest)
				}
				return nil
			},
		},
		{
			Name: "create networks and volumes",
			Run: func(ctx context.Context, sc *jobs.StepContext) error {
				st, _, proj, err := s.render(ctx, p.StackID, p.Revision)
				if err != nil {
					return err
				}
				var nets []agentproto.NetworkSummary
				var vols []agentproto.VolumeSummary
				if err := s.call(ctx, sc, p.Actor, agentproto.OpNetworksList, nil, &nets); err != nil {
					return err
				}
				if err := s.call(ctx, sc, p.Actor, agentproto.OpVolumesList, nil, &vols); err != nil {
					return err
				}
				haveNet, haveVol := map[string]bool{}, map[string]bool{}
				for _, n := range nets {
					haveNet[n.Name] = true
				}
				for _, v := range vols {
					haveVol[v.Name] = true
				}
				var created []string
				var done []string
				_, _ = sc.Output(2, "created_networks", &done)
				for _, n := range proj.Networks {
					if haveNet[n.Name] {
						continue
					}
					if n.External {
						return jobs.Permanent(fmt.Errorf("external network %s does not exist", n.Name))
					}
					if err := s.call(ctx, sc, p.Actor, agentproto.OpNetworksCreate, agentproto.NetworkCreate{Name: n.Name, Internal: n.Internal, Labels: n.Labels,
						Stack: &agentproto.StackRef{Name: st.Name}}, nil); err != nil {
						return err
					}
					created = append(created, n.Name)
					sc.Logf("created network %s", n.Name)
				}
				for _, v := range proj.Volumes {
					if haveVol[v.Name] {
						continue
					}
					if v.External {
						return jobs.Permanent(fmt.Errorf("external volume %s does not exist", v.Name))
					}
					if err := s.call(ctx, sc, p.Actor, agentproto.OpVolumesCreate, agentproto.VolumeCreate{Name: v.Name, Labels: v.Labels,
						Stack: &agentproto.StackRef{Name: st.Name}}, nil); err != nil {
						return err
					}
					sc.Logf("created volume %s", v.Name)
				}
				return sc.SetOutput("created_networks", append(done, created...))
			},
			Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
				var created []string
				_, _ = sc.Output(2, "created_networks", &created)
				for _, n := range created {
					err := s.call(ctx, sc, p.Actor, agentproto.OpNetworksRemove, agentproto.NamedObject{Name: n}, nil)
					if err != nil && !isCode(err, agentproto.CodeNotFound) {
						return err
					}
					sc.Logf("removed network %s (rollback)", n)
				}
				return nil
			},
		},
		{
			Name: "remove containers of the previous revision",
			Run: func(ctx context.Context, sc *jobs.StepContext) error {
				st, err := s.st.byID(ctx, s.st.db, p.StackID)
				if err != nil {
					return jobs.Permanent(err)
				}
				if err := sc.SetOutput("previous", st.DeployedRevision); err != nil {
					return err
				}
				list, err := s.listContainers(ctx, sc, p.Actor, st.Name)
				if err != nil {
					return err
				}
				for _, c := range list {
					if err := s.removeContainer(ctx, sc, p.Actor, c.ID); err != nil {
						return err
					}
				}
				sc.Logf("removed %d containers of revision %d", len(list), st.DeployedRevision)
				return nil
			},
			Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
				// A later step may have stopped half-way: remove every container
				// of the stack before restoring the previous revision.
				st, err := s.st.byID(ctx, s.st.db, p.StackID)
				if err != nil {
					return err
				}
				list, err := s.listContainers(ctx, sc, p.Actor, st.Name)
				if err != nil {
					return err
				}
				for _, c := range list {
					if err := s.removeContainer(ctx, sc, p.Actor, c.ID); err != nil {
						return err
					}
				}
				var prev int
				if ok, _ := sc.Output(3, "previous", &prev); !ok || prev == 0 {
					return nil
				}
				st, rev, proj, err := s.render(ctx, p.StackID, prev)
				if err != nil {
					return err
				}
				sc.Logf("restoring revision %d", prev)
				return s.startServices(ctx, sc, p.Actor, st, rev, proj)
			},
		},
	}
	if p.Snapshot {
		steps = append(steps, s.snapshotStep(p))
	}
	return append(steps, []jobs.Step{
		{
			Name: "create and start services",
			Run: func(ctx context.Context, sc *jobs.StepContext) error {
				st, rev, proj, err := s.render(ctx, p.StackID, p.Revision)
				if err != nil {
					return err
				}
				return s.startServices(ctx, sc, p.Actor, st, rev, proj)
			},
			Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
				st, err := s.st.byID(ctx, s.st.db, p.StackID)
				if err != nil {
					return err
				}
				list, err := s.listContainers(ctx, sc, p.Actor, st.Name)
				if err != nil {
					return err
				}
				for _, c := range list {
					if c.Labels[labelRevision] == strconv.Itoa(p.Revision) {
						if err := s.removeContainer(ctx, sc, p.Actor, c.ID); err != nil {
							return err
						}
					}
				}
				return nil
			},
		},
		{
			Name: "verify services are running and healthy",
			Run: func(ctx context.Context, sc *jobs.StepContext) error {
				_, _, proj, err := s.render(ctx, p.StackID, p.Revision)
				if err != nil {
					return err
				}
				deadline := time.Now().Add(s.VerifyTimeout)
				for {
					pending, ferr := s.checkServices(ctx, sc, p.Actor, proj)
					if ferr != nil {
						return jobs.Permanent(ferr)
					}
					if len(pending) == 0 {
						sc.Logf("all %d services are running", len(proj.Services))
						return nil
					}
					if time.Now().After(deadline) {
						return jobs.Permanent(fmt.Errorf("not ready within %s: %v", s.VerifyTimeout, pending))
					}
					select {
					case <-ctx.Done():
						return ctx.Err()
					case <-time.After(s.pollInterval):
					}
				}
			},
		},
		{
			Name: "record deployment",
			Run: func(ctx context.Context, sc *jobs.StepContext) error {
				n := p.Revision
				return s.st.setStatus(ctx, p.StackID, "deployed", "", &n)
			},
		},
	}...), nil
}

// checkServices returns services that are not ready yet, or an error for a
// service that failed.
func (s *Service) checkServices(ctx context.Context, sc *jobs.StepContext, actor string, proj *compose.Project) ([]string, error) {
	var pending []string
	for _, svc := range proj.Services {
		var d agentproto.ContainerDetail
		if err := s.call(ctx, sc, actor, agentproto.OpContainersInspect, agentproto.ContainerRef{ID: svc.Spec.Name}, &d); err != nil {
			return nil, fmt.Errorf("service %s: %w", svc.Name, err)
		}
		switch {
		case d.Status == "exited" || d.Status == "dead":
			return nil, fmt.Errorf("service %s exited with code %d", svc.Name, d.ExitCode)
		case d.Health == "unhealthy":
			return nil, fmt.Errorf("service %s is unhealthy", svc.Name)
		case !d.Running:
			pending = append(pending, svc.Name+" ("+d.Status+")")
		case svc.Spec.Healthcheck != nil && svc.Spec.Healthcheck.Test[0] != "NONE" && d.Health != "healthy":
			pending = append(pending, svc.Name+" (health: "+d.Health+")")
		}
	}
	return pending, nil
}

func (s *Service) planDown(raw json.RawMessage) ([]jobs.Step, error) {
	var p downPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.StackID <= 0 {
		return nil, errors.New("invalid payload")
	}
	name := func(ctx context.Context) (string, error) {
		st, err := s.st.byID(ctx, s.st.db, p.StackID)
		if err != nil {
			return "", jobs.Permanent(err)
		}
		return st.Name, nil
	}
	steps := []jobs.Step{
		{Name: "stop and remove containers", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			n, err := name(ctx)
			if err != nil {
				return err
			}
			list, err := s.listContainers(ctx, sc, p.Actor, n)
			if err != nil {
				return err
			}
			for _, c := range list {
				if err := s.removeContainer(ctx, sc, p.Actor, c.ID); err != nil {
					return err
				}
			}
			sc.Logf("removed %d containers", len(list))
			return nil
		}},
		{Name: "remove networks", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			n, err := name(ctx)
			if err != nil {
				return err
			}
			var nets []agentproto.NetworkSummary
			if err := s.call(ctx, sc, p.Actor, agentproto.OpNetworksList, nil, &nets); err != nil {
				return err
			}
			for _, nw := range nets {
				if nw.Labels[labelStack] == n {
					err := s.call(ctx, sc, p.Actor, agentproto.OpNetworksRemove, agentproto.NamedObject{Name: nw.Name}, nil)
					if err != nil && !isCode(err, agentproto.CodeNotFound) {
						return err
					}
					sc.Logf("removed network %s", nw.Name)
				}
			}
			return nil
		}},
	}
	if p.RemoveVolumes {
		steps = append(steps, jobs.Step{Name: "remove volumes", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			n, err := name(ctx)
			if err != nil {
				return err
			}
			var vols []agentproto.VolumeSummary
			if err := s.call(ctx, sc, p.Actor, agentproto.OpVolumesList, nil, &vols); err != nil {
				return err
			}
			for _, v := range vols {
				if v.Labels[labelStack] == n {
					err := s.call(ctx, sc, p.Actor, agentproto.OpVolumesRemove, agentproto.NamedObject{Name: v.Name}, nil)
					if err != nil && !isCode(err, agentproto.CodeNotFound) {
						return err
					}
					sc.Logf("removed volume %s", v.Name)
				}
			}
			return nil
		}})
	}
	if p.DeleteStack {
		return append(steps, jobs.Step{Name: "delete stack record", Run: func(ctx context.Context, sc *jobs.StepContext) error {
			st, err := s.st.byID(ctx, s.st.db, p.StackID)
			if errors.Is(err, ErrNotFound) {
				return nil // already deleted by an earlier attempt
			}
			if err != nil {
				return err
			}
			return s.withTx(ctx, func(tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `DELETE FROM stacks WHERE id = ?`, st.ID); err != nil {
					return err
				}
				_, err := audit.Append(ctx, tx, s.st.now(), audit.Event{Actor: p.Actor, Action: "stack.delete", Target: "stack:" + st.Name,
					Result: audit.Success, Details: map[string]string{"job": fmt.Sprint(sc.JobID), "volumes_removed": fmt.Sprint(p.RemoveVolumes)}})
				return err
			})
		}}), nil
	}
	steps = append(steps, jobs.Step{Name: "record", Run: func(ctx context.Context, sc *jobs.StepContext) error {
		zero := 0
		return s.st.setStatus(ctx, p.StackID, "stopped", "", &zero)
	}})
	return steps, nil
}

// snapshotName is the volume holding the pre-update copy of vol.
func snapshotName(vol string) string {
	const suffix = ".snapshot"
	if len(vol)+len(suffix) <= 63 {
		return vol + suffix
	}
	sum := sha256.Sum256([]byte(vol))
	return vol[:40] + "." + hex.EncodeToString(sum[:4]) + suffix
}

type snapshotPair struct {
	Volume   string `json:"volume"`
	Snapshot string `json:"snapshot"`
}

// snapshotStep copies every volume of the stack before the new revision
// starts; its compensation restores them (AT-F05-02, ADR-0021). It runs after
// the previous containers were removed, so the data does not change while it
// is copied.
func (s *Service) snapshotStep(p deployPayload) jobs.Step {
	return jobs.Step{
		Name: "snapshot volumes",
		Run: func(ctx context.Context, sc *jobs.StepContext) error {
			st, err := s.st.byID(ctx, s.st.db, p.StackID)
			if err != nil {
				return jobs.Permanent(err)
			}
			var vols []agentproto.VolumeSummary
			if err := s.call(ctx, sc, p.Actor, agentproto.OpVolumesList, nil, &vols); err != nil {
				return err
			}
			pairs := []snapshotPair{}
			for _, v := range vols {
				if v.Labels[labelStack] != st.Name || v.Labels[labelSnapshotOf] != "" {
					continue
				}
				pair := snapshotPair{Volume: v.Name, Snapshot: snapshotName(v.Name)}
				if err := s.copyVolume(ctx, sc, p.Actor, st.Name, pair.Volume, pair.Snapshot); err != nil {
					return err
				}
				sc.Logf("copied %s to %s", pair.Volume, pair.Snapshot)
				pairs = append(pairs, pair)
			}
			sc.Logf("%d volumes saved", len(pairs))
			return sc.SetOutput("snapshots", pairs)
		},
		Compensate: func(ctx context.Context, sc *jobs.StepContext) error {
			st, err := s.st.byID(ctx, s.st.db, p.StackID)
			if err != nil {
				return err
			}
			var pairs []snapshotPair
			if _, err := sc.Output(4, "snapshots", &pairs); err != nil {
				return err
			}
			// Containers of the failed revision may still be running.
			list, err := s.listContainers(ctx, sc, p.Actor, st.Name)
			if err != nil {
				return err
			}
			for _, c := range list {
				if err := s.removeContainer(ctx, sc, p.Actor, c.ID); err != nil {
					return err
				}
			}
			for _, pair := range pairs {
				if err := s.copyVolume(ctx, sc, p.Actor, st.Name, pair.Snapshot, pair.Volume); err != nil {
					return err
				}
				sc.Logf("restored %s from %s", pair.Volume, pair.Snapshot)
			}
			return nil
		},
	}
}

// CopyVolume replaces dst with a copy of src for another module's job;
// restores keep a stack's current data with it (M16).
func (s *Service) CopyVolume(ctx context.Context, sc *jobs.StepContext, actor, stack, src, dst string) error {
	return s.copyVolume(ctx, sc, actor, stack, src, dst)
}

// copyVolume replaces dst with a copy of src through the agent's helper
// container and waits until it has finished.
func (s *Service) copyVolume(ctx context.Context, sc *jobs.StepContext, actor, stack, src, dst string) error {
	var res agentproto.VolumeCopyResult
	if err := s.call(ctx, sc, actor, agentproto.OpVolumesCopy, agentproto.VolumeCopy{Source: src, Target: dst, Stack: stack}, &res); err != nil {
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	deadline := time.Now().Add(s.CopyTimeout)
	for {
		var d agentproto.ContainerDetail
		if err := s.call(ctx, sc, actor, agentproto.OpContainersInspect, agentproto.ContainerRef{ID: res.Helper}, &d); err != nil {
			return fmt.Errorf("copy %s to %s: %w", src, dst, err)
		}
		if !d.Running && (d.Status == "exited" || d.Status == "dead") {
			if err := s.removeContainer(ctx, sc, actor, res.Helper); err != nil {
				return err
			}
			if d.ExitCode != 0 {
				return jobs.Permanent(fmt.Errorf("copying %s to %s failed with exit code %d (disk full?)", src, dst, d.ExitCode))
			}
			return nil
		}
		if time.Now().After(deadline) {
			return jobs.Permanent(fmt.Errorf("copying %s to %s did not finish within %s", src, dst, s.CopyTimeout))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.pollInterval):
		}
	}
}
