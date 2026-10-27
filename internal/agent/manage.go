package agent

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// Labels set by the agent on objects it creates.
const (
	LabelManaged    = "io.kernhaven.managed"
	LabelCreatedBy  = "io.kernhaven.created_by"
	LabelExceptions = "io.kernhaven.policy.exceptions"
)

type actorKey struct{}

func actorFrom(ctx context.Context) string {
	a, _ := ctx.Value(actorKey{}).(string)
	return a
}

var imageIDRe = regexp.MustCompile(`^(sha256:)?[a-f0-9]{12,64}$`)

func validLabels(l map[string]string) error {
	if len(l) > 64 {
		return invalid("at most 64 labels")
	}
	for k, v := range l {
		if k == "" || len(k) > 128 || len(v) > 1024 || strings.HasPrefix(k, policy.ReservedLabelPrefix) {
			return invalid("invalid or reserved label %q", k)
		}
	}
	return nil
}

func managedLabels(ctx context.Context, extra map[string]string) map[string]string {
	l := map[string]string{LabelManaged: "true", LabelCreatedBy: actorFrom(ctx)}
	for k, v := range extra {
		l[k] = v
	}
	return l
}

// manageOperations are the M6 operations.
func manageOperations(d Docker, o Options) map[string]handler {
	popts := policy.Options{AllowedBindRoots: o.AllowedBindRoots, Resolve: filepath.EvalSymlinks}
	return map[string]handler{
		agentproto.OpContainersCreate: typed(func(ctx context.Context, p agentproto.CreateContainer) (any, error) {
			if err := policy.Validate(p.Spec); err != nil {
				return nil, invalid("%v", err)
			}
			// Authoritative policy evaluation (TH-21, TH-30).
			dec, err := policy.Check(p.Spec, p.Exceptions, popts)
			if err != nil {
				return nil, err
			}
			labels := map[string]string{}
			if len(dec.Applied) > 0 {
				labels[LabelExceptions] = strings.Join(dec.Applied, ",")
			}
			res, err := d.Create(ctx, p.Spec, managedLabels(ctx, labels))
			if err != nil {
				return nil, err
			}
			for _, w := range dec.Result.Warnings {
				res.Warnings = append(res.Warnings, w.Message)
			}
			if p.Start {
				if _, err := d.Start(ctx, res.ID); err != nil {
					return nil, err
				}
			}
			return res, nil
		}),
		agentproto.OpContainersRemove: typed(func(ctx context.Context, p agentproto.RemoveContainer) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			return agentproto.ActionResult{ID: p.ID, Changed: true}, d.Remove(ctx, p.ID, p.Force, p.RemoveVolumes)
		}),
		agentproto.OpContainersPause: typed(func(ctx context.Context, p agentproto.ContainerRef) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			changed, err := d.Pause(ctx, p.ID)
			return agentproto.ActionResult{ID: p.ID, Changed: changed}, err
		}),
		agentproto.OpContainersUnpause: typed(func(ctx context.Context, p agentproto.ContainerRef) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			changed, err := d.Unpause(ctx, p.ID)
			return agentproto.ActionResult{ID: p.ID, Changed: changed}, err
		}),
		agentproto.OpContainersLogs: typed(func(ctx context.Context, p agentproto.LogsRequest) (any, error) {
			if err := validRef(p.ID); err != nil {
				return nil, err
			}
			if p.Tail == 0 {
				p.Tail = 200
			}
			if p.Tail < 1 || p.Tail > 10000 {
				return nil, invalid("tail must be 1..10000")
			}
			if p.Since < 0 || p.Until < 0 || (p.Until > 0 && p.Until < p.Since) {
				return nil, invalid("since/until must be Unix seconds with until >= since")
			}
			return d.Logs(ctx, p)
		}),
		agentproto.OpImagesList: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			return d.ListImages(ctx)
		}),
		agentproto.OpImagesPull: typed(func(ctx context.Context, p agentproto.ImageRef) (any, error) {
			if !policy.ValidImageReference(p.Reference) {
				return nil, invalid("reference is not a valid image reference")
			}
			return d.Pull(ctx, p.Reference)
		}),
		agentproto.OpImagesRemove: typed(func(ctx context.Context, p agentproto.ImageRef) (any, error) {
			if !policy.ValidImageReference(p.Reference) && !imageIDRe.MatchString(p.Reference) {
				return nil, invalid("reference must be an image reference or ID")
			}
			return agentproto.ActionResult{ID: p.Reference, Changed: true}, d.RemoveImage(ctx, p.Reference, p.Force)
		}),
		agentproto.OpImagesPrune: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			return d.PruneImages(ctx)
		}),
		agentproto.OpVolumesList: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			v, err := d.ListVolumes(ctx)
			if err == nil {
				sort.Slice(v, func(i, j int) bool { return v[i].Name < v[j].Name })
			}
			return v, err
		}),
		agentproto.OpVolumesCreate: typed(func(ctx context.Context, p agentproto.VolumeCreate) (any, error) {
			if !policy.ValidName(p.Name) {
				return nil, invalid("name must be 1-63 characters: letters, digits, _ . -")
			}
			if err := validLabels(p.Labels); err != nil {
				return nil, err
			}
			return agentproto.NamedObject{Name: p.Name}, d.CreateVolume(ctx, p.Name, managedLabels(ctx, p.Labels))
		}),
		agentproto.OpVolumesRemove: typed(func(ctx context.Context, p agentproto.NamedObject) (any, error) {
			if !policy.ValidName(p.Name) && !imageIDRe.MatchString(p.Name) {
				return nil, invalid("invalid volume name")
			}
			return agentproto.ActionResult{ID: p.Name, Changed: true}, d.RemoveVolume(ctx, p.Name)
		}),
		agentproto.OpNetworksList: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			n, err := d.ListNetworks(ctx)
			if err == nil {
				sort.Slice(n, func(i, j int) bool { return n[i].Name < n[j].Name })
			}
			return n, err
		}),
		agentproto.OpNetworksCreate: typed(func(ctx context.Context, p agentproto.NetworkCreate) (any, error) {
			if !policy.ValidName(p.Name) || docker.BuiltInNetworks[p.Name] {
				return nil, invalid("name must be a valid, non built-in network name")
			}
			if err := validLabels(p.Labels); err != nil {
				return nil, err
			}
			id, err := d.CreateNetwork(ctx, p.Name, p.Internal, managedLabels(ctx, p.Labels))
			return agentproto.NetworkSummary{ID: id, Name: p.Name, Driver: "bridge", Internal: p.Internal}, err
		}),
		agentproto.OpNetworksRemove: typed(func(ctx context.Context, p agentproto.NamedObject) (any, error) {
			if (!policy.ValidName(p.Name) && !imageIDRe.MatchString(p.Name)) || docker.BuiltInNetworks[p.Name] {
				return nil, invalid("built-in networks cannot be removed")
			}
			return agentproto.ActionResult{ID: p.Name, Changed: true}, d.RemoveNetwork(ctx, p.Name)
		}),
	}
}
