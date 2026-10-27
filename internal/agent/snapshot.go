package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// Volume copies (ADR-0021).
const (
	// DefaultHelperImage is busybox 1.37.0 pinned by its multi-arch index digest.
	DefaultHelperImage = "busybox:1.37.0@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
	LabelHelper        = "io.kernhaven.helper"
	LabelSnapshotOf    = "io.kernhaven.snapshot.of"
	helperVolumeCopy   = "volume-copy"
)

// copyScript empties /to (including dot files) and copies /from preserving
// owners, modes and timestamps. It is fixed here; callers supply only names.
const copyScript = `set -e; cd /to; rm -rf -- * .[!.]* ..?*; cp -a /from/. /to/`

// HelperName is the deterministic name of the helper copying into target, so
// a retried copy replaces an interrupted one.
func HelperName(target string) string {
	sum := sha256.Sum256([]byte(target))
	return "kh-volume-copy-" + hex.EncodeToString(sum[:6])
}

func helperSpec(image, name, source, target string) agentproto.ContainerSpec {
	return agentproto.ContainerSpec{
		Name: name, Image: image, Cmd: []string{"sh", "-c", copyScript},
		User: "0", NetworkMode: "none", ReadOnlyRootfs: true,
		CapDrop:     []string{"ALL"},
		CapAdd:      []string{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID"},
		SecurityOpt: []string{"no-new-privileges"},
		MemoryBytes: 256 << 20,
		Mounts: []agentproto.MountSpec{
			{Type: "volume", Source: source, Target: "/from", ReadOnly: true},
			{Type: "volume", Source: target, Target: "/to"},
		},
	}
}

func volumeCopy(d Docker, o Options) handler {
	image := o.HelperImage
	if image == "" {
		image = DefaultHelperImage
	}
	return typed(func(ctx context.Context, p agentproto.VolumeCopy) (any, error) {
		if !policy.ValidName(p.Source) || !policy.ValidName(p.Target) || p.Source == p.Target || !stackNameRe.MatchString(p.Stack) {
			return nil, invalid("source and target must be different valid volume names of a valid stack")
		}
		vols, err := d.ListVolumes(ctx)
		if err != nil {
			return nil, err
		}
		var src, dst *agentproto.VolumeSummary
		for i := range vols {
			switch vols[i].Name {
			case p.Source:
				src = &vols[i]
			case p.Target:
				dst = &vols[i]
			}
		}
		// Both volumes must belong to the stack, so a compromised Core cannot
		// copy data out of other stacks or unmanaged volumes (ADR-0021).
		if src == nil {
			return nil, docker.ErrNotFound
		}
		if src.Labels[LabelStack] != p.Stack || (dst != nil && dst.Labels[LabelStack] != p.Stack) {
			return nil, invalid("both volumes must belong to stack %s", p.Stack)
		}
		if dst == nil {
			if err := d.CreateVolume(ctx, p.Target, managedLabels(ctx, map[string]string{LabelStack: p.Stack, LabelSnapshotOf: p.Source})); err != nil {
				return nil, err
			}
		}
		name := HelperName(p.Target)
		if err := d.Remove(ctx, name, true, false); err != nil && !errors.Is(err, docker.ErrNotFound) {
			return nil, err
		}
		spec := helperSpec(image, name, p.Source, p.Target)
		labels := managedLabels(ctx, map[string]string{LabelHelper: helperVolumeCopy})
		res, err := d.Create(ctx, spec, labels)
		if errors.Is(err, docker.ErrNotFound) {
			if _, err := d.Pull(ctx, image); err != nil {
				return nil, err
			}
			res, err = d.Create(ctx, spec, labels)
		}
		if err != nil {
			return nil, err
		}
		if _, err := d.Start(ctx, res.ID); err != nil {
			_ = d.Remove(ctx, res.ID, true, false)
			return nil, err
		}
		return agentproto.VolumeCopyResult{Helper: name}, nil
	})
}
