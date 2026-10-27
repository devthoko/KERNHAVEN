package agent

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// copyDocker adds volumes and a capturing Create to fakeDocker.
type copyDocker struct {
	*fakeDocker
	vols       []agentproto.VolumeSummary
	spec       agentproto.ContainerSpec
	labels     map[string]string
	imageGone  bool
	createRuns int
}

func (c *copyDocker) ListVolumes(context.Context) ([]agentproto.VolumeSummary, error) {
	return c.vols, c.record("volumes")
}

func (c *copyDocker) Create(_ context.Context, s agentproto.ContainerSpec, labels map[string]string) (agentproto.CreateResult, error) {
	c.createRuns++
	if c.imageGone && c.createRuns == 1 {
		return agentproto.CreateResult{}, docker.ErrNotFound
	}
	c.spec, c.labels = s, labels
	return agentproto.CreateResult{ID: "helper1"}, c.record("create " + s.Name)
}

func (c *copyDocker) Start(_ context.Context, id string) (bool, error) {
	return true, c.record("start " + id)
}

func (c *copyDocker) Remove(_ context.Context, id string, force, volumes bool) error {
	_ = c.record("remove " + id)
	return docker.ErrNotFound
}

func runCopy(t *testing.T, d Docker, params string) (agentproto.VolumeCopyResult, error) {
	t.Helper()
	h := volumeCopy(d, Options{})
	out, err := h(context.WithValue(context.Background(), actorKey{}, "owner"), json.RawMessage(params))
	if err != nil {
		return agentproto.VolumeCopyResult{}, err
	}
	return out.(agentproto.VolumeCopyResult), nil
}

func stackVol(name, stack string) agentproto.VolumeSummary {
	return agentproto.VolumeSummary{Name: name, Labels: map[string]string{LabelStack: stack}}
}

func TestVolumeCopyHelperIsConfined(t *testing.T) {
	d := &copyDocker{fakeDocker: &fakeDocker{t: t}, vols: []agentproto.VolumeSummary{stackVol("app_data", "app")}, imageGone: true}
	res, err := runCopy(t, d, `{"source":"app_data","target":"app_data.snapshot","stack":"app"}`)
	if err != nil {
		t.Fatal(err)
	}
	if res.Helper != HelperName("app_data.snapshot") || !strings.HasPrefix(res.Helper, "kh-volume-copy-") {
		t.Fatalf("helper %q", res.Helper)
	}
	calls := strings.Join(d.callList(), "|")
	for _, want := range []string{"volume app_data.snapshot managed=true", "pull " + DefaultHelperImage, "create " + res.Helper, "start helper1"} {
		if !strings.Contains(calls, want) {
			t.Errorf("missing call %q in %s", want, calls)
		}
	}
	s := d.spec
	if s.Image != DefaultHelperImage || s.NetworkMode != "none" || !s.ReadOnlyRootfs || s.Privileged ||
		!reflect.DeepEqual(s.CapDrop, []string{"ALL"}) || !reflect.DeepEqual(s.SecurityOpt, []string{"no-new-privileges"}) ||
		len(s.Ports) != 0 || len(s.Devices) != 0 || s.MemoryBytes == 0 {
		t.Fatalf("helper is not confined: %+v", s)
	}
	if len(s.Mounts) != 2 || s.Mounts[0] != (agentproto.MountSpec{Type: "volume", Source: "app_data", Target: "/from", ReadOnly: true}) ||
		s.Mounts[1] != (agentproto.MountSpec{Type: "volume", Source: "app_data.snapshot", Target: "/to"}) {
		t.Fatalf("mounts %+v", s.Mounts)
	}
	if s.Cmd[2] != copyScript || d.labels[LabelHelper] != helperVolumeCopy || d.labels[LabelStack] != "" {
		t.Fatalf("command or labels: %v %v", s.Cmd, d.labels)
	}
}

func TestVolumeCopyRejects(t *testing.T) {
	vols := []agentproto.VolumeSummary{stackVol("app_data", "app"), stackVol("other_data", "other"),
		{Name: "unmanaged", Labels: map[string]string{}}}
	cases := map[string]struct {
		params string
		want   error
	}{
		"same volume":        {`{"source":"app_data","target":"app_data","stack":"app"}`, nil},
		"bad name":           {`{"source":"../etc","target":"x","stack":"app"}`, nil},
		"bad stack":          {`{"source":"app_data","target":"x","stack":"App"}`, nil},
		"other stack source": {`{"source":"other_data","target":"app_copy","stack":"app"}`, nil},
		"other stack target": {`{"source":"app_data","target":"other_data","stack":"app"}`, nil},
		"unmanaged source":   {`{"source":"unmanaged","target":"app_copy","stack":"app"}`, nil},
		"unmanaged target":   {`{"source":"app_data","target":"unmanaged","stack":"app"}`, nil},
		"missing source":     {`{"source":"app_gone","target":"app_copy","stack":"app"}`, docker.ErrNotFound},
		"extra field":        {`{"source":"app_data","target":"app_copy","stack":"app","image":"evil"}`, nil},
	}
	for name, c := range cases {
		d := &copyDocker{fakeDocker: &fakeDocker{t: t}, vols: vols}
		_, err := runCopy(t, d, c.params)
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		var ip *errInvalidParams
		if c.want != nil && !errors.Is(err, c.want) || c.want == nil && !errors.As(err, &ip) {
			t.Errorf("%s: got %v", name, err)
		}
		for _, call := range d.callList() {
			if strings.HasPrefix(call, "create") || strings.HasPrefix(call, "volume ") {
				t.Errorf("%s: docker modified (%s)", name, call)
			}
		}
	}
}
