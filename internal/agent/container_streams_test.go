package agent

import (
	"context"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

type execDocker struct {
	Docker
	Streamer
	det agentproto.ContainerDetail
	pid string
}

func (e execDocker) Inspect(context.Context, string) (agentproto.ContainerDetail, error) {
	return e.det, nil
}
func (e execDocker) PidMode(context.Context, string) (string, error) { return e.pid, nil }

// AT-F02-07: no console where a shell would reach the host.
func TestCheckExec(t *testing.T) {
	ok := agentproto.ContainerDetail{Running: true, Labels: map[string]string{LabelManaged: "true"}, Mounts: []agentproto.Mount{{Source: "/srv/data", Destination: "/data"}}}
	if err := checkExec(context.Background(), execDocker{det: ok}, execDocker{det: ok}, "c"); err != nil {
		t.Fatalf("plain managed container: %v", err)
	}
	cases := map[string]func(*agentproto.ContainerDetail, *string){
		"unmanaged":  func(d *agentproto.ContainerDetail, _ *string) { d.Labels = map[string]string{} },
		"stopped":    func(d *agentproto.ContainerDetail, _ *string) { d.Running = false },
		"privileged": func(d *agentproto.ContainerDetail, _ *string) { d.Privileged = true },
		"docker socket": func(d *agentproto.ContainerDetail, _ *string) {
			d.Mounts = []agentproto.Mount{{Source: "/run/docker.sock", Destination: "/var/run/docker.sock"}}
		},
		"rootless socket": func(d *agentproto.ContainerDetail, _ *string) {
			d.Mounts = []agentproto.Mount{{Source: "/run/user/1000/docker.sock", Destination: "/sock"}}
		},
		"host PID": func(_ *agentproto.ContainerDetail, p *string) { *p = "host" },
	}
	for name, mut := range cases {
		d, pid := ok, ""
		d.Labels = map[string]string{LabelManaged: "true"}
		mut(&d, &pid)
		e := execDocker{det: d, pid: pid}
		if err := checkExec(context.Background(), e, e, "c"); err == nil {
			t.Errorf("%s allowed", name)
		}
	}
	if len(shells) != 2 || shells["sh"][0] != "/bin/sh" || shells["bash"][0] != "/bin/bash" {
		t.Fatalf("shells %v", shells)
	}
}
