package agent

import (
	"context"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Recorded M6 methods of fakeDocker.
func (f *fakeDocker) Create(_ context.Context, s agentproto.ContainerSpec, labels map[string]string) (agentproto.CreateResult, error) {
	keys := []string{}
	for k, v := range labels {
		keys = append(keys, k+"="+v)
	}
	return agentproto.CreateResult{ID: "new123", Warnings: []string{}}, f.record("create " + s.Name + " " + strings.Join(sortStrings(keys), ","))
}
func (f *fakeDocker) Remove(_ context.Context, id string, force, volumes bool) error {
	return f.record("remove " + id)
}
func (f *fakeDocker) Logs(_ context.Context, r agentproto.LogsRequest) (agentproto.Logs, error) {
	return agentproto.Logs{Lines: []agentproto.LogLine{}}, f.record("logs " + r.ID)
}
func (f *fakeDocker) CreateNetwork(_ context.Context, name string, internal bool, labels map[string]string) (string, error) {
	return "net1", f.record("network " + name)
}
func (f *fakeDocker) RemoveNetwork(_ context.Context, ref string) error {
	return f.record("rmnetwork " + ref)
}
func (f *fakeDocker) CreateVolume(_ context.Context, name string, labels map[string]string) error {
	return f.record("volume " + name + " managed=" + labels[LabelManaged])
}
func (f *fakeDocker) Pull(_ context.Context, ref string) (agentproto.PullResult, error) {
	return agentproto.PullResult{Reference: ref}, f.record("pull " + ref)
}

func sortStrings(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}

const safeSpec = `{"name":"web","image":"nginx:1.27","user":"101","memory_bytes":268435456}`

// AT-F02-04: the agent enforces the policy even if the Core is bypassed.
func TestAgentEnforcesContainerPolicy(t *testing.T) {
	e := start(t, self())
	e.docker.setForbid(true)
	rejected := map[string]string{
		"privileged":            `{"spec":{"name":"x","image":"alpine","privileged":true}}`,
		"host network":          `{"spec":{"name":"x","image":"alpine","network_mode":"host"}}`,
		"docker socket":         `{"spec":{"name":"x","image":"alpine","mounts":[{"type":"bind","source":"/var/run/docker.sock","target":"/s"}]}}`,
		"socket with exception": `{"spec":{"name":"x","image":"alpine","mounts":[{"type":"bind","source":"/var/run/docker.sock","target":"/s"}]},"exceptions":["docker-socket"]}`,
		"etc with exception":    `{"spec":{"name":"x","image":"alpine","mounts":[{"type":"bind","source":"/etc","target":"/s"}]},"exceptions":["bind-mount","sensitive-path"]}`,
		"stale exception":       `{"spec":{"name":"x","image":"alpine"},"exceptions":["privileged"]}`,
	}
	for name, body := range rejected {
		if r := e.call("containers.create", body, nil); r.status != 422 || r.code != agentproto.CodePolicyViolation {
			t.Errorf("%s: %d %s", name, r.status, r.code)
		}
	}
	invalidSpecs := map[string]string{
		"reserved label": `{"spec":{"name":"x","image":"alpine","labels":{"io.kernhaven.managed":"false"}}}`,
		"bad image":      `{"spec":{"name":"x","image":"Not An Image"}}`,
		"unknown field":  `{"spec":{"name":"x","image":"alpine","cgroupns":"host"}}`,
	}
	for name, body := range invalidSpecs {
		if r := e.call("containers.create", body, nil); r.status != 400 || r.code != agentproto.CodeInvalidParams {
			t.Errorf("%s: %d %s", name, r.status, r.code)
		}
	}
	if !strings.Contains(e.logs.String(), "policy rejected container") {
		t.Fatal("policy rejections are not logged")
	}

	// Allowed: safe spec, and a privileged spec with an exception.
	e.docker.setForbid(false)
	if r := e.call("containers.create", `{"spec":`+safeSpec+`}`, nil); r.status != 200 || !strings.Contains(string(r.result), "image is not pinned") {
		t.Fatalf("safe create: %+v %s", r, r.result)
	}
	if r := e.call("containers.create", `{"spec":{"name":"vpn","image":"alpine","cap_add":["NET_ADMIN"]},"exceptions":["capability"]}`, nil); r.status != 200 {
		t.Fatalf("create with exception: %+v", r)
	}
	calls := strings.Join(e.docker.callList(), "\n")
	if !strings.Contains(calls, "create web io.kernhaven.created_by=owner,io.kernhaven.managed=true") {
		t.Errorf("labels not set: %s", calls)
	}
	if !strings.Contains(calls, "create vpn io.kernhaven.created_by=owner,io.kernhaven.managed=true,io.kernhaven.policy.exceptions=capability") {
		t.Errorf("exception label not set: %s", calls)
	}
}

func TestManageParamValidation(t *testing.T) {
	e := start(t, self())
	e.docker.setForbid(true)
	cases := map[string]struct{ op, params string }{
		"logs tail":          {"containers.logs", `{"id":"web","tail":10001}`},
		"logs range":         {"containers.logs", `{"id":"web","since":100,"until":50}`},
		"pull bad ref":       {"images.pull", `{"reference":"http://evil/x"}`},
		"remove bad ref":     {"images.remove", `{"reference":"../x"}`},
		"builtin network":    {"networks.create", `{"name":"host"}`},
		"remove bridge":      {"networks.remove", `{"name":"bridge"}`},
		"volume name":        {"volumes.create", `{"name":"../x"}`},
		"volume label":       {"volumes.create", `{"name":"data","labels":{"io.kernhaven.managed":"no"}}`},
		"network label":      {"networks.create", `{"name":"apps","labels":{"io.kernhaven.x":"1"}}`},
		"remove container":   {"containers.remove", `{"id":"a/b"}`},
		"pause unknown flag": {"containers.pause", `{"id":"web","force":true}`},
	}
	for name, tc := range cases {
		if r := e.call(tc.op, tc.params, nil); r.status != 400 || r.code != agentproto.CodeInvalidParams {
			t.Errorf("%s: %d %s", name, r.status, r.code)
		}
	}
	e.docker.setForbid(false)
	e.call("volumes.create", `{"name":"data"}`, nil)
	e.call("networks.create", `{"name":"apps","internal":true}`, nil)
	e.call("images.pull", `{"reference":"alpine:3"}`, nil)
	e.call("containers.logs", `{"id":"web"}`, nil)
	got := strings.Join(e.docker.callList(), "|")
	for _, want := range []string{"volume data managed=true", "network apps", "pull alpine:3", "logs web"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing call %q in %s", want, got)
		}
	}
}
