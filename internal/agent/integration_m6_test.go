//go:build integration

package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

// stack starts an agent on real Docker and returns a call helper.
func stack(t *testing.T) (string, func(op string, params, out any) error) {
	t.Helper()
	sock := dockerSocket(t)
	dir := t.TempDir()
	key, err := agentclient.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := agentproto.ReadPublicKey(filepath.Join(dir, agentclient.PublicKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	srv := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), pub, []uint32{uint32(os.Getuid())}, docker.New(sock, 30*time.Second), Options{})
	ln, err := Listen(filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	cl := agentclient.New(filepath.Join(dir, "agent.sock"), key)
	return sock, func(op string, params, out any) error {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		defer cancel()
		return cl.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: "it", RequestID: "it"}, out)
	}
}

func suffix() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func code(err error) string {
	var ae *agentclient.Error
	if errors.As(err, &ae) {
		return ae.Code
	}
	if err != nil {
		return "other: " + err.Error()
	}
	return ""
}

// AT-F02-01, -02, -03, -04, -05, -06 on a real Docker Engine.
func TestM6ContainersImagesVolumesNetworks(t *testing.T) {
	sock, do := stack(t)
	s := suffix()
	vol, network, name := "kh-it-vol-"+s, "kh-it-net-"+s, "kh-it-c-"+s
	t.Cleanup(func() {
		raw(t, sock, "DELETE", "/v1.44/containers/"+name+"?force=1", "")
		raw(t, sock, "DELETE", "/v1.44/volumes/"+vol, "")
		raw(t, sock, "DELETE", "/v1.44/networks/"+network, "")
	})

	// AT-F02-05: pull resolves a digest.
	var pulled agentproto.PullResult
	if err := do(agentproto.OpImagesPull, agentproto.ImageRef{Reference: testImage}, &pulled); err != nil {
		t.Fatalf("pull: %v", err)
	}
	if !strings.Contains(pulled.Digest, "@sha256:") {
		t.Fatalf("pull did not resolve a digest: %+v", pulled)
	}
	if err := do(agentproto.OpImagesPull, agentproto.ImageRef{Reference: "kernhaven-test/does-not-exist-" + s + ":1"}, nil); err == nil {
		t.Fatal("pulling a missing image succeeded")
	}

	// AT-F02-06: create volume and network.
	if err := do(agentproto.OpVolumesCreate, agentproto.VolumeCreate{Name: vol}, nil); err != nil {
		t.Fatalf("volume create: %v", err)
	}
	if err := do(agentproto.OpNetworksCreate, agentproto.NetworkCreate{Name: network, Internal: true}, nil); err != nil {
		t.Fatalf("network create: %v", err)
	}

	// AT-F02-04: the agent refuses a privileged container.
	err := do(agentproto.OpContainersCreate, agentproto.CreateContainer{Spec: agentproto.ContainerSpec{Name: name + "-bad", Image: testImage, Privileged: true}}, nil)
	if code(err) != agentproto.CodePolicyViolation {
		t.Fatalf("privileged create: %v", err)
	}

	// Create a safe container pinned by digest, using the volume and network.
	spec := agentproto.ContainerSpec{
		Name: name, Image: pulled.Digest, User: "65534", MemoryBytes: 64 << 20, NetworkMode: network,
		Cmd:    []string{"sh", "-c", "echo hello-out; echo hello-err >&2; sleep 300"},
		Mounts: []agentproto.MountSpec{{Type: "volume", Source: vol, Target: "/data"}},
		Labels: map[string]string{"app": "it"},
	}
	var created agentproto.CreateResult
	if err := do(agentproto.OpContainersCreate, agentproto.CreateContainer{Spec: spec, Start: true}, &created); err != nil {
		t.Fatalf("create: %v", err)
	}
	var detail agentproto.ContainerDetail
	if err := do(agentproto.OpContainersInspect, agentproto.ContainerRef{ID: name}, &detail); err != nil || !detail.Running || detail.Privileged {
		t.Fatalf("inspect: %+v %v", detail, err)
	}
	var list []agentproto.ContainerSummary
	if err := do(agentproto.OpContainersList, agentproto.ContainersList{All: true}, &list); err != nil {
		t.Fatal(err)
	}
	labelled := false
	for _, c := range list {
		if c.ID == created.ID {
			labelled = c.Labels[LabelManaged] == "true" && c.Labels[LabelCreatedBy] == "it" && c.Labels["app"] == "it"
		}
	}
	if !labelled {
		t.Fatal("created container lacks Kernhaven labels")
	}

	// AT-F02-03: logs from both streams.
	var logs agentproto.Logs
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := do(agentproto.OpContainersLogs, agentproto.LogsRequest{ID: name, Tail: 100}, &logs); err != nil {
			t.Fatalf("logs: %v", err)
		}
		if len(logs.Lines) >= 2 || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	streams := map[string]string{}
	for _, l := range logs.Lines {
		streams[l.Text] = l.Stream
	}
	if streams["hello-out"] != "stdout" || streams["hello-err"] != "stderr" {
		t.Fatalf("log lines %+v", logs.Lines)
	}
	if err := do(agentproto.OpContainersLogs, agentproto.LogsRequest{ID: name, Tail: 100, Since: time.Now().Add(time.Hour).Unix()}, &logs); err != nil || len(logs.Lines) != 0 {
		t.Fatalf("logs since future: %+v %v", logs, err)
	}

	// AT-F02-02: pause/unpause.
	var res agentproto.ActionResult
	if err := do(agentproto.OpContainersPause, agentproto.ContainerRef{ID: name}, &res); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if err := do(agentproto.OpContainersInspect, agentproto.ContainerRef{ID: name}, &detail); err != nil || detail.Status != "paused" {
		t.Fatalf("after pause: %+v %v", detail.Status, err)
	}
	if err := do(agentproto.OpContainersUnpause, agentproto.ContainerRef{ID: name}, &res); err != nil {
		t.Fatalf("unpause: %v", err)
	}

	// AT-F02-06: in-use volume, network and image cannot be removed.
	if err := do(agentproto.OpVolumesRemove, agentproto.NamedObject{Name: vol}, nil); code(err) != agentproto.CodeConflict {
		t.Fatalf("remove in-use volume: %v", err)
	}
	if err := do(agentproto.OpNetworksRemove, agentproto.NamedObject{Name: network}, nil); code(err) != agentproto.CodeConflict {
		t.Fatalf("remove in-use network: %v", err)
	}
	var images []agentproto.ImageSummary
	if err := do(agentproto.OpImagesList, nil, &images); err != nil {
		t.Fatal(err)
	}
	inUse := false
	for _, im := range images {
		if im.ID == detail.Image || (im.Containers > 0 && strings.Contains(strings.Join(im.RepoDigests, ","), strings.SplitN(pulled.Digest, "@", 2)[1])) {
			inUse = true
		}
	}
	if !inUse {
		t.Fatalf("image list does not count the container: %+v", images)
	}
	var volumes []agentproto.VolumeSummary
	var networks []agentproto.NetworkSummary
	if err := do(agentproto.OpVolumesList, nil, &volumes); err != nil {
		t.Fatal(err)
	}
	if err := do(agentproto.OpNetworksList, nil, &networks); err != nil {
		t.Fatal(err)
	}
	foundNet := false
	for _, n := range networks {
		if n.Name == network && n.Internal && n.Containers == 1 && n.Labels[LabelManaged] == "true" {
			foundNet = true
		}
	}
	if !foundNet {
		t.Fatalf("network not listed with its container: %+v", networks)
	}

	// Remove the running container (force), then volume and network go.
	if err := do(agentproto.OpContainersRemove, agentproto.RemoveContainer{ID: name}, nil); code(err) != agentproto.CodeConflict {
		t.Fatalf("remove running without force: %v", err)
	}
	if err := do(agentproto.OpContainersRemove, agentproto.RemoveContainer{ID: name, Force: true}, nil); err != nil {
		t.Fatalf("force remove: %v", err)
	}
	if err := do(agentproto.OpVolumesRemove, agentproto.NamedObject{Name: vol}, nil); err != nil {
		t.Fatalf("remove volume: %v", err)
	}
	if err := do(agentproto.OpNetworksRemove, agentproto.NamedObject{Name: network}, nil); err != nil {
		t.Fatalf("remove network: %v", err)
	}
	if err := do(agentproto.OpNetworksRemove, agentproto.NamedObject{Name: "bridge"}, nil); code(err) != agentproto.CodeInvalidParams {
		t.Fatalf("remove bridge: %v", err)
	}
	var pr agentproto.PruneResult
	if err := do(agentproto.OpImagesPrune, nil, &pr); err != nil {
		t.Fatalf("prune: %v", err)
	}
}
