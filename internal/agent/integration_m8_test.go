//go:build integration

package agent

import (
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// AT-F05-02: snapshot a volume, change it, restore it — on a real Docker Engine.
func TestM8VolumeCopyRoundTrip(t *testing.T) {
	sock, do := stack(t)
	s := suffix()
	st := "khit-" + s
	vol, snap := st+"_data", st+"_data.snapshot"
	writer, reader := st+"-writer", st+"-reader"
	t.Cleanup(func() {
		for _, c := range []string{writer, reader, HelperName(snap), HelperName(vol)} {
			raw(t, sock, "DELETE", "/v1.44/containers/"+c+"?force=1", "")
		}
		raw(t, sock, "DELETE", "/v1.44/volumes/"+vol, "")
		raw(t, sock, "DELETE", "/v1.44/volumes/"+snap, "")
	})
	if err := do(agentproto.OpImagesPull, agentproto.ImageRef{Reference: testImage}, nil); err != nil {
		t.Fatal(err)
	}
	if err := do(agentproto.OpVolumesCreate, agentproto.VolumeCreate{Name: vol, Stack: &agentproto.StackRef{Name: st}}, nil); err != nil {
		t.Fatal(err)
	}
	run := func(name, script string) []string {
		t.Helper()
		_ = do(agentproto.OpContainersRemove, agentproto.RemoveContainer{ID: name, Force: true}, nil)
		spec := agentproto.ContainerSpec{Name: name, Image: testImage, User: "0", MemoryBytes: 64 << 20, Cmd: []string{"sh", "-c", script},
			Mounts: []agentproto.MountSpec{{Type: "volume", Source: vol, Target: "/data"}}}
		if err := do(agentproto.OpContainersCreate, agentproto.CreateContainer{Spec: spec, Start: true}, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		waitExit(t, do, name)
		var logs agentproto.Logs
		if err := do(agentproto.OpContainersLogs, agentproto.LogsRequest{ID: name, Tail: 100}, &logs); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, l := range logs.Lines {
			out = append(out, l.Text)
		}
		return out
	}
	copyVol := func(src, dst string) {
		t.Helper()
		var res agentproto.VolumeCopyResult
		if err := do(agentproto.OpVolumesCopy, agentproto.VolumeCopy{Source: src, Target: dst, Stack: st}, &res); err != nil {
			t.Fatalf("copy %s → %s: %v", src, dst, err)
		}
		if code := waitExit(t, do, res.Helper); code != 0 {
			t.Fatalf("copy %s → %s exited with %d", src, dst, code)
		}
		if err := do(agentproto.OpContainersRemove, agentproto.RemoveContainer{ID: res.Helper, Force: true}, nil); err != nil {
			t.Fatal(err)
		}
	}

	run(writer, "echo v1 > /data/version; echo hidden > /data/.config; mkdir /data/owned; chown 65534:65534 /data/owned; chmod 750 /data/owned")
	copyVol(vol, snap)
	run(writer, "echo v2 > /data/version; rm /data/.config; echo new > /data/added")
	copyVol(snap, vol)
	got := strings.Join(run(reader, "cat /data/version; ls -A /data | tr '\\n' ' '; echo; stat -c '%u:%g %a' /data/owned"), "\n")
	want := "v1\n.config owned version \n65534:65534 750"
	if got != want {
		t.Fatalf("restored volume:\n%s\nwant:\n%s", got, want)
	}

	// A volume of another stack cannot be the target.
	other := "khit-other-" + s
	if err := do(agentproto.OpVolumesCreate, agentproto.VolumeCreate{Name: other + "_x", Stack: &agentproto.StackRef{Name: other}}, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { raw(t, sock, "DELETE", "/v1.44/volumes/"+other+"_x", "") })
	if err := do(agentproto.OpVolumesCopy, agentproto.VolumeCopy{Source: vol, Target: other + "_x", Stack: st}, nil); code(err) != agentproto.CodeInvalidParams {
		t.Fatalf("cross-stack copy: %v", err)
	}
}

func waitExit(t *testing.T, do func(op string, params, out any) error, name string) int {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for time.Now().Before(deadline) {
		var d agentproto.ContainerDetail
		if err := do(agentproto.OpContainersInspect, agentproto.ContainerRef{ID: name}, &d); err != nil {
			t.Fatalf("inspect %s: %v", name, err)
		}
		if !d.Running && (d.Status == "exited" || d.Status == "dead") {
			return d.ExitCode
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s did not exit", name)
	return -1
}
