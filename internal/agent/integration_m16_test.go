//go:build integration

package agent

import (
	"archive/tar"
	"bytes"
	"context"
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
	"github.com/devthoko/KERNHAVEN/internal/core/backup"
)

// AT-F14-03/05 on a real Docker Engine: a volume goes through export,
// encryption into a repository, decryption and import into an empty volume
// with contents, owners, modes, links and dot files intact.
func TestM16VolumeExportImport(t *testing.T) {
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
	do := func(op string, params, out any) error {
		return cl.Do(ctx, agentclient.Call{Op: op, Params: params, Actor: "it", RequestID: "it"}, out)
	}

	s := suffix()
	st, other := "khit-"+s, "khot-"+s
	vol, vol2, foreign := st+"_data", st+"_copy", other+"_data"
	t.Cleanup(func() {
		for _, c := range []string{st + "-w", st + "-r", archiveHelperName(helperVolumeExport, vol), archiveHelperName(helperVolumeImport, vol2), archiveHelperName("volume-clear", vol2)} {
			raw(t, sock, "DELETE", "/v1.44/containers/"+c+"?force=1", "")
		}
		for _, v := range []string{vol, vol2, foreign} {
			raw(t, sock, "DELETE", "/v1.44/volumes/"+v, "")
		}
	})
	if err := do(agentproto.OpImagesPull, agentproto.ImageRef{Reference: testImage}, nil); err != nil {
		t.Fatal(err)
	}
	for _, v := range []struct{ name, stack string }{{vol, st}, {vol2, st}, {foreign, other}} {
		if err := do(agentproto.OpVolumesCreate, agentproto.VolumeCreate{Name: v.name, Stack: &agentproto.StackRef{Name: v.stack}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	run := func(name, volume, script string) string {
		t.Helper()
		_ = do(agentproto.OpContainersRemove, agentproto.RemoveContainer{ID: name, Force: true}, nil)
		spec := agentproto.ContainerSpec{Name: name, Image: testImage, User: "0", MemoryBytes: 64 << 20, Cmd: []string{"sh", "-c", script},
			Mounts: []agentproto.MountSpec{{Type: "volume", Source: volume, Target: "/data"}}}
		if err := do(agentproto.OpContainersCreate, agentproto.CreateContainer{Spec: spec, Start: true}, nil); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		waitExit(t, func(op string, p, o any) error { return do(op, p, o) }, name)
		var logs agentproto.Logs
		if err := do(agentproto.OpContainersLogs, agentproto.LogsRequest{ID: name, Tail: 500}, &logs); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, l := range logs.Lines {
			out = append(out, l.Text)
		}
		return strings.Join(out, "\n")
	}
	run(st+"-w", vol, `set -e; cd /data; chown 999:999 .; chmod 750 .; echo secret > .env; chmod 600 .env; chown 1000:1000 .env
		mkdir -p db/empty; dd if=/dev/urandom of=db/blob bs=1k count=3000 2>/dev/null; chown -R 999:999 db; chmod 700 db
		ln -s db/blob link; ln db/blob hard; mkfifo pipe; touch -d '2020-01-02 03:04:05' .env`)
	// The comparison lists owner, mode, type, size, content hash and link
	// target of everything in the volume.
	const inventory = `cd /data && find . | sort | while read f; do s=$(stat -c '%u:%g %a %F %s' "$f"); h=""; [ -f "$f" ] && [ ! -L "$f" ] && h=$(sha256sum "$f" | cut -c1-16); l=""; [ -L "$f" ] && l=$(readlink "$f"); echo "$f $s $h $l"; done; stat -c '%Y' .env`
	before := run(st+"-r", vol, inventory)

	// Export, encrypt, store.
	repoDir := t.TempDir()
	tg, err := backup.OpenLocal(backup.LocalConfig{Path: repoDir}, []string{repoDir})
	if err != nil {
		t.Fatal(err)
	}
	repo, err := backup.InitRepo(ctx, tg, "integration test passphrase", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	snap := backup.NewSnapshotID(time.Now())
	stream, err := cl.DoStream(ctx, agentclient.Call{Op: agentproto.OpVolumesExport, Params: agentproto.VolumeArchive{Stack: st, Volume: vol}, Actor: "it", RequestID: "it"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e, err := repo.WriteObject(ctx, snap, backup.ObjectEntry{File: 0, Kind: backup.KindVolume, Stack: st, Volume: vol}, stream.Body)
	stream.Body.Close()
	if err != nil || e.Size < 3000*1024 {
		t.Fatalf("export: %+v %v", e, err)
	}
	// Import into the other volume, which has old content to be replaced.
	run(st+"-w", vol2, `touch /data/old /data/.old`)
	rc, err := repo.OpenObject(ctx, snap, e)
	if err != nil {
		t.Fatal(err)
	}
	var res agentproto.VolumeImportResult
	if err := cl.DoStreamJSON(ctx, agentclient.Call{Op: agentproto.OpVolumesImport, Params: agentproto.VolumeArchive{Stack: st, Volume: vol2}, Actor: "it", RequestID: "it"}, rc, &res); err != nil {
		t.Fatal(err)
	}
	rc.Close()
	after := run(st+"-r", vol2, inventory)
	if before != after || res.Entries < 8 {
		t.Fatalf("contents differ after the round trip (%d entries)\nbefore:\n%s\nafter:\n%s", res.Entries, before, after)
	}
	t.Logf("round trip of %d entries, %d bytes:\n%s", res.Entries, res.Bytes, after)

	// Refusals: another stack's volume, archives with entries outside the volume.
	if err := cl.DoStreamJSON(ctx, agentclient.Call{Op: agentproto.OpVolumesExport, Params: agentproto.VolumeArchive{Stack: st, Volume: foreign}, Actor: "it", RequestID: "it"}, nil, nil); code(err) != agentproto.CodeInvalidParams {
		t.Fatalf("export of another stack's volume: %v", err)
	}
	var evil bytes.Buffer
	tw := tar.NewWriter(&evil)
	_ = tw.WriteHeader(&tar.Header{Name: "data/", Typeflag: tar.TypeDir, Mode: 0o755})
	_ = tw.WriteHeader(&tar.Header{Name: "data/../../etc/evil", Typeflag: tar.TypeReg, Mode: 0o644})
	_ = tw.Close()
	if err := cl.DoStreamJSON(ctx, agentclient.Call{Op: agentproto.OpVolumesImport, Params: agentproto.VolumeArchive{Stack: st, Volume: vol2}, Actor: "it", RequestID: "it"}, &evil, nil); code(err) != agentproto.CodeInvalidParams {
		t.Fatalf("import of an escaping archive: %v", err)
	}
	if err := cl.DoStreamJSON(ctx, agentclient.Call{Op: agentproto.OpVolumesImport, Params: agentproto.VolumeArchive{Stack: other, Volume: vol2}, Actor: "it", RequestID: "it"}, bytes.NewReader(nil), nil); code(err) != agentproto.CodeInvalidParams {
		t.Fatalf("import across stacks: %v", err)
	}
}
