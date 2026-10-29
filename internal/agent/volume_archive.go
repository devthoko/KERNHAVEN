package agent

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// Archiver is the part of the Docker client that reads and writes volume
// contents as tar streams (M16, ADR-0030).
type Archiver interface {
	ArchiveGet(ctx context.Context, ref, path string) (io.ReadCloser, error)
	ArchivePut(ctx context.Context, ref, path string, r io.Reader) error
}

const (
	helperVolumeExport = "volume-export"
	helperVolumeImport = "volume-import"
	// clearScript empties /data including dot files; it is fixed here.
	clearScript  = `set -e; cd /data; rm -rf -- * .[!.]* ..?*`
	clearTimeout = 30 * time.Minute
)

func archiveHelperName(kind, volume string) string {
	sum := sha256.Sum256([]byte(volume))
	return "kh-" + kind + "-" + hex.EncodeToString(sum[:6])
}

// stackVolume returns the volume if it belongs to the stack and is not a
// snapshot copy, so a compromised Core cannot read or overwrite volumes it
// does not manage.
func stackVolume(ctx context.Context, d Docker, p agentproto.VolumeArchive) error {
	if !policy.ValidName(p.Volume) || !stackNameRe.MatchString(p.Stack) {
		return invalid("stack and volume must be valid names")
	}
	vols, err := d.ListVolumes(ctx)
	if err != nil {
		return err
	}
	for _, v := range vols {
		if v.Name == p.Volume {
			if v.Labels[LabelStack] != p.Stack || v.Labels[LabelSnapshotOf] != "" {
				return invalid("volume %s does not belong to stack %s", p.Volume, p.Stack)
			}
			return nil
		}
	}
	return fmt.Errorf("volume %s: %w", p.Volume, docker.ErrNotFound)
}

func archiveHelperSpec(image, name, volume, kind string) agentproto.ContainerSpec {
	s := agentproto.ContainerSpec{
		Name: name, Image: image, Cmd: []string{"true"},
		User: "0", NetworkMode: "none", ReadOnlyRootfs: true,
		CapDrop: []string{"ALL"}, SecurityOpt: []string{"no-new-privileges"}, MemoryBytes: 64 << 20,
		Mounts: []agentproto.MountSpec{{Type: "volume", Source: volume, Target: "/data", ReadOnly: kind == helperVolumeExport}},
	}
	switch kind {
	case helperVolumeImport:
		// Docker refuses to extract into a container with a read-only root
		// file system, even below a volume. The helper never starts.
		s.ReadOnlyRootfs = false
	case "volume-clear":
		s.Cmd = []string{"sh", "-c", clearScript}
		s.CapAdd = []string{"DAC_OVERRIDE", "FOWNER"}
	}
	return s
}

// createHelper replaces any leftover helper of the same name and creates a
// new one, pulling the helper image once if needed.
func createHelper(ctx context.Context, d Docker, image, name, volume, kind string) error {
	if err := d.Remove(ctx, name, true, false); err != nil && !errors.Is(err, docker.ErrNotFound) {
		return err
	}
	spec := archiveHelperSpec(image, name, volume, kind)
	labels := managedLabels(ctx, map[string]string{LabelHelper: kind})
	_, err := d.Create(ctx, spec, labels)
	if errors.Is(err, docker.ErrNotFound) {
		if _, err := d.Pull(ctx, image); err != nil {
			return err
		}
		_, err = d.Create(ctx, spec, labels)
	}
	return err
}

func removeHelper(ctx context.Context, d Docker, name string) {
	_ = d.Remove(context.WithoutCancel(ctx), name, true, false)
}

// filterTar copies a volume archive, accepting only entries below data/:
// regular files, directories, symbolic links, hard links to earlier files
// and FIFOs. Device files, paths through earlier symbolic links, ".." and
// absolute names are refused. Extended attributes are not carried over.
func filterTar(r io.Reader, w io.Writer) (int, int64, error) {
	tr := tar.NewReader(r)
	tw := tar.NewWriter(w)
	files := map[string]bool{}
	links := map[string]bool{}
	var entries int
	var total int64
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return entries, total, invalid("invalid archive: %v", err)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if name == "" || path.Clean(name) != name || path.IsAbs(name) || (name != "data" && !strings.HasPrefix(name, "data/")) {
			return entries, total, invalid("archive entry %q is outside the volume", h.Name)
		}
		for _, part := range strings.Split(name, "/") {
			if part == ".." {
				return entries, total, invalid("archive entry %q is outside the volume", h.Name)
			}
		}
		for dir := path.Dir(name); dir != "." && dir != "/"; dir = path.Dir(dir) {
			if links[dir] {
				return entries, total, invalid("archive entry %q is below a symbolic link", h.Name)
			}
		}
		if name == "data" && h.Typeflag != tar.TypeDir {
			return entries, total, invalid("the volume root must be a directory")
		}
		out := &tar.Header{Name: name, Mode: h.Mode & 0o7777, Uid: h.Uid, Gid: h.Gid, Uname: h.Uname, Gname: h.Gname, ModTime: h.ModTime, Typeflag: h.Typeflag, Format: tar.FormatPAX}
		switch h.Typeflag {
		case tar.TypeReg:
			out.Size = h.Size
			files[name] = true
		case tar.TypeDir:
			out.Name += "/"
		case tar.TypeSymlink:
			if h.Linkname == "" || strings.ContainsRune(h.Linkname, 0) {
				return entries, total, invalid("archive entry %q has an invalid link", h.Name)
			}
			out.Linkname = h.Linkname
			links[name] = true
		case tar.TypeLink:
			if !files[h.Linkname] {
				return entries, total, invalid("hard link %q does not refer to an earlier file", h.Name)
			}
			out.Linkname = h.Linkname
		case tar.TypeFifo:
		default:
			return entries, total, invalid("archive entry %q has an unsupported type", h.Name)
		}
		if err := tw.WriteHeader(out); err != nil {
			return entries, total, err
		}
		if out.Typeflag == tar.TypeReg {
			n, err := io.Copy(tw, tr)
			total += n
			if err != nil {
				return entries, total, err
			}
		}
		entries++
	}
	if entries == 0 {
		return 0, 0, invalid("the archive is empty")
	}
	return entries, total, tw.Close()
}

func waitExited(ctx context.Context, d Docker, name string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		det, err := d.Inspect(ctx, name)
		if err != nil {
			return err
		}
		if !det.Running && (det.Status == "exited" || det.Status == "dead") {
			if det.ExitCode != 0 {
				return fmt.Errorf("helper %s failed with exit code %d", name, det.ExitCode)
			}
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("helper %s did not finish within %s", name, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
}

// volumeStreamOperations are the Docker agent's stream operations (M16).
func volumeStreamOperations(d Docker, o Options) map[string]streamHandler {
	a, ok := d.(Archiver)
	if !ok {
		return map[string]streamHandler{}
	}
	image := o.HelperImage
	if image == "" {
		image = DefaultHelperImage
	}
	return map[string]streamHandler{
		agentproto.OpVolumesExport: func(ctx context.Context, raw json.RawMessage, _ io.Reader, w http.ResponseWriter) error {
			p, err := decode[agentproto.VolumeArchive](raw)
			if err != nil {
				return err
			}
			if err := stackVolume(ctx, d, p); err != nil {
				return err
			}
			name := archiveHelperName(helperVolumeExport, p.Volume)
			if err := createHelper(ctx, d, image, name, p.Volume, helperVolumeExport); err != nil {
				return err
			}
			defer removeHelper(ctx, d, name)
			rc, err := a.ArchiveGet(ctx, name, "/data")
			if err != nil {
				return err
			}
			defer rc.Close()
			w.Header().Set("Content-Type", "application/x-tar")
			w.WriteHeader(http.StatusOK)
			if _, _, err := filterTar(rc, w); err != nil {
				// The status is already sent: break the response so the
				// Core sees an incomplete transfer, never a short archive.
				removeHelper(ctx, d, name)
				panic(http.ErrAbortHandler)
			}
			return nil
		},
		agentproto.OpVolumesImport: func(ctx context.Context, raw json.RawMessage, body io.Reader, w http.ResponseWriter) error {
			p, err := decode[agentproto.VolumeArchive](raw)
			if err != nil {
				return err
			}
			if err := stackVolume(ctx, d, p); err != nil {
				return err
			}
			clear := archiveHelperName("volume-clear", p.Volume)
			if err := createHelper(ctx, d, image, clear, p.Volume, "volume-clear"); err != nil {
				return err
			}
			defer removeHelper(ctx, d, clear)
			if _, err := d.Start(ctx, clear); err != nil {
				return err
			}
			if err := waitExited(ctx, d, clear, clearTimeout); err != nil {
				return err
			}
			name := archiveHelperName(helperVolumeImport, p.Volume)
			if err := createHelper(ctx, d, image, name, p.Volume, helperVolumeImport); err != nil {
				return err
			}
			defer removeHelper(ctx, d, name)
			pr, pw := io.Pipe()
			type filtered struct {
				entries int
				bytes   int64
				err     error
			}
			done := make(chan filtered, 1)
			go func() {
				n, b, ferr := filterTar(body, pw)
				pw.CloseWithError(ferr)
				done <- filtered{n, b, ferr}
			}()
			err = a.ArchivePut(ctx, name, "/", pr)
			pr.CloseWithError(errors.New("import ended"))
			f := <-done
			if f.err != nil {
				return f.err // the archive was refused; Docker saw a broken stream
			}
			if err != nil {
				return fmt.Errorf("import into %s: %w", p.Volume, err)
			}
			writeJSON(w, http.StatusOK, map[string]any{"result": agentproto.VolumeImportResult{Entries: f.entries, Bytes: f.bytes}})
			return nil
		},
	}
}
