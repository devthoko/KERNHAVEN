package docker

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Create creates a container from a policy-checked spec. labels are added to
// the spec's labels (Kernhaven's reserved labels).
func (c *Client) Create(ctx context.Context, s agentproto.ContainerSpec, labels map[string]string) (agentproto.CreateResult, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return agentproto.CreateResult{}, err
	}
	env := make([]string, 0, len(s.Env))
	for _, e := range s.Env {
		env = append(env, e.Name+"="+e.Value)
	}
	all := map[string]string{}
	for k, v := range s.Labels {
		all[k] = v
	}
	for k, v := range labels {
		all[k] = v
	}
	exposed := map[string]struct{}{}
	bindings := map[string][]map[string]string{}
	for _, pb := range s.Ports {
		proto := pb.Protocol
		if proto == "" {
			proto = "tcp"
		}
		key := strconv.Itoa(pb.ContainerPort) + "/" + proto
		exposed[key] = struct{}{}
		hp := ""
		if pb.HostPort > 0 {
			hp = strconv.Itoa(pb.HostPort)
		}
		bindings[key] = append(bindings[key], map[string]string{"HostIp": pb.HostIP, "HostPort": hp})
	}
	mounts := make([]map[string]any, 0, len(s.Mounts))
	for _, m := range s.Mounts {
		mm := map[string]any{"Type": m.Type, "Target": m.Target, "ReadOnly": m.ReadOnly}
		if m.Type != "tmpfs" {
			mm["Source"] = m.Source
		}
		mounts = append(mounts, mm)
	}
	devices := make([]map[string]string, 0, len(s.Devices))
	for _, d := range s.Devices {
		devices = append(devices, map[string]string{"PathOnHost": d, "PathInContainer": d, "CgroupPermissions": "rwm"})
	}
	networkMode := s.NetworkMode
	if networkMode == "" {
		networkMode = "bridge"
	}
	restart := s.RestartPolicy
	if restart == "" {
		restart = "no"
	}
	body := map[string]any{
		"Image": s.Image, "Cmd": nilIfEmpty(s.Cmd), "Entrypoint": nilIfEmpty(s.Entrypoint), "Env": env,
		"User": s.User, "WorkingDir": s.WorkingDir, "Labels": all, "ExposedPorts": exposed,
		"HostConfig": map[string]any{
			"Privileged": s.Privileged, "NetworkMode": networkMode, "RestartPolicy": map[string]string{"Name": restart},
			"PortBindings": bindings, "Mounts": mounts, "CapAdd": s.CapAdd, "CapDrop": s.CapDrop,
			"PidMode": s.PidMode, "IpcMode": s.IpcMode, "UTSMode": s.UTSMode, "Devices": devices,
			"SecurityOpt": s.SecurityOpt, "ReadonlyRootfs": s.ReadOnlyRootfs, "Memory": s.MemoryBytes, "NanoCpus": s.NanoCPUs,
		},
	}
	if h := s.Healthcheck; h != nil {
		body["Healthcheck"] = map[string]any{
			"Test": h.Test, "Interval": h.IntervalMS * 1e6, "Timeout": h.TimeoutMS * 1e6,
			"StartPeriod": h.StartPeriodMS * 1e6, "Retries": h.Retries,
		}
	}
	var out struct {
		ID       string   `json:"Id"`
		Warnings []string `json:"Warnings"`
	}
	if _, err := c.doBody(ctx, http.MethodPost, p+"/containers/create", url.Values{"name": {s.Name}}, 0, body, &out); err != nil {
		return agentproto.CreateResult{}, err
	}
	if out.Warnings == nil {
		out.Warnings = []string{}
	}
	return agentproto.CreateResult{ID: out.ID, Warnings: out.Warnings}, nil
}

func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Remove removes a container.
func (c *Client) Remove(ctx context.Context, ref string, force, volumes bool) error {
	p, err := c.prefix(ctx)
	if err != nil {
		return err
	}
	q := url.Values{"force": {strconv.FormatBool(force)}, "v": {strconv.FormatBool(volumes)}}
	_, err = c.do(ctx, http.MethodDelete, p+"/containers/"+url.PathEscape(ref), q, 0, nil)
	return err
}

// Pause pauses a container.
func (c *Client) Pause(ctx context.Context, ref string) (bool, error) {
	return c.action(ctx, ref, "pause", nil, 0)
}

// Unpause resumes a paused container.
func (c *Client) Unpause(ctx context.Context, ref string) (bool, error) {
	return c.action(ctx, ref, "unpause", nil, 0)
}

// MaxLogBytes caps the log text returned per request.
const MaxLogBytes = 2 << 20

// Logs returns demultiplexed log lines.
func (c *Client) Logs(ctx context.Context, r agentproto.LogsRequest) (agentproto.Logs, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return agentproto.Logs{}, err
	}
	var meta struct {
		Config struct {
			Tty bool `json:"Tty"`
		} `json:"Config"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(r.ID)+"/json", nil, 0, &meta); err != nil {
		return agentproto.Logs{}, err
	}
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "tail": {strconv.Itoa(r.Tail)}, "timestamps": {strconv.FormatBool(r.Timestamps)}}
	if r.Since > 0 {
		q.Set("since", strconv.FormatInt(r.Since, 10))
	}
	if r.Until > 0 {
		q.Set("until", strconv.FormatInt(r.Until, 10))
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(r.ID)+"/logs", q, nil)
	if err != nil {
		return agentproto.Logs{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return agentproto.Logs{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, err := c.decode(resp, nil)
		return agentproto.Logs{}, err
	}
	return readLogs(resp.Body, meta.Config.Tty)
}

// readLogs parses Docker's log stream: raw for TTY containers, otherwise
// frames of [stream, 0, 0, 0, size uint32 BE] + payload.
func readLogs(r io.Reader, tty bool) (agentproto.Logs, error) {
	out := agentproto.Logs{Lines: []agentproto.LogLine{}}
	total := 0
	add := func(stream, chunk string) bool {
		for _, line := range strings.SplitAfter(chunk, "\n") {
			if line == "" {
				continue
			}
			if total+len(line) > MaxLogBytes {
				out.Truncated = true
				return false
			}
			total += len(line)
			text := strings.TrimRight(line, "\r\n")
			if !utf8.ValidString(text) {
				text = strings.ToValidUTF8(text, "�")
			}
			out.Lines = append(out.Lines, agentproto.LogLine{Stream: stream, Text: text})
		}
		return true
	}
	if tty {
		sc := bufio.NewScanner(io.LimitReader(r, MaxLogBytes+1))
		sc.Buffer(make([]byte, 64<<10), MaxLogBytes+1)
		for sc.Scan() {
			if !add("stdout", sc.Text()+"\n") {
				break
			}
		}
		return out, nil
	}
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return out, nil
			}
			return out, fmt.Errorf("%w: reading logs: %v", ErrUnavailable, err)
		}
		size := binary.BigEndian.Uint32(hdr[4:])
		if size > MaxLogBytes {
			out.Truncated = true
			return out, nil
		}
		buf := make([]byte, size)
		if _, err := io.ReadFull(r, buf); err != nil {
			return out, nil
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		if !add(stream, string(buf)) {
			return out, nil
		}
	}
}

// ListImages lists images with the number of containers using each.
func (c *Client) ListImages(ctx context.Context) ([]agentproto.ImageSummary, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID          string   `json:"Id"`
		RepoTags    []string `json:"RepoTags"`
		RepoDigests []string `json:"RepoDigests"`
		Size        int64    `json:"Size"`
		Created     int64    `json:"Created"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/images/json", nil, 0, &raw); err != nil {
		return nil, err
	}
	var containers []struct {
		ImageID string `json:"ImageID"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/containers/json", url.Values{"all": {"1"}}, 0, &containers); err != nil {
		return nil, err
	}
	uses := map[string]int{}
	for _, ct := range containers {
		uses[ct.ImageID]++
	}
	out := make([]agentproto.ImageSummary, 0, len(raw))
	for _, i := range raw {
		out = append(out, agentproto.ImageSummary{ID: i.ID, RepoTags: orEmpty(i.RepoTags), RepoDigests: orEmpty(i.RepoDigests),
			Size: i.Size, Created: i.Created, Containers: uses[i.ID]})
	}
	return out, nil
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// PullTimeout bounds an image pull.
const PullTimeout = 5 * time.Minute

// Pull pulls ref (public registries; no credentials) and returns the
// resolved digest.
func (c *Client) Pull(ctx context.Context, ref string) (agentproto.PullResult, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return agentproto.PullResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, PullTimeout)
	defer cancel()
	req, err := c.newRequest(ctx, http.MethodPost, p+"/images/create", url.Values{"fromImage": {ref}}, nil)
	if err != nil {
		return agentproto.PullResult{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return agentproto.PullResult{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, err := c.decode(resp, nil)
		return agentproto.PullResult{}, err
	}
	// The body is a stream of progress messages; failures arrive in-band.
	dec := json.NewDecoder(io.LimitReader(resp.Body, 64<<20))
	for {
		var msg struct {
			Error string `json:"error"`
		}
		if err := dec.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return agentproto.PullResult{}, fmt.Errorf("%w: reading pull progress: %v", ErrUnavailable, err)
		}
		if msg.Error != "" {
			if strings.Contains(msg.Error, "not found") || strings.Contains(msg.Error, "manifest unknown") || strings.Contains(msg.Error, "does not exist") {
				return agentproto.PullResult{}, fmt.Errorf("%w: %s", ErrNotFound, msg.Error)
			}
			return agentproto.PullResult{}, fmt.Errorf("%w: %s", ErrInvalid, msg.Error)
		}
	}
	var img struct {
		ID          string   `json:"Id"`
		RepoDigests []string `json:"RepoDigests"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/images/"+url.PathEscape(ref)+"/json", nil, 0, &img); err != nil {
		return agentproto.PullResult{}, err
	}
	digest := ""
	repo := ref
	if i := strings.LastIndex(repo, "@"); i >= 0 {
		repo = repo[:i]
	}
	if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
		repo = repo[:i]
	}
	for _, d := range img.RepoDigests {
		if strings.HasPrefix(d, repo+"@") || strings.HasSuffix(strings.SplitN(d, "@", 2)[0], "/"+repo) {
			digest = d
			break
		}
	}
	if digest == "" && len(img.RepoDigests) > 0 {
		digest = img.RepoDigests[0]
	}
	return agentproto.PullResult{Reference: ref, ID: img.ID, Digest: digest}, nil
}

// RemoveImage removes an image by reference or ID.
func (c *Client) RemoveImage(ctx context.Context, ref string, force bool) error {
	p, err := c.prefix(ctx)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, p+"/images/"+url.PathEscape(ref), url.Values{"force": {strconv.FormatBool(force)}}, 0, nil)
	return err
}

// PruneImages removes dangling images only.
func (c *Client) PruneImages(ctx context.Context) (agentproto.PruneResult, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return agentproto.PruneResult{}, err
	}
	var out struct {
		ImagesDeleted  []json.RawMessage `json:"ImagesDeleted"`
		SpaceReclaimed int64             `json:"SpaceReclaimed"`
	}
	q := url.Values{"filters": {`{"dangling":["true"]}`}}
	if _, err := c.do(ctx, http.MethodPost, p+"/images/prune", q, time.Minute, &out); err != nil {
		return agentproto.PruneResult{}, err
	}
	return agentproto.PruneResult{Deleted: len(out.ImagesDeleted), SpaceReclaimed: out.SpaceReclaimed}, nil
}

// ListVolumes lists volumes.
func (c *Client) ListVolumes(ctx context.Context) ([]agentproto.VolumeSummary, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Volumes []struct {
			Name       string            `json:"Name"`
			Driver     string            `json:"Driver"`
			Mountpoint string            `json:"Mountpoint"`
			CreatedAt  string            `json:"CreatedAt"`
			Labels     map[string]string `json:"Labels"`
		} `json:"Volumes"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/volumes", nil, 0, &raw); err != nil {
		return nil, err
	}
	out := make([]agentproto.VolumeSummary, 0, len(raw.Volumes))
	for _, v := range raw.Volumes {
		if v.Labels == nil {
			v.Labels = map[string]string{}
		}
		out = append(out, agentproto.VolumeSummary{Name: v.Name, Driver: v.Driver, Mountpoint: v.Mountpoint, CreatedAt: v.CreatedAt, Labels: v.Labels})
	}
	return out, nil
}

// CreateVolume creates a local volume.
func (c *Client) CreateVolume(ctx context.Context, name string, labels map[string]string) error {
	p, err := c.prefix(ctx)
	if err != nil {
		return err
	}
	_, err = c.doBody(ctx, http.MethodPost, p+"/volumes/create", nil, 0, map[string]any{"Name": name, "Driver": "local", "Labels": labels}, nil)
	return err
}

// RemoveVolume removes a volume; in-use volumes yield ErrConflict.
func (c *Client) RemoveVolume(ctx context.Context, name string) error {
	p, err := c.prefix(ctx)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, p+"/volumes/"+url.PathEscape(name), nil, 0, nil)
	return err
}

// BuiltInNetworks cannot be removed.
var BuiltInNetworks = map[string]bool{"bridge": true, "host": true, "none": true}

// ListNetworks lists networks with the number of attached containers.
func (c *Client) ListNetworks(ctx context.Context) ([]agentproto.NetworkSummary, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID       string            `json:"Id"`
		Name     string            `json:"Name"`
		Driver   string            `json:"Driver"`
		Scope    string            `json:"Scope"`
		Internal bool              `json:"Internal"`
		Labels   map[string]string `json:"Labels"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/networks", nil, 0, &raw); err != nil {
		return nil, err
	}
	var containers []struct {
		NetworkSettings struct {
			Networks map[string]struct {
				NetworkID string `json:"NetworkID"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/containers/json", url.Values{"all": {"1"}}, 0, &containers); err != nil {
		return nil, err
	}
	uses := map[string]int{}
	for _, ct := range containers {
		for _, n := range ct.NetworkSettings.Networks {
			uses[n.NetworkID]++
		}
	}
	out := make([]agentproto.NetworkSummary, 0, len(raw))
	for _, n := range raw {
		if n.Labels == nil {
			n.Labels = map[string]string{}
		}
		out = append(out, agentproto.NetworkSummary{ID: n.ID, Name: n.Name, Driver: n.Driver, Scope: n.Scope, Internal: n.Internal,
			Containers: uses[n.ID], Labels: n.Labels, BuiltIn: BuiltInNetworks[n.Name]})
	}
	return out, nil
}

// CreateNetwork creates a bridge network.
func (c *Client) CreateNetwork(ctx context.Context, name string, internal bool, labels map[string]string) (string, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return "", err
	}
	var out struct {
		ID string `json:"Id"`
	}
	_, err = c.doBody(ctx, http.MethodPost, p+"/networks/create", nil, 0,
		map[string]any{"Name": name, "Driver": "bridge", "Internal": internal, "Labels": labels}, &out)
	return out.ID, err
}

// RemoveNetwork removes a network; networks with containers yield ErrConflict.
func (c *Client) RemoveNetwork(ctx context.Context, ref string) error {
	p, err := c.prefix(ctx)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, p+"/networks/"+url.PathEscape(ref), nil, 0, nil)
	return err
}
