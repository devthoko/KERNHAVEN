// Package docker is a minimal Docker Engine API client over a unix socket.
// It implements only what the agent's allow-listed operations need; the
// Docker SDK is not used to keep the privileged agent small (M4).
package docker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// API versions: the newest this client speaks and the oldest it accepts.
const (
	MaxAPIVersion = "1.47"
	MinAPIVersion = "1.44"
)

var (
	// ErrUnavailable means the daemon could not be reached or answered with
	// a server error.
	ErrUnavailable = errors.New("docker engine unavailable")
	// ErrNotFound means the referenced object does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means the request conflicts with the object's state.
	ErrConflict = errors.New("conflict")
	// ErrInvalid means Docker rejected the request as malformed.
	ErrInvalid = errors.New("rejected by Docker")
)

// Client talks to one Docker Engine.
type Client struct {
	http    *http.Client
	timeout time.Duration

	mu      sync.Mutex
	version string // negotiated, "" until the first successful call
}

// New returns a client for the daemon at socketPath. Each call is bounded by
// timeout (default 30 s); stop/restart add their own grace period.
func New(socketPath string, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		ResponseHeaderTimeout: 0, // bounded by per-call contexts
	}
	return &Client{http: &http.Client{Transport: tr}, timeout: timeout}
}

// apiError is Docker's error body.
type apiError struct {
	Message string `json:"message"`
}

// do sends a request and decodes a JSON response into out (if non-nil).
// Status 304 is returned as (304, nil) for start/stop semantics.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, extra time.Duration, out any) (int, error) {
	return c.doBody(ctx, method, path, query, extra, nil, out)
}

// doBody is do with an optional JSON request body.
func (c *Client) doBody(ctx context.Context, method, path string, query url.Values, extra time.Duration, in, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout+extra)
	defer cancel()
	req, err := c.newRequest(ctx, method, path, query, in)
	if err != nil {
		return 0, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	return c.decode(resp, out)
}

func (c *Client) newRequest(ctx context.Context, method, path string, query url.Values, in any) (*http.Request, error) {
	u := "http://docker" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}

// decode maps a Docker response to (status, error) and decodes JSON into out.
func (c *Client) decode(resp *http.Response, out any) (int, error) {
	body := io.LimitReader(resp.Body, 32<<20)

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return resp.StatusCode, nil
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		if out == nil {
			return resp.StatusCode, nil
		}
		if err := json.NewDecoder(body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("%w: decoding response: %v", ErrUnavailable, err)
		}
		return resp.StatusCode, nil
	}
	var ae apiError
	_ = json.NewDecoder(io.LimitReader(body, 64<<10)).Decode(&ae)
	msg := strings.TrimSpace(ae.Message)
	switch resp.StatusCode {
	case http.StatusNotFound:
		return resp.StatusCode, fmt.Errorf("%w: %s", ErrNotFound, msg)
	case http.StatusConflict:
		return resp.StatusCode, fmt.Errorf("%w: %s", ErrConflict, msg)
	case http.StatusBadRequest:
		return resp.StatusCode, fmt.Errorf("%w: %s", ErrInvalid, msg)
	case http.StatusForbidden:
		return resp.StatusCode, fmt.Errorf("%w: %s", ErrConflict, msg)
	default:
		return resp.StatusCode, fmt.Errorf("%w: HTTP %d: %s", ErrUnavailable, resp.StatusCode, msg)
	}
}

// parseVersion turns "1.47" into (1, 47).
func parseVersion(v string) (int, int, bool) {
	maj, min, ok := strings.Cut(v, ".")
	if !ok {
		return 0, 0, false
	}
	a, err1 := strconv.Atoi(maj)
	b, err2 := strconv.Atoi(min)
	return a, b, err1 == nil && err2 == nil
}

func versionLess(a, b string) bool {
	am, an, _ := parseVersion(a)
	bm, bn, _ := parseVersion(b)
	return am < bm || (am == bm && an < bn)
}

type versionResponse struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
}

// negotiate fixes the API version once per client.
func (c *Client) negotiate(ctx context.Context) (string, versionResponse, error) {
	var v versionResponse
	if _, err := c.do(ctx, http.MethodGet, "/version", nil, 0, &v); err != nil {
		return "", v, err
	}
	if _, _, ok := parseVersion(v.APIVersion); !ok {
		return "", v, fmt.Errorf("%w: daemon reported API version %q", ErrUnavailable, v.APIVersion)
	}
	if versionLess(v.APIVersion, MinAPIVersion) {
		return "", v, fmt.Errorf("%w: Docker API %s is older than the supported minimum %s", ErrUnavailable, v.APIVersion, MinAPIVersion)
	}
	ver := MaxAPIVersion
	if versionLess(v.APIVersion, MaxAPIVersion) {
		ver = v.APIVersion
	}
	c.mu.Lock()
	c.version = ver
	c.mu.Unlock()
	return ver, v, nil
}

func (c *Client) prefix(ctx context.Context) (string, error) {
	c.mu.Lock()
	v := c.version
	c.mu.Unlock()
	if v == "" {
		var err error
		if v, _, err = c.negotiate(ctx); err != nil {
			return "", err
		}
	}
	return "/v" + v, nil
}

// Info returns a summary of the daemon.
func (c *Client) Info(ctx context.Context) (agentproto.DockerInfo, error) {
	if _, err := c.do(ctx, http.MethodGet, "/_ping", nil, 0, nil); err != nil {
		return agentproto.DockerInfo{}, err
	}
	ver, v, err := c.negotiate(ctx)
	if err != nil {
		return agentproto.DockerInfo{}, err
	}
	var info struct {
		Containers        int      `json:"Containers"`
		ContainersRunning int      `json:"ContainersRunning"`
		ContainersPaused  int      `json:"ContainersPaused"`
		ContainersStopped int      `json:"ContainersStopped"`
		Images            int      `json:"Images"`
		Driver            string   `json:"Driver"`
		SecurityOptions   []string `json:"SecurityOptions"`
	}
	if _, err := c.do(ctx, http.MethodGet, "/v"+ver+"/info", nil, 0, &info); err != nil {
		return agentproto.DockerInfo{}, err
	}
	rootless := false
	for _, o := range info.SecurityOptions {
		if strings.Contains(o, "name=rootless") {
			rootless = true
		}
	}
	return agentproto.DockerInfo{
		ServerVersion: v.Version, APIVersion: v.APIVersion, NegotiatedVersion: ver,
		OS: v.Os, Arch: v.Arch, KernelVersion: v.KernelVersion, Rootless: rootless,
		StorageDriver: info.Driver, Containers: info.Containers, Running: info.ContainersRunning,
		Paused: info.ContainersPaused, Stopped: info.ContainersStopped, Images: info.Images,
	}, nil
}

// ListContainers lists running containers, or all with all=true.
func (c *Client) ListContainers(ctx context.Context, all bool) ([]agentproto.ContainerSummary, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Created int64             `json:"Created"`
		Labels  map[string]string `json:"Labels"`
		Ports   []struct {
			IP          string `json:"IP"`
			PrivatePort int    `json:"PrivatePort"`
			PublicPort  int    `json:"PublicPort"`
			Type        string `json:"Type"`
		} `json:"Ports"`
	}
	q := url.Values{}
	if all {
		q.Set("all", "1")
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/containers/json", q, 0, &raw); err != nil {
		return nil, err
	}
	out := make([]agentproto.ContainerSummary, 0, len(raw))
	for _, r := range raw {
		s := agentproto.ContainerSummary{ID: r.ID, Image: r.Image, State: r.State, Status: r.Status, Created: r.Created, Labels: r.Labels, Ports: []agentproto.Port{}}
		for _, n := range r.Names {
			s.Names = append(s.Names, strings.TrimPrefix(n, "/"))
		}
		for _, pt := range r.Ports {
			s.Ports = append(s.Ports, agentproto.Port{IP: pt.IP, PrivatePort: pt.PrivatePort, PublicPort: pt.PublicPort, Type: pt.Type})
		}
		if s.Labels == nil {
			s.Labels = map[string]string{}
		}
		out = append(out, s)
	}
	return out, nil
}

// Stats returns one-shot counters of every running container (M14). A
// container that stops in between is skipped.
func (c *Client) Stats(ctx context.Context) ([]agentproto.ContainerStats, error) {
	running, err := c.ListContainers(ctx, false)
	if err != nil {
		return nil, err
	}
	p, err := c.prefix(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]agentproto.ContainerStats, 0, len(running))
	for _, r := range running {
		var raw struct {
			CPU struct {
				Usage struct {
					Total uint64 `json:"total_usage"`
				} `json:"cpu_usage"`
				System uint64 `json:"system_cpu_usage"`
				Online int    `json:"online_cpus"`
			} `json:"cpu_stats"`
			Memory struct {
				Usage uint64            `json:"usage"`
				Limit uint64            `json:"limit"`
				Stats map[string]uint64 `json:"stats"`
			} `json:"memory_stats"`
			Networks map[string]struct {
				Rx uint64 `json:"rx_bytes"`
				Tx uint64 `json:"tx_bytes"`
			} `json:"networks"`
			Blkio struct {
				IO []struct {
					Op    string `json:"op"`
					Value uint64 `json:"value"`
				} `json:"io_service_bytes_recursive"`
			} `json:"blkio_stats"`
		}
		q := url.Values{"stream": {"false"}, "one-shot": {"true"}}
		status, err := c.do(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(r.ID)+"/stats", q, 0, &raw)
		if status == http.StatusNotFound || errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		st := agentproto.ContainerStats{ID: r.ID, CPUNanos: raw.CPU.Usage.Total, SystemNanos: raw.CPU.System, OnlineCPUs: raw.CPU.Online,
			Memory: raw.Memory.Usage, MemoryLimit: raw.Memory.Limit}
		if len(r.Names) > 0 {
			st.Name = r.Names[0]
		}
		// Like `docker stats`: page cache that can be reclaimed does not count.
		cache := raw.Memory.Stats["inactive_file"]
		if cache == 0 {
			cache = raw.Memory.Stats["total_inactive_file"]
		}
		if cache < st.Memory {
			st.Memory -= cache
		}
		for _, n := range raw.Networks {
			st.NetRx += n.Rx
			st.NetTx += n.Tx
		}
		for _, e := range raw.Blkio.IO {
			switch strings.ToLower(e.Op) {
			case "read":
				st.BlockRead += e.Value
			case "write":
				st.BlockWrite += e.Value
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// Inspect returns a security-relevant summary of one container.
func (c *Client) Inspect(ctx context.Context, ref string) (agentproto.ContainerDetail, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return agentproto.ContainerDetail{}, err
	}
	var raw struct {
		ID    string `json:"Id"`
		Name  string `json:"Name"`
		State struct {
			Status     string `json:"Status"`
			Running    bool   `json:"Running"`
			ExitCode   int    `json:"ExitCode"`
			StartedAt  string `json:"StartedAt"`
			FinishedAt string `json:"FinishedAt"`
			Health     *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		Config struct {
			Image  string            `json:"Image"`
			User   string            `json:"User"`
			Labels map[string]string `json:"Labels"`
		} `json:"Config"`
		HostConfig struct {
			Privileged    bool     `json:"Privileged"`
			NetworkMode   string   `json:"NetworkMode"`
			CapAdd        []string `json:"CapAdd"`
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
		Mounts []struct {
			Type        string `json:"Type"`
			Source      string `json:"Source"`
			Destination string `json:"Destination"`
			RW          bool   `json:"RW"`
		} `json:"Mounts"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(ref)+"/json", nil, 0, &raw); err != nil {
		return agentproto.ContainerDetail{}, err
	}
	d := agentproto.ContainerDetail{
		ID: raw.ID, Name: strings.TrimPrefix(raw.Name, "/"), Image: raw.Config.Image,
		Status: raw.State.Status, Running: raw.State.Running, ExitCode: raw.State.ExitCode,
		StartedAt: raw.State.StartedAt, FinishedAt: raw.State.FinishedAt,
		RestartPolicy: raw.HostConfig.RestartPolicy.Name, Privileged: raw.HostConfig.Privileged,
		NetworkMode: raw.HostConfig.NetworkMode, CapAdd: append([]string{}, raw.HostConfig.CapAdd...),
		Mounts: []agentproto.Mount{}, User: raw.Config.User, Labels: raw.Config.Labels,
	}
	if d.Labels == nil {
		d.Labels = map[string]string{}
	}
	if raw.State.Health != nil {
		d.Health = raw.State.Health.Status
	}
	for _, m := range raw.Mounts {
		d.Mounts = append(d.Mounts, agentproto.Mount{Type: m.Type, Source: m.Source, Destination: m.Destination, RW: m.RW})
	}
	return d, nil
}

// Start starts a container. changed is false if it was already running.
func (c *Client) Start(ctx context.Context, ref string) (bool, error) {
	return c.action(ctx, ref, "start", nil, 0)
}

// Stop stops a container, killing it after timeout.
func (c *Client) Stop(ctx context.Context, ref string, timeout time.Duration) (bool, error) {
	return c.action(ctx, ref, "stop", url.Values{"t": {strconv.Itoa(int(timeout.Seconds()))}}, timeout)
}

// Restart restarts a container.
func (c *Client) Restart(ctx context.Context, ref string, timeout time.Duration) (bool, error) {
	return c.action(ctx, ref, "restart", url.Values{"t": {strconv.Itoa(int(timeout.Seconds()))}}, timeout)
}

func (c *Client) action(ctx context.Context, ref, verb string, q url.Values, grace time.Duration) (bool, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return false, err
	}
	status, err := c.do(ctx, http.MethodPost, p+"/containers/"+url.PathEscape(ref)+"/"+verb, q, grace, nil)
	if err != nil {
		return false, err
	}
	return status != http.StatusNotModified, nil
}
