// Package network is the proxy role of the agent (M12, ADR-0025): it loads
// Caddy configurations built from typed routes through Caddy's admin socket
// and reads the host's interfaces and listening sockets.
package network

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/proxy"
)

// ErrUnavailable means Caddy's admin API cannot be reached.
var ErrUnavailable = errors.New("caddy is not running or its admin socket is not reachable")

// RejectedError carries Caddy's reason for refusing a configuration. The
// running configuration is unchanged.
type RejectedError struct{ Msg string }

func (e *RejectedError) Error() string { return "caddy refused the configuration: " + e.Msg }

// Service talks to one Caddy instance.
type Service struct {
	settings proxy.Settings
	client   *http.Client
	procNet  string
}

// New returns the service for the given settings.
func New(s proxy.Settings) *Service {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &Service{
		settings: s,
		procNet:  "/proc/self/net",
		client: &http.Client{
			Timeout: 90 * time.Second, // loading provisions certificates of the internal CA
			Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, "unix", s.AdminSocket)
			}},
		},
	}
}

func (s *Service) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://"+proxy.AdminHost+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := s.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return 0, nil, ctx.Err()
		}
		return 0, nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	return res.StatusCode, b, err
}

// Apply builds the configuration for a and loads it. Caddy starts the new
// configuration before stopping the old one and keeps the old one on any
// error (AT-F11-03).
func (s *Service) Apply(ctx context.Context, a agentproto.ProxyApply) (agentproto.ProxyApplied, error) {
	cfg, err := proxy.Build(a, s.settings)
	if err != nil {
		return agentproto.ProxyApplied{}, err
	}
	want, err := proxy.Hash(cfg)
	if err != nil {
		return agentproto.ProxyApplied{}, err
	}
	code, body, err := s.do(ctx, http.MethodPost, "/load", cfg)
	if err != nil {
		return agentproto.ProxyApplied{}, err
	}
	if code != http.StatusOK {
		return agentproto.ProxyApplied{}, &RejectedError{Msg: caddyMessage(body, code)}
	}
	st, err := s.Status(ctx)
	if err != nil {
		return agentproto.ProxyApplied{}, err
	}
	if st.Hash != want {
		return agentproto.ProxyApplied{}, &RejectedError{Msg: "the running configuration differs from the loaded one"}
	}
	return agentproto.ProxyApplied{Hash: want, Routes: len(a.Routes), HTTPSPort: s.settings.HTTPSPort}, nil
}

// caddyMessage extracts {"error": "..."} and limits its length.
func caddyMessage(body []byte, code int) string {
	msg := strings.TrimSpace(string(body))
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(body, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	if msg == "" {
		msg = fmt.Sprintf("HTTP %d", code)
	}
	if len(msg) > 500 {
		msg = msg[:500] + "…"
	}
	return msg
}

// Status hashes the running configuration (empty when Caddy has none).
func (s *Service) Status(ctx context.Context) (agentproto.ProxyStatus, error) {
	code, body, err := s.do(ctx, http.MethodGet, "/config/", nil)
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return agentproto.ProxyStatus{HTTPSPort: s.settings.HTTPSPort}, nil
		}
		return agentproto.ProxyStatus{}, err
	}
	if code != http.StatusOK {
		return agentproto.ProxyStatus{}, &RejectedError{Msg: caddyMessage(body, code)}
	}
	st := agentproto.ProxyStatus{Reachable: true, HTTPSPort: s.settings.HTTPSPort}
	if t := bytes.TrimSpace(body); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
		if st.Hash, err = proxy.Hash(t); err != nil {
			return agentproto.ProxyStatus{}, err
		}
	}
	return st, nil
}

// Overview lists interfaces and listening sockets (AT-F11-04).
func (s *Service) Overview(context.Context) (agentproto.NetworkOverview, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return agentproto.NetworkOverview{}, err
	}
	out := agentproto.NetworkOverview{Interfaces: []agentproto.NetworkInterface{}, Listening: []agentproto.ListeningSocket{}}
	for _, i := range ifs {
		ni := agentproto.NetworkInterface{Name: i.Name, MTU: i.MTU, MAC: i.HardwareAddr.String(), Up: i.Flags&net.FlagUp != 0, Loopback: i.Flags&net.FlagLoopback != 0, Addresses: []string{}}
		if addrs, err := i.Addrs(); err == nil {
			for _, a := range addrs {
				ni.Addresses = append(ni.Addresses, a.String())
			}
		}
		out.Interfaces = append(out.Interfaces, ni)
	}
	seen := map[agentproto.ListeningSocket]bool{}
	for _, proto := range []string{"tcp", "tcp6", "udp", "udp6"} {
		f, err := os.Open(filepath.Join(s.procNet, proto))
		if err != nil {
			continue // IPv6 may be disabled
		}
		socks, err := parseProcNet(f, proto)
		f.Close()
		if err != nil {
			return agentproto.NetworkOverview{}, err
		}
		for _, l := range socks {
			if !seen[l] {
				seen[l] = true
				out.Listening = append(out.Listening, l)
			}
		}
	}
	sort.Slice(out.Listening, func(i, j int) bool {
		a, b := out.Listening[i], out.Listening[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		return a.Address < b.Address
	})
	return out, nil
}

// parseProcNet reads /proc/net/{tcp,tcp6,udp,udp6}: listening TCP sockets
// (state 0A) and bound UDP sockets without a peer (state 07).
func parseProcNet(r io.Reader, proto string) ([]agentproto.ListeningSocket, error) {
	want := "0A"
	if strings.HasPrefix(proto, "udp") {
		want = "07"
	}
	var out []agentproto.ListeningSocket
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[3] != want {
			continue
		}
		if strings.HasPrefix(proto, "udp") && !zeroPort(f[2]) {
			continue
		}
		addr, port, err := hexAddr(f[1])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", proto, err)
		}
		out = append(out, agentproto.ListeningSocket{Protocol: proto, Address: addr, Port: port})
	}
	return out, sc.Err()
}

func zeroPort(s string) bool { return strings.HasSuffix(s, ":0000") }

// hexAddr decodes "0100007F:1F90": the address in host byte order per
// 32-bit word (little-endian on all supported architectures), port big-endian.
func hexAddr(s string) (string, int, error) {
	a, p, ok := strings.Cut(s, ":")
	if !ok {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return "", 0, fmt.Errorf("bad port %q", s)
	}
	raw, err := hex.DecodeString(a)
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, fmt.Errorf("bad address %q", s)
	}
	for i := 0; i < len(raw); i += 4 {
		raw[i], raw[i+1], raw[i+2], raw[i+3] = raw[i+3], raw[i+2], raw[i+1], raw[i]
	}
	ip, _ := netip.AddrFromSlice(raw)
	return ip.Unmap().String(), int(port), nil
}
