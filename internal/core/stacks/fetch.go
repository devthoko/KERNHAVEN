package stacks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/compose"
)

// Fetcher downloads Compose files over HTTPS without reaching internal
// addresses (TH-42).
type Fetcher struct {
	client *http.Client
}

var cgnat = mustCIDR("100.64.0.0/10")

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

// PublicIP reports whether ip is a public unicast address.
func PublicIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() || cgnat.Contains(ip) ||
		ip.Equal(net.IPv4bcast) || (len(ip) == net.IPv4len && ip[0] == 0))
}

// ErrBlocked means the URL points to a non-public address or scheme.
var ErrBlocked = errors.New("only public HTTPS addresses can be imported")

// NewFetcher returns a fetcher. allow decides which resolved addresses may be
// contacted (nil = PublicIP); tests pass a looser rule.
func NewFetcher(allow func(net.IP) bool, rootCAs *http.Transport) *Fetcher {
	if allow == nil {
		allow = PublicIP
	}
	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
		// Control runs after DNS resolution for the actual address, so DNS
		// rebinding and redirects cannot reach internal hosts.
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil || !allow(ip) {
				return fmt.Errorf("%w (%s)", ErrBlocked, host)
			}
			return nil
		},
	}
	tr := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second, Proxy: nil, MaxIdleConns: 2}
	if rootCAs != nil {
		tr.TLSClientConfig = rootCAs.TLSClientConfig
	}
	return &Fetcher{client: &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if req.URL.Scheme != "https" {
				return ErrBlocked
			}
			return nil
		},
	}}
}

// Fetch downloads a Compose file from an https URL (max compose.MaxSize).
func (f *Fetcher) Fetch(ctx context.Context, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return "", ErrBlocked
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/yaml, text/yaml, text/plain")
	resp, err := f.client.Do(req)
	if err != nil {
		if errors.Is(err, ErrBlocked) {
			return "", ErrBlocked
		}
		return "", fmt.Errorf("download failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, compose.MaxSize+1))
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	if len(body) > compose.MaxSize {
		return "", fmt.Errorf("the file is larger than %d KiB", compose.MaxSize>>10)
	}
	return string(body), nil
}
