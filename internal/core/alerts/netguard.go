package alerts

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// ErrForbiddenAddress is a destination the Core may not reach (ADR-0028).
var ErrForbiddenAddress = errors.New("destination address is not allowed")

// Guard checks destination addresses when a connection is made, so a name
// that resolves to a forbidden address is refused even if it changed after
// the channel was saved.
type Guard struct {
	AllowLoopback bool // tests only
	Resolver      *net.Resolver
}

// Allowed reports whether a may be dialled: not loopback (unless allowed),
// link-local, unspecified or multicast. Private ranges are allowed.
func (g Guard) Allowed(a netip.Addr) bool {
	a = a.Unmap()
	switch {
	case a.IsLoopback():
		return g.AllowLoopback
	case a.IsLinkLocalUnicast(), a.IsLinkLocalMulticast(), a.IsInterfaceLocalMulticast(), a.IsMulticast(), a.IsUnspecified(), !a.IsValid():
		return false
	}
	return true
}

// DialContext resolves addr and connects to the first allowed address.
func (g Guard) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	r := g.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	ips, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	var lastErr error = fmt.Errorf("%w: %s resolves to no allowed address", ErrForbiddenAddress, host)
	for _, ip := range ips {
		if !g.Allowed(ip) {
			lastErr = fmt.Errorf("%w: %s resolves to %s", ErrForbiddenAddress, host, ip.Unmap())
			continue
		}
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

// HTTPClient never follows redirects and dials through the guard.
func (g Guard) HTTPClient() *http.Client {
	return &http.Client{
		Timeout:   20 * time.Second,
		Transport: &http.Transport{DialContext: g.DialContext, Proxy: nil, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 10 * time.Second},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are not followed")
		},
	}
}

// drain reads at most 64 KiB of a response for error messages.
func drain(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 64<<10))
	if len(b) > 300 {
		b = b[:300]
	}
	return string(b)
}
