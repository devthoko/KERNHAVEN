package network

import (
	"context"
	"database/sql"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
)

// TLS is the TLS part of the proxy configuration (M13).
type TLS struct {
	Hosts        []agentproto.TLSHost
	Certificates []agentproto.TLSCertificate
	ACME         *agentproto.ACMESettings
}

// TLSSource returns the TLS settings for the hosts that have routes (and
// the Kernhaven host).
type TLSSource func(ctx context.Context, hosts map[string]bool) (TLS, error)

// SetTLS connects the stored TLS settings (package certs).
func (s *Service) SetTLS(src TLSSource) { s.tls = src }

// KernhavenHost is the host of the Core's public origin.
func (s *Service) KernhavenHost() string { return s.khHost }

// Host is a host that can have TLS settings.
type Host struct {
	Host      string `json:"host"`
	Kernhaven bool   `json:"kernhaven"`
	LANOnly   bool   `json:"lan_only"` // at least one LAN-only route
	Routes    int    `json:"routes"`
}

// Hosts lists the Kernhaven host and every host with a route.
func (s *Service) Hosts(ctx context.Context) ([]Host, error) {
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return nil, err
	}
	out := []Host{{Host: s.khHost, Kernhaven: true}}
	idx := map[string]int{}
	for _, r := range routes {
		i, ok := idx[r.Host]
		if !ok {
			i = len(out)
			idx[r.Host] = i
			out = append(out, Host{Host: r.Host})
		}
		out[i].Routes++
		out[i].LANOnly = out[i].LANOnly || r.LANOnly
	}
	return out, nil
}

// ChangeTLS applies the stored routes with the TLS settings from next and
// runs write with the audit entry only when Caddy accepted them.
func (s *Service) ChangeTLS(ctx context.Context, a Actor, action, target string, next TLSSource, write func(tx *sql.Tx) error, kv ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	routes, err := s.list(ctx, s.db)
	if err != nil {
		return err
	}
	res, err := s.push(ctx, a, routes, next)
	if err != nil {
		_ = s.audit.Record(context.WithoutCancel(ctx), s.event(a, action, target, err, kv...))
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if err := write(tx); err != nil {
			return err
		}
		if err := s.applied(ctx, tx, res); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), s.event(a, action, target, nil, kv...))
		return err
	})
}

// CA returns the root of Caddy's local CA (AT-F12-02).
func (s *Service) CA(ctx context.Context, a Actor) (agentproto.ProxyCA, error) {
	if s.client == nil {
		return agentproto.ProxyCA{}, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var ca agentproto.ProxyCA
	err := s.client.Do(ctx, agentclient.Call{Op: agentproto.OpProxyCA, Actor: a.Name, RequestID: a.RequestID}, &ca)
	return ca, err
}
