package certs

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// cloudflareAPI is Cloudflare's fixed API endpoint; nothing comes from input.
const cloudflareAPI = "https://api.cloudflare.com/client/v4"

// cloudflare creates DNS-01 TXT records with an API token that may edit the
// zone's DNS records.
type cloudflare struct {
	token string
	base  string
	hc    *http.Client

	mu      sync.Mutex
	records map[string][2]string // fqdn+value → zone ID, record ID
}

func newCloudflare(token, base string) *cloudflare {
	return &cloudflare{token: token, base: base, hc: &http.Client{Timeout: 30 * time.Second}, records: map[string][2]string{}}
}

type cfResponse struct {
	Success bool `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	Result json.RawMessage `json:"result"`
}

func (c *cloudflare) do(ctx context.Context, method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("cloudflare: %w", err)
	}
	defer res.Body.Close()
	var r cfResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&r); err != nil {
		return fmt.Errorf("cloudflare: HTTP %d", res.StatusCode)
	}
	if !r.Success || res.StatusCode >= 300 {
		msgs := []string{}
		for _, e := range r.Errors {
			msgs = append(msgs, e.Message)
		}
		return fmt.Errorf("cloudflare: HTTP %d: %s", res.StatusCode, strings.Join(msgs, "; "))
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

// zone finds the closest zone of fqdn the token can see.
func (c *cloudflare) zone(ctx context.Context, fqdn string) (string, error) {
	labels := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := 1; i < len(labels)-1; i++ {
		name := strings.Join(labels[i:], ".")
		var zones []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		if err := c.do(ctx, http.MethodGet, "/zones?"+url.Values{"name": {name}}.Encode(), nil, &zones); err != nil {
			return "", err
		}
		for _, z := range zones {
			if z.Name == name {
				return z.ID, nil
			}
		}
	}
	return "", fmt.Errorf("cloudflare: no zone for %s is accessible with this token", strings.TrimPrefix(fqdn, "_acme-challenge."))
}

func (c *cloudflare) Present(ctx context.Context, fqdn, value string) error {
	zone, err := c.zone(ctx, fqdn)
	if err != nil {
		return err
	}
	var rec struct {
		ID string `json:"id"`
	}
	if err := c.do(ctx, http.MethodPost, "/zones/"+url.PathEscape(zone)+"/dns_records",
		map[string]any{"type": "TXT", "name": fqdn, "content": value, "ttl": 120}, &rec); err != nil {
		return err
	}
	c.mu.Lock()
	c.records[fqdn+" "+value] = [2]string{zone, rec.ID}
	c.mu.Unlock()
	return nil
}

func (c *cloudflare) CleanUp(ctx context.Context, fqdn, value string) error {
	c.mu.Lock()
	r, ok := c.records[fqdn+" "+value]
	delete(c.records, fqdn+" "+value)
	c.mu.Unlock()
	if !ok {
		return nil
	}
	return c.do(ctx, http.MethodDelete, "/zones/"+url.PathEscape(r[0])+"/dns_records/"+url.PathEscape(r[1]), nil, nil)
}
