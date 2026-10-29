package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Channel kinds (AT-F16-01).
const (
	KindSMTP    = "smtp"
	KindWebhook = "webhook"
	KindNtfy    = "ntfy"
	KindGotify  = "gotify"
)

// ChannelConfig holds the non-secret settings of a channel.
type ChannelConfig struct {
	// SMTP
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Security string   `json:"security,omitempty"` // starttls, tls, none
	Username string   `json:"username,omitempty"`
	From     string   `json:"from,omitempty"`
	To       []string `json:"to,omitempty"`
	// webhook, ntfy, Gotify
	URL   string `json:"url,omitempty"`
	Topic string `json:"topic,omitempty"`
}

// Message is what a channel sends.
type Message struct {
	Title    string    `json:"title"`
	Body     string    `json:"body"`
	Severity string    `json:"severity"`
	State    string    `json:"state"` // firing, resolved, event, test
	Rule     string    `json:"rule"`
	Key      string    `json:"key"`
	Time     time.Time `json:"time"`
	Instance string    `json:"instance"`
}

var (
	topicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	hostRE  = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]{0,252})$`)
)

func validAddress(s string) bool {
	a, err := mail.ParseAddress(s)
	return err == nil && a.Address == s && !strings.ContainsAny(s, "\r\n")
}

func validURL(raw string) error {
	u, err := url.Parse(raw)
	switch {
	case err != nil || len(raw) > 2048:
		return fmt.Errorf("the URL is not valid")
	case u.Scheme != "https" && u.Scheme != "http":
		return fmt.Errorf("the URL must use https or http")
	case u.Host == "" || u.User != nil || u.Opaque != "":
		return fmt.Errorf("the URL needs a host and must not contain credentials")
	}
	return nil
}

// validate checks a channel's settings; secret is whether one is stored.
func validate(kind string, c *ChannelConfig, hasSecret bool) error {
	switch kind {
	case KindSMTP:
		if !hostRE.MatchString(c.Host) {
			return fmt.Errorf("SMTP host %q is not valid", c.Host)
		}
		if c.Port == 0 {
			c.Port = 587
		}
		if c.Port < 1 || c.Port > 65535 {
			return fmt.Errorf("SMTP port must be 1-65535")
		}
		if c.Security == "" {
			c.Security = "starttls"
		}
		switch c.Security {
		case "starttls", "tls":
		case "none":
			if c.Username != "" || hasSecret {
				return fmt.Errorf("authentication needs TLS: use starttls or tls")
			}
		default:
			return fmt.Errorf("security must be starttls, tls or none")
		}
		if !validAddress(c.From) {
			return fmt.Errorf("sender %q is not a valid address", c.From)
		}
		if len(c.To) == 0 || len(c.To) > 10 {
			return fmt.Errorf("1 to 10 recipients are needed")
		}
		for _, t := range c.To {
			if !validAddress(t) {
				return fmt.Errorf("recipient %q is not a valid address", t)
			}
		}
		c.URL, c.Topic = "", ""
	case KindWebhook, KindGotify:
		if err := validURL(c.URL); err != nil {
			return err
		}
		*c = ChannelConfig{URL: c.URL}
	case KindNtfy:
		if err := validURL(c.URL); err != nil {
			return err
		}
		if !topicRE.MatchString(c.Topic) {
			return fmt.Errorf("the ntfy topic may contain letters, digits, _ and - (1-64)")
		}
		*c = ChannelConfig{URL: c.URL, Topic: c.Topic}
	default:
		return fmt.Errorf("kind must be smtp, webhook, ntfy or gotify")
	}
	return nil
}

// Sender delivers messages through the guard.
type Sender struct {
	Guard Guard
	// Roots replaces the system roots for TLS (tests).
	Roots *x509.CertPool
}

func (s Sender) client() *http.Client {
	c := s.Guard.HTTPClient()
	if s.Roots != nil {
		c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: s.Roots}
	}
	return c
}

func (s Sender) post(ctx context.Context, u string, body []byte, hdr map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "kernhaven")
	res, err := s.client().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	msg := drain(res.Body)
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(msg))
	}
	return nil
}

func priority(m Message, crit, warn, low int) int {
	switch {
	case m.State == "resolved":
		return low
	case m.Severity == "critical":
		return crit
	default:
		return warn
	}
}

// Send delivers m to a channel.
func (s Sender) Send(ctx context.Context, kind string, c ChannelConfig, secret string, m Message) error {
	switch kind {
	case KindWebhook:
		body, _ := json.Marshal(m)
		hdr := map[string]string{"Content-Type": "application/json", "X-Kernhaven-Event": m.State}
		if secret != "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(body)
			hdr["X-Kernhaven-Signature"] = "sha256=" + hex.EncodeToString(mac.Sum(nil))
		}
		return s.post(ctx, c.URL, body, hdr)
	case KindNtfy:
		hdr := map[string]string{"Title": m.Title, "Priority": strconv.Itoa(priority(m, 5, 4, 2)), "Tags": map[string]string{"resolved": "white_check_mark", "test": "bell"}[m.State]}
		if hdr["Tags"] == "" {
			hdr["Tags"] = "warning"
		}
		if secret != "" {
			hdr["Authorization"] = "Bearer " + secret
		}
		return s.post(ctx, strings.TrimRight(c.URL, "/")+"/"+c.Topic, []byte(m.Body), hdr)
	case KindGotify:
		body, _ := json.Marshal(map[string]any{"title": m.Title, "message": m.Body, "priority": priority(m, 8, 5, 2)})
		return s.post(ctx, strings.TrimRight(c.URL, "/")+"/message", body, map[string]string{"Content-Type": "application/json", "X-Gotify-Key": secret})
	case KindSMTP:
		return s.mail(ctx, c, secret, m)
	}
	return fmt.Errorf("unknown channel kind %q", kind)
}

func header(s string) string { return strings.NewReplacer("\r", " ", "\n", " ").Replace(s) }

func (s Sender) mail(ctx context.Context, c ChannelConfig, password string, m Message) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	conn, err := s.Guard.DialContext(ctx, "tcp", net.JoinHostPort(c.Host, strconv.Itoa(c.Port)))
	if err != nil {
		return err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tlsCfg := &tls.Config{ServerName: c.Host, RootCAs: s.Roots, MinVersion: tls.VersionTLS12}
	if c.Security == "tls" {
		conn = tls.Client(conn, tlsCfg)
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return err
	}
	defer cl.Close()
	if c.Security == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return fmt.Errorf("the server does not offer STARTTLS")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return err
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, password, c.Host)); err != nil {
			return fmt.Errorf("authentication: %w", err)
		}
	}
	if err := cl.Mail(c.From); err != nil {
		return err
	}
	for _, t := range c.To {
		if err := cl.Rcpt(t); err != nil {
			return err
		}
	}
	w, err := cl.Data()
	if err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMessage-ID: <%d.kernhaven@%s>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n",
		c.From, strings.Join(c.To, ", "), header("[Kernhaven] "+m.Title), m.Time.Format(time.RFC1123Z), m.Time.UnixNano(), header(c.Host))
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(m.Body, "\r\n", "\n"), "\n", "\r\n"))
	b.WriteString("\r\n\r\n-- \r\n" + m.Instance + "\r\n")
	if _, err := w.Write([]byte(b.String())); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return cl.Quit()
}
