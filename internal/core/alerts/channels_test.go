package alerts

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/proxy/certtest"
)

func TestGuard(t *testing.T) {
	g := Guard{}
	for addr, want := range map[string]bool{
		"192.168.1.10": true, "10.0.0.5": true, "172.16.3.4": true, "fd00::1": true, "1.1.1.1": true,
		"127.0.0.1": false, "::1": false, "169.254.169.254": false, "fe80::1": false, "0.0.0.0": false, "::": false,
		"224.0.0.1": false, "::ffff:127.0.0.1": false, "::ffff:169.254.169.254": false,
	} {
		if got := g.Allowed(netip.MustParseAddr(addr)); got != want {
			t.Errorf("%s: %v", addr, got)
		}
	}
	if !(Guard{AllowLoopback: true}).Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Error("test exception")
	}
	ctx := context.Background()
	for _, addr := range []string{"localhost:80", "127.0.0.1:80", "169.254.169.254:80", "[::1]:80"} {
		if _, err := g.DialContext(ctx, "tcp", addr); !errors.Is(err, ErrForbiddenAddress) {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestValidate(t *testing.T) {
	ok := []struct {
		kind string
		c    ChannelConfig
	}{
		{KindSMTP, ChannelConfig{Host: "mail.home.arpa", From: "kh@home.arpa", To: []string{"me@example.org"}}},
		{KindSMTP, ChannelConfig{Host: "10.0.0.2", Port: 25, Security: "none", From: "kh@home.arpa", To: []string{"me@example.org"}}},
		{KindWebhook, ChannelConfig{URL: "https://hooks.example.org/x"}},
		{KindNtfy, ChannelConfig{URL: "http://192.168.1.5:8080", Topic: "kernhaven"}},
		{KindGotify, ChannelConfig{URL: "https://gotify.home.arpa"}},
	}
	for _, c := range ok {
		if err := validate(c.kind, &c.c, false); err != nil {
			t.Errorf("%s %+v: %v", c.kind, c.c, err)
		}
	}
	smtp := ChannelConfig{Host: "mail.lan", From: "kh@lan.example", To: []string{"me@example.org"}}
	if validate(KindSMTP, &smtp, false); smtp.Port != 587 || smtp.Security != "starttls" {
		t.Errorf("defaults %+v", smtp)
	}
	bad := map[string]struct {
		kind   string
		c      ChannelConfig
		secret bool
	}{
		"auth without TLS": {KindSMTP, ChannelConfig{Host: "m", Security: "none", Username: "u", From: "a@b.c", To: []string{"d@e.f"}}, false},
		"secret no TLS":    {KindSMTP, ChannelConfig{Host: "m", Security: "none", From: "a@b.c", To: []string{"d@e.f"}}, true},
		"bad sender":       {KindSMTP, ChannelConfig{Host: "m", From: "Kernhaven <a@b.c>", To: []string{"d@e.f"}}, false},
		"header injection": {KindSMTP, ChannelConfig{Host: "m", From: "a@b.c", To: []string{"d@e.f\r\nBcc: x@y.z"}}, false},
		"no recipients":    {KindSMTP, ChannelConfig{Host: "m", From: "a@b.c"}, false},
		"bad host":         {KindSMTP, ChannelConfig{Host: "m;rm", From: "a@b.c", To: []string{"d@e.f"}}, false},
		"ftp url":          {KindWebhook, ChannelConfig{URL: "ftp://x/y"}, false},
		"credentials":      {KindWebhook, ChannelConfig{URL: "https://u:p@x/y"}, false},
		"no host":          {KindGotify, ChannelConfig{URL: "https:///message"}, false},
		"bad topic":        {KindNtfy, ChannelConfig{URL: "https://ntfy.sh", Topic: "a/b"}, false},
		"kind":             {"slack", ChannelConfig{URL: "https://x"}, false},
	}
	for name, c := range bad {
		if err := validate(c.kind, &c.c, c.secret); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func msg() Message {
	return Message{Title: "Disk almost full", Body: "sda1 is 95 % full", Severity: "warning", State: "firing", Rule: "disk_full", Key: "/dev/sda1",
		Time: time.Date(2026, 10, 29, 8, 0, 0, 0, time.UTC), Instance: "https://kernhaven.test"}
}

func TestHTTPChannels(t *testing.T) {
	type got struct {
		path string
		hdr  http.Header
		body []byte
	}
	var mu sync.Mutex
	var last got
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		last = got{r.URL.Path, r.Header.Clone(), b}
		mu.Unlock()
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/elsewhere", http.StatusFound)
			return
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, "receiver says no")
	}))
	defer srv.Close()
	s := Sender{Guard: Guard{AllowLoopback: true}}
	ctx := context.Background()

	// Webhook: JSON with an HMAC signature of the exact body.
	if err := s.Send(ctx, KindWebhook, ChannelConfig{URL: srv.URL + "/hook"}, "s3cret", msg()); err != nil {
		t.Fatal(err)
	}
	var m Message
	if err := json.Unmarshal(last.body, &m); err != nil || m.Title != "Disk almost full" || m.State != "firing" || m.Instance != "https://kernhaven.test" {
		t.Fatalf("webhook body %s", last.body)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(last.body)
	if last.hdr.Get("X-Kernhaven-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature %q", last.hdr.Get("X-Kernhaven-Signature"))
	}
	// ntfy: topic in the path, title and priority as headers, token as bearer.
	if err := s.Send(ctx, KindNtfy, ChannelConfig{URL: srv.URL + "/", Topic: "kh"}, "tk_abc", msg()); err != nil {
		t.Fatal(err)
	}
	if last.path != "/kh" || last.hdr.Get("Title") != "Disk almost full" || last.hdr.Get("Priority") != "4" || last.hdr.Get("Authorization") != "Bearer tk_abc" || string(last.body) != "sda1 is 95 % full" {
		t.Fatalf("ntfy %+v %s", last.hdr, last.body)
	}
	// Gotify: /message with the application token.
	crit := msg()
	crit.Severity = "critical"
	if err := s.Send(ctx, KindGotify, ChannelConfig{URL: srv.URL}, "AbCd", crit); err != nil {
		t.Fatal(err)
	}
	var g struct {
		Title    string
		Message  string
		Priority int
	}
	_ = json.Unmarshal(last.body, &g)
	if last.path != "/message" || last.hdr.Get("X-Gotify-Key") != "AbCd" || g.Priority != 8 || g.Message != "sda1 is 95 % full" {
		t.Fatalf("gotify %+v %+v", last.hdr, g)
	}
	// Errors carry the status and a bounded body; redirects are not followed.
	status = http.StatusInternalServerError
	if err := s.Send(ctx, KindWebhook, ChannelConfig{URL: srv.URL + "/hook"}, "", msg()); err == nil || !strings.Contains(err.Error(), "HTTP 500: receiver says no") {
		t.Fatalf("500: %v", err)
	}
	if err := s.Send(ctx, KindWebhook, ChannelConfig{URL: srv.URL + "/redirect"}, "", msg()); err == nil || !strings.Contains(err.Error(), "redirects are not followed") {
		t.Fatalf("redirect: %v", err)
	}
	// Without the test exception loopback is refused.
	if err := (Sender{}).Send(ctx, KindWebhook, ChannelConfig{URL: srv.URL + "/hook"}, "", msg()); !errors.Is(err, ErrForbiddenAddress) {
		t.Fatalf("loopback: %v", err)
	}
}

// fakeSMTP is a minimal SMTP server with STARTTLS and AUTH PLAIN.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	starttls bool
	mu       sync.Mutex
	auth     string
	from     string
	rcpt     []string
	data     string
	tlsUsed  bool
}

func (f *fakeSMTP) serve(t *testing.T) {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.session(c)
	}
}

func (f *fakeSMTP) session(c net.Conn) {
	defer c.Close()
	rd, w := bufio.NewReader(c), c
	say := func(s string) { _, _ = io.WriteString(w, s+"\r\n") }
	say("220 fake ESMTP")
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.TrimSpace(line)
		up := strings.ToUpper(cmd)
		switch {
		case strings.HasPrefix(up, "EHLO"):
			if f.starttls && !f.tlsUsed {
				say("250-fake\r\n250-STARTTLS\r\n250 AUTH PLAIN")
			} else {
				say("250-fake\r\n250 AUTH PLAIN")
			}
		case up == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.tlsCfg)
			if tc.Handshake() != nil {
				return
			}
			f.mu.Lock()
			f.tlsUsed = true
			f.mu.Unlock()
			c, rd, w = tc, bufio.NewReader(tc), tc
		case strings.HasPrefix(up, "AUTH PLAIN"):
			f.mu.Lock()
			f.auth = strings.TrimSpace(cmd[len("AUTH PLAIN"):])
			f.mu.Unlock()
			say("235 ok")
		case strings.HasPrefix(up, "MAIL FROM:"):
			f.mu.Lock()
			f.from = cmd[len("MAIL FROM:"):]
			f.mu.Unlock()
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			f.mu.Lock()
			f.rcpt = append(f.rcpt, cmd[len("RCPT TO:"):])
			f.mu.Unlock()
			say("250 ok")
		case up == "DATA":
			say("354 go")
			var b strings.Builder
			for {
				l, err := rd.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(l)
			}
			f.mu.Lock()
			f.data = b.String()
			f.mu.Unlock()
			say("250 queued")
		case up == "QUIT":
			say("221 bye")
			return
		default:
			say("250 ok")
		}
	}
}

func TestSMTP(t *testing.T) {
	ca := certtest.NewCA(t, "Mail CA", nil)
	cert, key := ca.Issue(t, certtest.Leaf{Names: []string{"127.0.0.1"}})
	pair, err := tls.X509KeyPair([]byte(cert), []byte(key))
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	f := &fakeSMTP{ln: ln, tlsCfg: &tls.Config{Certificates: []tls.Certificate{pair}}, starttls: true}
	go f.serve(t)
	port := ln.Addr().(*net.TCPAddr).Port
	roots := x509.NewCertPool()
	roots.AddCert(ca.Cert)
	s := Sender{Guard: Guard{AllowLoopback: true}, Roots: roots}
	cfg := ChannelConfig{Host: "127.0.0.1", Port: port, Security: "starttls", Username: "kh", From: "kh@home.arpa", To: []string{"me@example.org", "ops@example.org"}}
	if err := s.Send(context.Background(), KindSMTP, cfg, "pw", msg()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	plain, _ := base64.StdEncoding.DecodeString(f.auth)
	if !f.tlsUsed || string(plain) != "\x00kh\x00pw" || f.from != "<kh@home.arpa>" || len(f.rcpt) != 2 {
		t.Fatalf("session tls=%v auth=%q from=%q rcpt=%v", f.tlsUsed, plain, f.from, f.rcpt)
	}
	if !strings.Contains(f.data, "Subject: [Kernhaven] Disk almost full\r\n") || !strings.Contains(f.data, "sda1 is 95 % full") || !strings.Contains(f.data, "To: me@example.org, ops@example.org") {
		t.Fatalf("data %q", f.data)
	}
	// A server without STARTTLS is refused before any credential is sent.
	f.starttls, f.auth, f.tlsUsed = false, "", false
	f.mu.Unlock()
	err = s.Send(context.Background(), KindSMTP, cfg, "pw", msg())
	f.mu.Lock()
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") || f.auth != "" {
		t.Fatalf("no starttls: %v, auth %q", err, f.auth)
	}
}
