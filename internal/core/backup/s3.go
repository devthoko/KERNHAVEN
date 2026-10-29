package backup

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
)

// S3Config is a bucket on an S3-compatible service (ADR-0030).
type S3Config struct {
	Endpoint    string `json:"endpoint"` // https://s3.example.com[:port]
	Region      string `json:"region"`
	Bucket      string `json:"bucket"`
	Prefix      string `json:"prefix,omitempty"`
	AccessKeyID string `json:"access_key_id"`
	// PathStyle puts the bucket in the path (most self-hosted services)
	// instead of the host name.
	PathStyle bool `json:"path_style"`
}

var (
	bucketRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	s3PrefixRe = regexp.MustCompile(`^([A-Za-z0-9_.-]{1,64}/){0,4}$`)
	regionRe   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	keyIDRe    = regexp.MustCompile(`^[\x21-\x7e]{3,128}$`)
)

func (c *S3Config) validate() (*url.URL, error) {
	u, err := url.Parse(c.Endpoint)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, targetErr("endpoint must be http(s)://host[:port] without a path")
	}
	if c.Region == "" {
		c.Region = "us-east-1"
	}
	if !regionRe.MatchString(c.Region) {
		return nil, targetErr("region is invalid")
	}
	if !bucketRe.MatchString(c.Bucket) {
		return nil, targetErr("bucket name is invalid")
	}
	if c.Prefix != "" && !s3PrefixRe.MatchString(c.Prefix) {
		return nil, targetErr("prefix must be up to four path segments ending with /")
	}
	if !keyIDRe.MatchString(c.AccessKeyID) {
		return nil, targetErr("access key ID is invalid")
	}
	return u, nil
}

// s3PartSize is the multipart part size; parts are buffered in memory.
const s3PartSize = 16 << 20

type s3Target struct {
	c      S3Config
	base   *url.URL
	secret string
	http   *http.Client
	now    func() time.Time
}

// OpenS3 checks the settings and that the bucket can be listed.
func OpenS3(ctx context.Context, g netguard.Guard, c S3Config, secret string, roots *x509.CertPool) (Target, error) {
	u, err := c.validate()
	if err != nil {
		return nil, err
	}
	if secret == "" {
		return nil, targetErr("the secret access key is required")
	}
	t := &s3Target{c: c, base: u, secret: secret, now: time.Now, http: &http.Client{
		Transport: &http.Transport{DialContext: g.DialContext, Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 2 * time.Minute, ForceAttemptHTTP2: true},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are not followed") },
	}}
	if _, err := t.list(ctx, "snapshots/", "", 1); err != nil {
		return nil, err
	}
	return t, nil
}

// uriEncode encodes like SigV4 requires: everything except unreserved
// characters (and '/' in paths).
func uriEncode(s string, path bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.' || c == '~' || (path && c == '/') {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func hmacSHA(key []byte, s string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// signV4 adds AWS Signature Version 4 headers. It signs host, range and
// every x-amz-* header; payloadHash is the hex SHA-256 of the body.
func signV4(r *http.Request, keyID, secret, region, payloadHash string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	day := amzDate[:8]
	r.Header.Set("x-amz-date", amzDate)
	r.Header.Set("x-amz-content-sha256", payloadHash)
	headers := map[string]string{"host": r.URL.Host}
	if r.Host != "" {
		headers["host"] = r.Host
	}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "x-amz-") || lk == "range" || lk == "content-md5" {
			headers[lk] = strings.TrimSpace(strings.Join(v, ","))
		}
	}
	names := make([]string, 0, len(headers))
	for k := range headers {
		names = append(names, k)
	}
	sort.Strings(names)
	var canonHeaders strings.Builder
	for _, k := range names {
		canonHeaders.WriteString(k + ":" + headers[k] + "\n")
	}
	signed := strings.Join(names, ";")

	q := r.URL.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var qs []string
	for _, k := range keys {
		vs := append([]string(nil), q[k]...)
		sort.Strings(vs)
		for _, v := range vs {
			qs = append(qs, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	p := r.URL.EscapedPath()
	if p == "" {
		p = "/"
	}
	if raw, err := url.PathUnescape(p); err == nil {
		p = uriEncode(raw, true)
	}
	canon := strings.Join([]string{r.Method, p, strings.Join(qs, "&"), canonHeaders.String(), signed, payloadHash}, "\n")
	scope := day + "/" + region + "/s3/aws4_request"
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + sha256Hex([]byte(canon))
	k := hmacSHA(hmacSHA(hmacSHA(hmacSHA([]byte("AWS4"+secret), day), region), "s3"), "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, sts))
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+keyID+"/"+scope+",SignedHeaders="+signed+",Signature="+sig)
}

// objectURL addresses key below the configured prefix; an empty key
// addresses the bucket itself.
func (t *s3Target) objectURL(key string, q url.Values) *url.URL {
	u := *t.base
	full := ""
	if key != "" {
		full = t.c.Prefix + key
	}
	if t.c.PathStyle {
		u.Path = "/" + t.c.Bucket + "/" + full
	} else {
		u.Host = t.c.Bucket + "." + u.Host
		u.Path = "/" + full
	}
	u.RawPath = uriEncode(u.Path, true)
	u.RawQuery = strings.ReplaceAll(q.Encode(), "+", "%20")
	return &u
}

func (t *s3Target) do(ctx context.Context, method string, u *url.URL, body []byte, hdr http.Header) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.ContentLength = int64(len(body))
	signV4(req, t.c.AccessKeyID, t.secret, t.c.Region, sha256Hex(body), t.now())
	resp, err := t.http.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound && method != http.MethodPost {
			return nil, ErrNotExist
		}
		var e struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		_ = xml.Unmarshal(b, &e)
		return nil, fmt.Errorf("s3 %s: %s %s %s", method, resp.Status, e.Code, e.Message)
	}
	return resp, nil
}

func (t *s3Target) Put(ctx context.Context, name string, r io.Reader) (int64, error) {
	if err := checkName(name); err != nil {
		return 0, err
	}
	buf := make([]byte, s3PartSize)
	n, err := io.ReadFull(r, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return 0, err
	}
	if n < s3PartSize {
		resp, err := t.do(ctx, http.MethodPut, t.objectURL(name, nil), buf[:n], nil)
		if err != nil {
			return 0, err
		}
		resp.Body.Close()
		return int64(n), nil
	}
	// Multipart: the object appears only when the upload is completed.
	resp, err := t.do(ctx, http.MethodPost, t.objectURL(name, url.Values{"uploads": {""}}), nil, nil)
	if err != nil {
		return 0, err
	}
	var init struct {
		UploadID string `xml:"UploadId"`
	}
	err = xml.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&init)
	resp.Body.Close()
	if err != nil || init.UploadID == "" {
		return 0, fmt.Errorf("s3: invalid multipart response")
	}
	abort := func() {
		if resp, err := t.do(context.WithoutCancel(ctx), http.MethodDelete, t.objectURL(name, url.Values{"uploadId": {init.UploadID}}), nil, nil); err == nil {
			resp.Body.Close()
		}
	}
	type part struct {
		Number int    `xml:"PartNumber"`
		ETag   string `xml:"ETag"`
	}
	var parts []part
	var total int64
	for num := 1; n > 0; num++ {
		if num > 10000 {
			abort()
			return total, errors.New("s3: object too large")
		}
		resp, err := t.do(ctx, http.MethodPut, t.objectURL(name, url.Values{"partNumber": {strconv.Itoa(num)}, "uploadId": {init.UploadID}}), buf[:n], nil)
		if err != nil {
			abort()
			return total, err
		}
		resp.Body.Close()
		parts = append(parts, part{num, resp.Header.Get("ETag")})
		total += int64(n)
		n, err = io.ReadFull(r, buf)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
			abort()
			return total, err
		}
	}
	body, _ := xml.Marshal(struct {
		XMLName xml.Name `xml:"CompleteMultipartUpload"`
		Parts   []part   `xml:"Part"`
	}{Parts: parts})
	resp, err = t.do(ctx, http.MethodPost, t.objectURL(name, url.Values{"uploadId": {init.UploadID}}), body, http.Header{"Content-Type": {"application/xml"}})
	if err != nil {
		abort()
		return total, err
	}
	defer resp.Body.Close()
	// S3 may report a failed completion with status 200 and an error body.
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if bytes.Contains(b, []byte("<Error>")) {
		abort()
		return total, fmt.Errorf("s3: completing the upload failed")
	}
	return total, nil
}

func (t *s3Target) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	if err := checkName(name); err != nil {
		return nil, err
	}
	resp, err := t.do(ctx, http.MethodGet, t.objectURL(name, nil), nil, nil)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func (t *s3Target) list(ctx context.Context, prefix, token string, max int) ([]ObjectInfo, error) {
	q := url.Values{"list-type": {"2"}, "prefix": {t.c.Prefix + prefix}}
	if max > 0 {
		q.Set("max-keys", strconv.Itoa(max))
	}
	var out []ObjectInfo
	for {
		if token != "" {
			q.Set("continuation-token", token)
		}
		u := t.objectURL("", q)
		resp, err := t.do(ctx, http.MethodGet, u, nil, nil)
		if errors.Is(err, ErrNotExist) {
			return nil, targetErr("bucket %s does not exist", t.c.Bucket)
		}
		if err != nil {
			return nil, err
		}
		var res struct {
			Contents []struct {
				Key  string `xml:"Key"`
				Size int64  `xml:"Size"`
			} `xml:"Contents"`
			IsTruncated bool   `xml:"IsTruncated"`
			NextToken   string `xml:"NextContinuationToken"`
		}
		err = xml.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&res)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("s3: invalid list response: %w", err)
		}
		for _, c := range res.Contents {
			k := strings.TrimPrefix(c.Key, t.c.Prefix)
			if objectNameRe.MatchString(k) {
				out = append(out, ObjectInfo{Name: k, Size: c.Size})
			}
		}
		if !res.IsTruncated || res.NextToken == "" || max > 0 {
			break
		}
		token = res.NextToken
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (t *s3Target) List(ctx context.Context, prefix string) ([]ObjectInfo, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	return t.list(ctx, prefix, "", 0)
}

func (t *s3Target) Delete(ctx context.Context, name string) error {
	if err := checkName(name); err != nil {
		return err
	}
	resp, err := t.do(ctx, http.MethodDelete, t.objectURL(name, nil), nil, nil)
	if errors.Is(err, ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

func (t *s3Target) Close() error {
	t.http.CloseIdleConnections()
	return nil
}
