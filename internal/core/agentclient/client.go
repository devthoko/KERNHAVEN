// Package agentclient is the Core's client for kernhaven-agent: it signs a
// grant for every call (M4, ADR-0003).
package agentclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Key file names inside the Core data directory.
const (
	PrivateKeyFile = "agent-grant.key"
	PublicKeyFile  = "agent-grant.pub"
)

// ErrUnavailable means the agent could not be reached.
var ErrUnavailable = errors.New("host agent unavailable")

// Error is an error reported by the agent.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return fmt.Sprintf("agent: %s: %s", e.Code, e.Message) }

// LoadOrCreateKey returns the grant signing key, creating it (and the public
// key file the agent reads) on first use.
func LoadOrCreateKey(dataDir string) (ed25519.PrivateKey, error) {
	priv := filepath.Join(dataDir, PrivateKeyFile)
	key, err := agentproto.ReadPrivateKey(priv)
	if err == nil {
		return key, agentproto.WritePublicKey(filepath.Join(dataDir, PublicKeyFile), key.Public().(ed25519.PublicKey))
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := agentproto.WritePrivateKey(priv, key); err != nil {
		return nil, err
	}
	return key, agentproto.WritePublicKey(filepath.Join(dataDir, PublicKeyFile), pub)
}

// Client calls the agent.
type Client struct {
	socket string
	key    ed25519.PrivateKey
	http   *http.Client
	now    func() time.Time
}

// New returns a client for the agent socket.
func New(socket string, key ed25519.PrivateKey) *Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socket)
		},
		// One connection per call: a kept-alive connection to an agent that
		// restarted in between would fail the next call (unix sockets are
		// cheap to open).
		DisableKeepAlives: true,
	}
	return &Client{socket: socket, key: key, http: &http.Client{Transport: tr}, now: time.Now}
}

// Call is one authorized operation.
type Call struct {
	Op        string
	Params    any // nil for no parameters
	Actor     string
	RequestID string
}

// Do signs a grant for c and runs it; the result is decoded into out.
func (cl *Client) Do(ctx context.Context, c Call, out any) error {
	params := []byte("null")
	if c.Params != nil {
		var err error
		if params, err = json.Marshal(c.Params); err != nil {
			return err
		}
	}
	now := cl.now()
	grant, err := agentproto.Sign(cl.key, agentproto.Grant{
		Op: c.Op, ParamsSHA256: agentproto.ParamsHash(params), Actor: c.Actor, RequestID: c.RequestID,
		Nonce: agentproto.NewNonce(), IssuedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(30 * time.Second).UnixMilli(),
	})
	if err != nil {
		return err
	}
	body, err := json.Marshal(agentproto.Request{Grant: grant, Params: params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/v1/op/"+c.Op, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := cl.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		var eb agentproto.ErrorBody
		_ = json.Unmarshal(data, &eb)
		return &Error{Status: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
	}
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("agent: malformed response: %w", err)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}

// Stream is the response of a stream operation. The caller closes Body.
type Stream struct {
	Meta []byte // decoded X-Kernhaven-Meta, if any
	Body io.ReadCloser
}

// DoStream runs a stream operation (M10): grant and parameters travel in
// headers, body (may be nil) is sent as the request body.
func (cl *Client) DoStream(ctx context.Context, c Call, body io.Reader) (*Stream, error) {
	params := []byte("null")
	if c.Params != nil {
		var err error
		if params, err = json.Marshal(c.Params); err != nil {
			return nil, err
		}
	}
	now := cl.now()
	grant, err := agentproto.Sign(cl.key, agentproto.Grant{
		Op: c.Op, ParamsSHA256: agentproto.ParamsHash(params), Actor: c.Actor, RequestID: c.RequestID,
		Nonce: agentproto.NewNonce(), IssuedAtMS: now.UnixMilli(), ExpiresAtMS: now.Add(30 * time.Second).UnixMilli(),
	})
	if err != nil {
		return nil, err
	}
	if body == nil {
		body = http.NoBody
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agent/v1/stream/"+c.Op, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set(agentproto.HeaderGrant, grant)
	req.Header.Set(agentproto.HeaderParams, base64.StdEncoding.EncodeToString(params))
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := cl.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		var eb agentproto.ErrorBody
		_ = json.Unmarshal(data, &eb)
		return nil, &Error{Status: resp.StatusCode, Code: eb.Error.Code, Message: eb.Error.Message}
	}
	s := &Stream{Body: resp.Body}
	if m := resp.Header.Get(agentproto.HeaderMeta); m != "" {
		s.Meta, _ = base64.StdEncoding.DecodeString(m)
	}
	return s, nil
}

// DoStreamJSON runs a stream operation whose response is a JSON result.
func (cl *Client) DoStreamJSON(ctx context.Context, c Call, body io.Reader, out any) error {
	s, err := cl.DoStream(ctx, c, body)
	if err != nil {
		return err
	}
	defer s.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
	}
	if err := json.NewDecoder(io.LimitReader(s.Body, 1<<20)).Decode(&env); err != nil {
		return fmt.Errorf("agent: malformed response: %w", err)
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(env.Result, out)
}
