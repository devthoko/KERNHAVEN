// Package agentproto defines the wire protocol between kernhaven-core and
// kernhaven-agent (M4, ADR-0003): signed grants and the request envelope.
package agentproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Operation names. The agent registers exactly these (AT-M4-01).
const (
	OpAgentInfo         = "agent.info"
	OpDockerInfo        = "docker.info"
	OpContainersList    = "containers.list"
	OpContainersInspect = "containers.inspect"
	OpContainersStart   = "containers.start"
	OpContainersStop    = "containers.stop"
	OpContainersRestart = "containers.restart"

	// M6
	OpContainersCreate  = "containers.create"
	OpContainersRemove  = "containers.remove"
	OpContainersPause   = "containers.pause"
	OpContainersUnpause = "containers.unpause"
	OpContainersLogs    = "containers.logs"
	OpImagesList        = "images.list"
	OpImagesPull        = "images.pull"
	OpImagesRemove      = "images.remove"
	OpImagesPrune       = "images.prune"
	OpVolumesList       = "volumes.list"
	OpVolumesCreate     = "volumes.create"
	OpVolumesRemove     = "volumes.remove"
	OpNetworksList      = "networks.list"
	OpNetworksCreate    = "networks.create"
	OpNetworksRemove    = "networks.remove"
	OpVolumesCopy       = "volumes.copy"
	OpStorageInventory  = "storage.inventory"
	OpStorageFormat     = "storage.format"
	OpStorageMount      = "storage.mount"
	OpStorageUnmount    = "storage.unmount"
)

// Grant limits.
const (
	MaxGrantLifetime = 60 * time.Second
	ClockSkew        = 5 * time.Second
	MaxRequestBytes  = 64 << 10
)

// Grant authorizes one operation with exactly one parameter document.
type Grant struct {
	Op           string `json:"op"`
	ParamsSHA256 string `json:"params_sha256"`
	Actor        string `json:"actor"`
	RequestID    string `json:"request_id"`
	Nonce        string `json:"nonce"`
	IssuedAtMS   int64  `json:"iat"`
	ExpiresAtMS  int64  `json:"exp"`
}

// Request is the body of POST /v1/op/{op}.
type Request struct {
	Grant  string          `json:"grant"`
	Params json.RawMessage `json:"params"`
}

// ErrorBody is the agent's error response.
type ErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Error codes returned by the agent.
const (
	CodeInvalidRequest    = "invalid_request"
	CodeInvalidGrant      = "invalid_grant"
	CodeUnknownOp         = "unknown_operation"
	CodeInvalidParams     = "invalid_params"
	CodeNotFound          = "not_found"
	CodeConflict          = "conflict"
	CodeDockerUnavailable = "docker_unavailable"
	CodePolicyViolation   = "policy_violation"
	CodeInternal          = "internal_error"
)

// ParamsHash is the hex SHA-256 of the exact parameter bytes sent.
func ParamsHash(params []byte) string {
	h := sha256.Sum256(params)
	return hex.EncodeToString(h[:])
}

// NewNonce returns a random 128-bit nonce.
func NewNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("agentproto: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

var b64 = base64.RawURLEncoding

// Sign encodes and signs g as "<payload>.<signature>" (base64url).
func Sign(key ed25519.PrivateKey, g Grant) (string, error) {
	payload, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(payload) + "." + b64.EncodeToString(ed25519.Sign(key, payload)), nil
}

// Verification errors.
var (
	ErrMalformedGrant = errors.New("malformed grant")
	ErrBadSignature   = errors.New("grant signature invalid")
	ErrExpired        = errors.New("grant expired or not yet valid")
	ErrLifetime       = errors.New("grant lifetime too long")
)

// Verify checks the signature and validity window and returns the grant.
// Callers must still compare Op and ParamsSHA256 and check the nonce.
func Verify(pub ed25519.PublicKey, token string, now time.Time) (Grant, error) {
	if len(token) > 4096 {
		return Grant{}, ErrMalformedGrant
	}
	p, s, ok := strings.Cut(token, ".")
	if !ok {
		return Grant{}, ErrMalformedGrant
	}
	payload, err := b64.DecodeString(p)
	if err != nil {
		return Grant{}, ErrMalformedGrant
	}
	sig, err := b64.DecodeString(s)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return Grant{}, ErrMalformedGrant
	}
	if !ed25519.Verify(pub, payload, sig) {
		return Grant{}, ErrBadSignature
	}
	var g Grant
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&g); err != nil {
		return Grant{}, ErrMalformedGrant
	}
	if g.Op == "" || g.Nonce == "" || len(g.ParamsSHA256) != 64 {
		return Grant{}, ErrMalformedGrant
	}
	if g.ExpiresAtMS-g.IssuedAtMS > MaxGrantLifetime.Milliseconds() || g.ExpiresAtMS < g.IssuedAtMS {
		return Grant{}, ErrLifetime
	}
	n := now.UnixMilli()
	if n+ClockSkew.Milliseconds() < g.IssuedAtMS || n-ClockSkew.Milliseconds() > g.ExpiresAtMS {
		return Grant{}, ErrExpired
	}
	return g, nil
}

// Key files hold one base64 (standard) line.

// WritePrivateKey writes key to path with mode 0600 (no overwrite).
func WritePrivateKey(path string, key ed25519.PrivateKey) error {
	return writeKey(path, key, 0o600)
}

// WritePublicKey writes key to path with mode 0644 (overwrites).
func WritePublicKey(path string, key ed25519.PublicKey) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.StdEncoding.EncodeToString(key)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeKey(path string, key []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// ReadPrivateKey reads a key written by WritePrivateKey and refuses files
// readable by group or others.
func ReadPrivateKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: mode %#o is too open; expected 0600", path, fi.Mode().Perm())
	}
	b, err := readKeyFile(path, ed25519.PrivateKeySize)
	return ed25519.PrivateKey(b), err
}

// ReadPublicKey reads a key written by WritePublicKey.
func ReadPublicKey(path string) (ed25519.PublicKey, error) {
	b, err := readKeyFile(path, ed25519.PublicKeySize)
	return ed25519.PublicKey(b), err
}

func readKeyFile(path string, size int) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != size {
		return nil, fmt.Errorf("%s: not a valid ed25519 key file", path)
	}
	return b, nil
}
