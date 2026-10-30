// Package catalog parses and verifies signed app catalogs (ADR-0020).
package catalog

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devthoko/KERNHAVEN/internal/compose"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// Format is the only envelope format accepted.
const Format = "kernhaven-catalog/v1"

// Limits.
const (
	MaxEnvelope   = 4 << 20
	MaxApps       = 1000
	MaxFields     = 32
	MaxCompose    = 64 << 10
	MaxValidity   = 400 * 24 * time.Hour
	maxText       = 200
	maxDesc       = 4000
	maxCategories = 5
)

// Errors returned by Open. They wrap more specific messages.
var (
	ErrFormat    = errors.New("not a Kernhaven catalog")
	ErrSignature = errors.New("the catalog signature is not valid for this source's key")
	ErrRollback  = errors.New("the catalog is older than the one already accepted")
	ErrExpired   = errors.New("the catalog has expired")
	ErrInvalid   = errors.New("the catalog is invalid")
)

// Envelope is the signed document.
type Envelope struct {
	Format    string `json:"format"`
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// Catalog is the signed payload.
type Catalog struct {
	Name    string    `json:"name"`
	Serial  int64     `json:"serial"`
	Expires time.Time `json:"expires,omitzero"`
	Apps    []App     `json:"apps"`
}

// App is one catalog entry.
type App struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Version     string      `json:"version"`
	Summary     string      `json:"summary"`
	Description string      `json:"description,omitempty"`
	Categories  []string    `json:"categories"`
	Homepage    string      `json:"homepage,omitempty"`
	Compose     string      `json:"compose"`
	Fields      []Field     `json:"fields"`
	Web         *Web        `json:"web,omitempty"`
	Exceptions  []Exception `json:"exceptions"`
}

// Field is one configuration value; Name is the Compose variable.
type Field struct {
	Name        string   `json:"name"`
	Label       string   `json:"label"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type"`
	Default     string   `json:"default,omitempty"`
	Required    bool     `json:"required,omitempty"`
	Options     []string `json:"options,omitempty"`
	Min         *int64   `json:"min,omitempty"`
	Max         *int64   `json:"max,omitempty"`
	Generate    string   `json:"generate,omitempty"`
}

// Field types.
const (
	TypeText     = "text"
	TypePassword = "password"
	TypeNumber   = "number"
	TypeBoolean  = "boolean"
	TypeSelect   = "select"
)

// Generators for generated values.
const (
	GeneratePassword = "password"
	GenerateHex32    = "hex32"
)

// Secret reports whether the value is stored as a secret.
func (f Field) Secret() bool { return f.Type == TypePassword }

// Web points to the app's web interface.
type Web struct {
	Service string `json:"service"`
	Port    int    `json:"port"`
}

// Exception is a policy exception the app declares.
type Exception struct {
	Service string `json:"service"`
	Rule    string `json:"rule"`
	Reason  string `json:"reason"`
}

// State is what a source has accepted before (zero for a new source).
type State struct {
	Serial        int64
	PayloadSHA256 string
}

// Verified is an accepted catalog.
type Verified struct {
	Catalog       Catalog
	PayloadSHA256 string
}

var (
	idRe       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)
	fieldRe    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	categoryRe = regexp.MustCompile(`^[\p{L}\p{N}][\p{L}\p{N} &-]{0,31}$`)
)

// KeyID returns the short fingerprint of a public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// ParsePublicKey decodes a base64 Ed25519 public key.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("the trust key must be a base64-encoded Ed25519 public key (32 bytes)")
	}
	return ed25519.PublicKey(b), nil
}

func signedMessage(payload []byte) []byte {
	return append([]byte(Format+"\n"), payload...)
}

// Sign validates c and returns the signed envelope.
func Sign(key ed25519.PrivateKey, c Catalog) ([]byte, error) {
	payload, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := c.validate(true); err != nil {
		return nil, err
	}
	env := Envelope{
		Format:    Format,
		KeyID:     KeyID(key.Public().(ed25519.PublicKey)),
		Payload:   base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, signedMessage(payload))),
	}
	return json.MarshalIndent(env, "", "  ")
}

func strictDecode(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

// Open verifies an envelope against pub and the source's previous state and
// returns the validated catalog. Nothing is accepted partially.
func Open(data []byte, pub ed25519.PublicKey, prev State, now time.Time) (Verified, error) {
	if len(data) > MaxEnvelope {
		return Verified{}, fmt.Errorf("%w: larger than %d MiB", ErrFormat, MaxEnvelope>>20)
	}
	var env Envelope
	if err := strictDecode(data, &env); err != nil || env.Format != Format {
		return Verified{}, ErrFormat
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return Verified{}, ErrFormat
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(pub, signedMessage(payload), sig) {
		if env.KeyID != "" && env.KeyID != KeyID(pub) {
			return Verified{}, fmt.Errorf("%w (signed with key %s, expected %s)", ErrSignature, truncate(env.KeyID, 16), KeyID(pub))
		}
		return Verified{}, ErrSignature
	}
	var c Catalog
	if err := strictDecode(payload, &c); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	switch {
	case c.Serial < prev.Serial:
		return Verified{}, fmt.Errorf("%w (serial %d, accepted %d)", ErrRollback, c.Serial, prev.Serial)
	case c.Serial == prev.Serial && prev.PayloadSHA256 != "" && digest != prev.PayloadSHA256:
		return Verified{}, fmt.Errorf("%w: serial %d was already accepted with different content", ErrRollback, c.Serial)
	case !c.Expires.After(now):
		return Verified{}, fmt.Errorf("%w (%s)", ErrExpired, c.Expires.UTC().Format(time.RFC3339))
	case c.Expires.After(now.Add(MaxValidity)):
		return Verified{}, fmt.Errorf("%w: expires more than 400 days ahead", ErrInvalid)
	}
	if err := c.validate(true); err != nil {
		return Verified{}, err
	}
	return Verified{Catalog: c, PayloadSHA256: digest}, nil
}

// OpenBuiltin validates a catalog that ships inside the Kernhaven binary
// (ADR-0034). It has no signature of its own: the release signature covers
// the binary, and with it this payload. It has no expiry either, because it
// is replaced by the next Kernhaven version, not by a download. Every other
// check of Open applies.
func OpenBuiltin(payload []byte) (Verified, error) {
	var c Catalog
	if err := strictDecode(payload, &c); err != nil {
		return Verified{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if !c.Expires.IsZero() {
		return Verified{}, fmt.Errorf("%w: a built-in catalog has no expiry", ErrInvalid)
	}
	if err := c.validate(false); err != nil {
		return Verified{}, err
	}
	sum := sha256.Sum256(payload)
	return Verified{Catalog: c, PayloadSHA256: hex.EncodeToString(sum[:])}, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func plain(s string, max int, multiline bool) bool {
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return false
	}
	for _, r := range s {
		if r < 0x20 && !(multiline && (r == '\n' || r == '\t')) || r == 0x7f {
			return false
		}
	}
	return true
}

func (c Catalog) validate(signed bool) error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }
	if strings.TrimSpace(c.Name) == "" || !plain(c.Name, maxText, false) {
		add("name: 1-%d printable characters required", maxText)
	}
	if c.Serial < 1 {
		add("serial: must be at least 1")
	}
	if signed && c.Expires.IsZero() {
		add("expires: required")
	}
	if len(c.Apps) > MaxApps {
		add("apps: at most %d", MaxApps)
	}
	seen := map[string]bool{}
	for i, a := range c.Apps {
		prefix := fmt.Sprintf("apps[%d]", i)
		if a.ID != "" {
			prefix = "app " + a.ID
		}
		if seen[a.ID] {
			add("%s: duplicate id", prefix)
		}
		seen[a.ID] = true
		for _, e := range a.validate() {
			add("%s: %s", prefix, e)
		}
		if len(errs) > 20 {
			break
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(errs, "; "))
	}
	return nil
}

func (a App) validate() []string {
	var errs []string
	add := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	if !idRe.MatchString(a.ID) {
		add("id must be 1-31 characters: lowercase letters, digits and -")
	}
	if strings.TrimSpace(a.Name) == "" || !plain(a.Name, 64, false) {
		add("name: 1-64 printable characters required")
	}
	if strings.TrimSpace(a.Version) == "" || !plain(a.Version, 64, false) {
		add("version: 1-64 printable characters required")
	}
	if !plain(a.Summary, maxText, false) {
		add("summary: at most %d printable characters", maxText)
	}
	if !plain(a.Description, maxDesc, true) {
		add("description: at most %d characters", maxDesc)
	}
	if len(a.Categories) > maxCategories {
		add("categories: at most %d", maxCategories)
	}
	for _, c := range a.Categories {
		if !categoryRe.MatchString(c) {
			add("category %q is invalid", c)
		}
	}
	if a.Homepage != "" {
		u, err := url.Parse(a.Homepage)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || len(a.Homepage) > 500 {
			add("homepage must be an https URL")
		}
	}
	if len(a.Compose) == 0 || len(a.Compose) > MaxCompose {
		add("compose: 1 byte to %d KiB required", MaxCompose>>10)
		return errs
	}
	if len(a.Fields) > MaxFields {
		add("fields: at most %d", MaxFields)
	}
	names := map[string]bool{}
	for _, f := range a.Fields {
		if names[f.Name] {
			add("field %s: duplicate", f.Name)
		}
		names[f.Name] = true
		for _, e := range f.validate() {
			add("field %s: %s", f.Name, e)
		}
	}
	if len(errs) > 0 {
		return errs
	}
	proj, cerrs := compose.Parse([]byte(a.Compose), "catalog-check", a.Placeholders())
	if cerrs != nil {
		for i, e := range cerrs {
			if i == 5 {
				break
			}
			add("compose: %s", e.String())
		}
		return errs
	}
	services := map[string]bool{}
	for _, s := range proj.Services {
		services[s.Name] = true
		if err := policy.Validate(s.Spec); err != nil {
			add("compose: service %s: %v", s.Name, err)
		}
	}
	if a.Web != nil && (!services[a.Web.Service] || a.Web.Port < 1 || a.Web.Port > 65535) {
		add("web: service must exist and port must be 1-65535")
	}
	for _, e := range a.Exceptions {
		if !services[e.Service] || !policy.Exemptible(e.Rule) {
			add("exception %s/%s: unknown service or rule that cannot be exempted", e.Service, e.Rule)
		}
		if n := utf8.RuneCountInString(strings.TrimSpace(e.Reason)); n < 10 || !plain(e.Reason, 500, false) {
			add("exception %s/%s: reason of 10 to 500 characters required", e.Service, e.Rule)
		}
	}
	return errs
}

func (f Field) validate() []string {
	var errs []string
	if !fieldRe.MatchString(f.Name) {
		errs = append(errs, "name must be an upper-case variable name")
	}
	if strings.TrimSpace(f.Label) == "" || !plain(f.Label, 100, false) || !plain(f.Description, 500, false) {
		errs = append(errs, "label (1-100) and description (≤500) must be printable text")
	}
	if f.Generate != "" && f.Generate != GeneratePassword && f.Generate != GenerateHex32 {
		errs = append(errs, "generate must be password or hex32")
	}
	if f.Generate != "" && f.Type != TypeText && f.Type != TypePassword {
		errs = append(errs, "only text and password fields can be generated")
	}
	switch f.Type {
	case TypeText, TypePassword:
	case TypeNumber:
		if f.Min != nil && f.Max != nil && *f.Min > *f.Max {
			errs = append(errs, "min is greater than max")
		}
	case TypeBoolean:
	case TypeSelect:
		if len(f.Options) == 0 || len(f.Options) > 50 {
			errs = append(errs, "select needs 1-50 options")
		}
		for _, o := range f.Options {
			if o == "" || !plain(o, 100, false) {
				errs = append(errs, "options must be printable text")
				break
			}
		}
	default:
		errs = append(errs, "type must be text, password, number, boolean or select")
	}
	if f.Default != "" {
		if f.Type == TypePassword {
			errs = append(errs, "password fields cannot have a default")
		} else if err := f.Check(f.Default); err != nil {
			errs = append(errs, "default: "+err.Error())
		}
	}
	return errs
}

// MaxValue is the longest accepted field value.
const MaxValue = 4096

// Check validates a value for the field.
func (f Field) Check(v string) error {
	if !plain(v, MaxValue, false) {
		return fmt.Errorf("must be printable text of at most %d characters", MaxValue)
	}
	switch f.Type {
	case TypeNumber:
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			return errors.New("must be a whole number")
		}
		if (f.Min != nil && n < *f.Min) || (f.Max != nil && n > *f.Max) {
			return errors.New("is out of range")
		}
	case TypeBoolean:
		if v != "true" && v != "false" {
			return errors.New("must be true or false")
		}
	case TypeSelect:
		for _, o := range f.Options {
			if o == v {
				return nil
			}
		}
		return errors.New("is not one of the options")
	case TypePassword:
		if v != "" && utf8.RuneCountInString(v) < 8 {
			return errors.New("must be at least 8 characters")
		}
	}
	return nil
}

// Placeholders returns a value for every field that satisfies its type, used
// to check the Compose file before any user input exists.
func (a App) Placeholders() map[string]string {
	m := map[string]string{}
	for _, f := range a.Fields {
		v := f.Default
		if v == "" {
			switch f.Type {
			case TypeNumber:
				v = "1"
				if f.Min != nil {
					v = strconv.FormatInt(*f.Min, 10)
				}
			case TypeBoolean:
				v = "false"
			case TypeSelect:
				v = f.Options[0]
			default:
				v = "placeholder"
			}
		}
		m[f.Name] = v
	}
	return m
}
