package identity

import (
	"bufio"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// HashParams are Argon2id parameters (ADR-0015).
type HashParams struct {
	Memory  uint32 // KiB
	Time    uint32
	Threads uint8
}

// DefaultHashParams balance attack cost against memory on small arm64 hosts.
var DefaultHashParams = HashParams{Memory: 64 * 1024, Time: 2, Threads: 2}

const (
	saltLen = 16
	keyLen  = 32

	minPasswordRunes = 12
	maxPasswordBytes = 256
)

// Bounds applied when decoding stored hashes so a tampered row cannot make
// verification allocate unbounded memory.
const (
	maxMemoryKiB = 1 << 20
	maxTime      = 16
)

var b64 = base64.RawStdEncoding

func hashPassword(p HashParams, password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("malformed password hash")

func verifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var p HashParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return false, errBadHash
	}
	if p.Memory == 0 || p.Memory > maxMemoryKiB || p.Time == 0 || p.Time > maxTime || p.Threads == 0 {
		return false, errBadHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil || len(salt) < 8 {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

//go:embed common_passwords.txt
var commonPasswordsFile string

var commonPasswords = func() map[string]bool {
	m := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(commonPasswordsFile))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			m[strings.ToLower(line)] = true
		}
	}
	return m
}()

// CheckPasswordPolicy enforces the M2 password policy (NIST SP 800-63B style).
func CheckPasswordPolicy(username, password string) error {
	if !utf8.ValidString(password) {
		return &ValidationError{Field: "password", Message: "must be valid UTF-8"}
	}
	if utf8.RuneCountInString(password) < minPasswordRunes {
		return &ValidationError{Field: "password", Message: fmt.Sprintf("must be at least %d characters", minPasswordRunes)}
	}
	if len(password) > maxPasswordBytes {
		return &ValidationError{Field: "password", Message: fmt.Sprintf("must be at most %d bytes", maxPasswordBytes)}
	}
	lower := strings.ToLower(password)
	if username != "" && strings.Contains(lower, strings.ToLower(username)) {
		return &ValidationError{Field: "password", Message: "must not contain the username"}
	}
	distinct := map[rune]bool{}
	for _, r := range password {
		distinct[r] = true
	}
	if len(distinct) < 5 {
		return &ValidationError{Field: "password", Message: "must contain at least 5 different characters"}
	}
	if commonPasswords[lower] {
		return &ValidationError{Field: "password", Message: "is too common"}
	}
	return nil
}
