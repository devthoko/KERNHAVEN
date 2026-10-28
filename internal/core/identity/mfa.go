package identity

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP uses HMAC-SHA1; authenticator apps expect it
	"crypto/sha256"
	"database/sql"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

// MFA errors.
var (
	// ErrStepUpRequired means the action needs a recent strong authentication.
	ErrStepUpRequired = errors.New("confirm it is you to continue")
	// ErrLastFactor protects the last second factor of a user whose role
	// requires MFA, and the last passkey of a passkey-only account.
	ErrLastFactor = errors.New("this is the last sign-in method of this kind that the account needs")
	// ErrChallenge covers unknown, expired and exhausted challenges.
	ErrChallenge = errors.New("the sign-in attempt has expired; start again")
)

// Timing and sizes.
const (
	StepUpWindow       = 10 * time.Minute
	challengeTTL       = 5 * time.Minute
	challengeAttempts  = 5
	totpPeriod         = 30
	totpDigits         = 6
	recoveryCodeCount  = 10
	challengeMFA       = "mfa"
	challengePasskey   = "passkey_login"
	challengeRegister  = "passkey_register"
	challengeStepUpKey = "step_up_passkey"
	challengeMFAKey    = "mfa_passkey"
)

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---- TOTP (RFC 6238) ----

// totpCode computes the code for a time step (RFC 4226 dynamic truncation).
func totpCode(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", totpDigits, v%1000000)
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func totpContext(userID int64) string { return fmt.Sprintf("user:%d/totp", userID) }

func normalizeCode(c string) string {
	return strings.ToUpper(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(c)))
}

// verifyTOTP accepts a code for the current step ±1 that is newer than the
// last accepted step (replay protection) and records its step.
func (s *Service) verifyTOTP(ctx context.Context, tx *sql.Tx, userID int64, code string, confirmedOnly bool) (bool, error) {
	if s.cfg.Box == nil {
		return false, errors.New("identity: no secret box configured")
	}
	var ct []byte
	var confirmed int
	var last int64
	err := tx.QueryRowContext(ctx, `SELECT secret, confirmed, last_step FROM user_totp WHERE user_id = ?`, userID).Scan(&ct, &confirmed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if confirmedOnly && confirmed == 0 {
		return false, nil
	}
	secret, err := s.cfg.Box.Open(ct, totpContext(userID))
	if err != nil {
		return false, err
	}
	code = normalizeCode(code)
	if len(code) != totpDigits {
		return false, nil
	}
	now := s.now().Unix() / totpPeriod
	for _, st := range []int64{now - 1, now, now + 1} {
		if st <= last {
			continue
		}
		if hmac.Equal([]byte(totpCode([]byte(secret), st)), []byte(code)) {
			_, err := tx.ExecContext(ctx, `UPDATE user_totp SET last_step = ? WHERE user_id = ?`, st, userID)
			return err == nil, err
		}
	}
	return false, nil
}

// ---- recovery codes ----

func hashCode(c string) string {
	sum := sha256.Sum256([]byte(normalizeCode(c)))
	return hex.EncodeToString(sum[:])
}

func newRecoveryCodes() []string {
	out := make([]string, recoveryCodeCount)
	for i := range out {
		b := make([]byte, 7)
		_, _ = rand.Read(b)
		c := b32.EncodeToString(b)[:10]
		out[i] = c[:5] + "-" + c[5:]
	}
	return out
}

func (s *Service) replaceRecoveryCodes(ctx context.Context, tx *sql.Tx, userID int64) ([]string, error) {
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return nil, err
	}
	codes := newRecoveryCodes()
	for _, c := range codes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (?, ?)`, userID, hashCode(c)); err != nil {
			return nil, err
		}
	}
	return codes, nil
}

func (s *Service) useRecoveryCode(ctx context.Context, tx *sql.Tx, userID int64, code string) (bool, error) {
	res, err := tx.ExecContext(ctx, `UPDATE user_recovery_codes SET used_ms = ? WHERE user_id = ? AND code_hash = ? AND used_ms = 0`,
		s.nowMS(), userID, hashCode(code))
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// verifySecondFactor checks a TOTP or recovery code.
func (s *Service) verifySecondFactor(ctx context.Context, tx *sql.Tx, userID int64, code, recovery string) (string, bool, error) {
	if recovery != "" {
		ok, err := s.useRecoveryCode(ctx, tx, userID, recovery)
		return "recovery_code", ok, err
	}
	ok, err := s.verifyTOTP(ctx, tx, userID, code, true)
	return "totp", ok, err
}

// ---- factors and policy ----

// methods lists the second factors a user can sign in with.
func (s *Service) methods(ctx context.Context, q dbtx, userID int64) ([]string, error) {
	var totp, passkeys, codes int
	if err := q.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM user_totp WHERE user_id = ? AND confirmed = 1),
		(SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?),
		(SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = ? AND used_ms = 0)`, userID, userID, userID).Scan(&totp, &passkeys, &codes); err != nil {
		return nil, err
	}
	var out []string
	if totp > 0 {
		out = append(out, "totp")
	}
	if passkeys > 0 {
		out = append(out, "passkey")
	}
	if len(out) > 0 && codes > 0 {
		out = append(out, "recovery_code")
	}
	return out, nil
}

func (s *Service) mfaRequired(ctx context.Context, q dbtx, role authz.Role) (bool, error) {
	var req int
	err := q.QueryRowContext(ctx, `SELECT required FROM mfa_policy WHERE role = ?`, string(role)).Scan(&req)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return req == 1, err
}

// ---- challenges ----

func (s *Service) newChallenge(ctx context.Context, q dbtx, userID int64, kind, data string) (string, error) {
	tok := randomToken(32)
	var uid any
	if userID > 0 {
		uid = userID
	}
	_, _ = q.ExecContext(ctx, `DELETE FROM auth_challenges WHERE expires_ms < ?`, s.nowMS())
	_, err := q.ExecContext(ctx, `INSERT INTO auth_challenges (id, user_id, kind, data, expires_ms) VALUES (?, ?, ?, ?, ?)`,
		sha256Hex(tok), uid, kind, data, s.now().Add(challengeTTL).UnixMilli())
	return tok, err
}

// challenge loads a challenge and counts the attempt.
func (s *Service) challenge(ctx context.Context, tx *sql.Tx, tok, kind string) (int64, string, error) {
	var uid sql.NullInt64
	var data string
	var attempts int
	var expires int64
	err := tx.QueryRowContext(ctx, `SELECT user_id, data, attempts, expires_ms FROM auth_challenges WHERE id = ? AND kind = ?`,
		sha256Hex(tok), kind).Scan(&uid, &data, &attempts, &expires)
	if errors.Is(err, sql.ErrNoRows) || err == nil && (expires < s.nowMS() || attempts >= challengeAttempts) {
		return 0, "", ErrChallenge
	}
	if err != nil {
		return 0, "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE auth_challenges SET attempts = attempts + 1 WHERE id = ?`, sha256Hex(tok)); err != nil {
		return 0, "", err
	}
	return uid.Int64, data, nil
}

func (s *Service) dropChallenge(ctx context.Context, q dbtx, tok string) {
	_, _ = q.ExecContext(ctx, `DELETE FROM auth_challenges WHERE id = ?`, sha256Hex(tok))
}

// CompleteMFA finishes a password sign-in with a TOTP or recovery code.
func (s *Service) CompleteMFA(ctx context.Context, m Meta, tok, code, recovery string) (LoginResult, error) {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return LoginResult{}, &RateLimitError{RetryAfter: wait}
	}
	var userID int64
	var method string
	var ok bool
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		if userID, _, err = s.challenge(ctx, tx, tok, challengeMFA); err != nil {
			return err
		}
		method, ok, err = s.verifySecondFactor(ctx, tx, userID, code, recovery)
		return err
	})
	if err != nil {
		return LoginResult{}, err
	}
	u, err := s.getUser(ctx, s.db, userID)
	if err != nil {
		return LoginResult{}, err
	}
	if !ok || u.Disabled {
		if err := s.registerFailure(ctx, m, userID, u.Username); err != nil {
			return LoginResult{}, err
		}
		s.record(ctx, withDetails(audit.Event{ActorID: userID, Actor: u.Username, Action: "auth.login", Target: targetUser(userID),
			Result: audit.Failure, RequestID: m.RequestID, IP: m.IP}, "stage", "second factor", "method", method))
		return LoginResult{}, ErrInvalidCredentials
	}
	s.dropChallenge(ctx, s.db, tok)
	return s.startSession(ctx, m, userID, u.Username, sessionKind{mfa: true}, "password+"+method)
}

// ---- step-up (AT-F09-04) ----

// RequireStepUp reports ErrStepUpRequired unless the session authenticated
// strongly within StepUpWindow.
func (s *Service) RequireStepUp(p *Principal) error {
	if p == nil || s.now().Sub(p.Session.StepUpAt) > StepUpWindow {
		return ErrStepUpRequired
	}
	return nil
}

// RequireStepUpRequest is RequireStepUp for the request's principal.
func (s *Service) RequireStepUpRequest(ctx context.Context) error {
	p, _ := FromContext(ctx)
	return s.RequireStepUp(p)
}

func (s *Service) markStepUp(ctx context.Context, q dbtx, p *Principal, mfa bool) error {
	now := s.nowMS()
	q2 := `UPDATE sessions SET step_up_ms = ? WHERE id = ?`
	args := []any{now, p.Session.ID}
	if mfa {
		q2 = `UPDATE sessions SET step_up_ms = ?, mfa_ms = ? WHERE id = ?`
		args = []any{now, now, p.Session.ID}
	}
	_, err := q.ExecContext(ctx, q2, args...)
	return err
}

// StepUp confirms the user with the strongest proof the account has besides
// a passkey: password plus TOTP or recovery code, or the password alone for
// accounts without MFA. Passkey-only accounts must use a passkey.
func (s *Service) StepUp(ctx context.Context, p *Principal, m Meta, password, code, recovery string) error {
	if ok, wait := s.limiter.allow(m.IP); !ok {
		return &RateLimitError{RetryAfter: wait}
	}
	var hash string
	var pwLogin int
	var locked int64
	if err := s.db.QueryRowContext(ctx, `SELECT password_hash, password_login, locked_until_ms FROM users WHERE id = ?`, p.User.ID).Scan(&hash, &pwLogin, &locked); err != nil {
		return err
	}
	methods, err := s.methods(ctx, s.db, p.User.ID)
	if err != nil {
		return err
	}
	fail := func(reason string) error {
		if err := s.registerFailure(ctx, m, p.User.ID, p.User.Username); err != nil {
			return err
		}
		s.record(ctx, withDetails(actorEvent(p, m, "auth.step_up", targetUser(p.User.ID), audit.Failure), "reason", reason))
		return ErrInvalidCredentials
	}
	if pwLogin == 0 {
		return fail("passkey-only account: use a passkey")
	}
	if locked > s.nowMS() {
		_, _ = s.verify(ctx, s.dummyHash, password)
		return fail("account locked")
	}
	if ok, err := s.verify(ctx, hash, password); err != nil {
		return err
	} else if !ok {
		return fail("wrong password")
	}
	needsSecond := len(methods) > 0
	method := "password"
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		if needsSecond {
			var ok bool
			var err error
			var m2 string
			if m2, ok, err = s.verifySecondFactor(ctx, tx, p.User.ID, code, recovery); err != nil {
				return err
			}
			if !ok {
				return ErrInvalidCredentials
			}
			method = "password+" + m2
		}
		if err := s.markStepUp(ctx, tx, p, needsSecond); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "auth.step_up", targetUser(p.User.ID), audit.Success), "method", method))
		return err
	})
	if errors.Is(err, ErrInvalidCredentials) {
		return fail("wrong second factor")
	}
	return err
}

// ---- self-service ----

// MFAStatus describes a user's sign-in methods.
type MFAStatus struct {
	TOTP              bool          `json:"totp"`
	RecoveryCodesLeft int           `json:"recovery_codes_left"`
	Passkeys          []PasskeyInfo `json:"passkeys"`
	PasswordLogin     bool          `json:"password_login"`
	RequiredByPolicy  bool          `json:"required_by_policy"`
}

// MFAStatus returns the sign-in methods of userID.
func (s *Service) MFAStatus(ctx context.Context, userID int64) (MFAStatus, error) {
	var st MFAStatus
	var totp, pw int
	var role authz.Role
	if err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM user_totp WHERE user_id = u.id AND confirmed = 1),
		(SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = u.id AND used_ms = 0),
		u.password_login, u.role FROM users u WHERE u.id = ?`, userID).Scan(&totp, &st.RecoveryCodesLeft, &pw, &role); err != nil {
		return st, err
	}
	st.TOTP, st.PasswordLogin = totp == 1, pw == 1
	var err error
	if st.Passkeys, err = s.passkeys(ctx, userID); err != nil {
		return st, err
	}
	st.RequiredByPolicy, err = s.mfaRequired(ctx, s.db, role)
	return st, err
}

// BeginTOTP creates an unconfirmed TOTP secret and returns it with the
// otpauth URL for authenticator apps.
func (s *Service) BeginTOTP(ctx context.Context, p *Principal) (string, string, error) {
	if s.cfg.Box == nil {
		return "", "", errors.New("identity: no secret box configured")
	}
	if err := s.requireFresh(p); err != nil {
		return "", "", err
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	secret := b32.EncodeToString(raw)
	ct, err := s.cfg.Box.Seal(string(raw), totpContext(p.User.ID))
	if err != nil {
		return "", "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO user_totp (user_id, secret, confirmed, last_step, created_ms) VALUES (?, ?, 0, 0, ?)
		ON CONFLICT (user_id) DO UPDATE SET secret = excluded.secret, confirmed = 0, last_step = 0, created_ms = excluded.created_ms
		WHERE user_totp.confirmed = 0`, p.User.ID, ct, s.nowMS()); err != nil {
		return "", "", err
	}
	var confirmed int
	_ = s.db.QueryRowContext(ctx, `SELECT confirmed FROM user_totp WHERE user_id = ?`, p.User.ID).Scan(&confirmed)
	if confirmed == 1 {
		return "", "", &ValidationError{Field: "totp", Message: "is already set up; remove it first"}
	}
	issuer := "Kernhaven"
	u := url.URL{Scheme: "otpauth", Host: "totp", Path: "/" + issuer + ":" + p.User.Username,
		RawQuery: url.Values{"secret": {secret}, "issuer": {issuer}, "digits": {strconv.Itoa(totpDigits)}, "period": {strconv.Itoa(totpPeriod)}}.Encode()}
	return secret, u.String(), nil
}

// requireFresh allows enrolment-only sessions (just signed in with the
// password) and otherwise requires step-up.
func (s *Service) requireFresh(p *Principal) error {
	return s.RequireStepUp(p)
}

// ConfirmTOTP activates TOTP with a first valid code and returns new
// recovery codes. An enrolment-only session becomes a full session.
func (s *Service) ConfirmTOTP(ctx context.Context, p *Principal, m Meta, code string) ([]string, error) {
	var codes []string
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		ok, err := s.verifyTOTP(ctx, tx, p.User.ID, code, false)
		if err != nil {
			return err
		}
		if !ok {
			return &ValidationError{Field: "code", Message: "is not valid; check the time on the device"}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE user_totp SET confirmed = 1 WHERE user_id = ?`, p.User.ID); err != nil {
			return err
		}
		if codes, err = s.replaceRecoveryCodes(ctx, tx, p.User.ID); err != nil {
			return err
		}
		if err := s.factorAdded(ctx, tx, p); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), actorEvent(p, m, "auth.totp_enable", targetUser(p.User.ID), audit.Success))
		return err
	})
	return codes, err
}

// factorAdded lifts the enrolment-only restriction and records the factor.
func (s *Service) factorAdded(ctx context.Context, tx *sql.Tx, p *Principal) error {
	now := s.nowMS()
	_, err := tx.ExecContext(ctx, `UPDATE sessions SET enrollment_only = 0, mfa_ms = ?, step_up_ms = ? WHERE id = ?`, now, now, p.Session.ID)
	return err
}

// ensureFactorsLeft refuses removing the last factor a policy or a
// passkey-only account still needs. remainingTOTP/remainingPasskeys describe
// the state after the removal.
func (s *Service) ensureFactorsLeft(ctx context.Context, tx *sql.Tx, userID int64, remainingTOTP bool, remainingPasskeys int) error {
	var pw int
	var role authz.Role
	if err := tx.QueryRowContext(ctx, `SELECT password_login, role FROM users WHERE id = ?`, userID).Scan(&pw, &role); err != nil {
		return err
	}
	if pw == 0 && remainingPasskeys == 0 {
		return ErrLastFactor
	}
	req, err := s.mfaRequired(ctx, tx, role)
	if err != nil {
		return err
	}
	if req && !remainingTOTP && remainingPasskeys == 0 {
		return ErrLastFactor
	}
	return nil
}

// DisableTOTP removes TOTP (step-up required).
func (s *Service) DisableTOTP(ctx context.Context, p *Principal, m Meta) error {
	if err := s.RequireStepUp(p); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?`, p.User.ID).Scan(&n); err != nil {
			return err
		}
		if err := s.ensureFactorsLeft(ctx, tx, p.User.ID, false, n); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM user_totp WHERE user_id = ?`, p.User.ID); err != nil {
			return err
		}
		if n == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM user_recovery_codes WHERE user_id = ?`, p.User.ID); err != nil {
				return err
			}
		}
		_, err := audit.Append(ctx, tx, s.now(), actorEvent(p, m, "auth.totp_disable", targetUser(p.User.ID), audit.Success))
		return err
	})
}

// RegenerateRecoveryCodes replaces the recovery codes (step-up required).
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, p *Principal, m Meta) ([]string, error) {
	if err := s.RequireStepUp(p); err != nil {
		return nil, err
	}
	var codes []string
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		methods, err := s.methods(ctx, tx, p.User.ID)
		if err != nil {
			return err
		}
		if len(methods) == 0 {
			return &ValidationError{Field: "recovery codes", Message: "need a second factor first"}
		}
		if codes, err = s.replaceRecoveryCodes(ctx, tx, p.User.ID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), actorEvent(p, m, "auth.recovery_codes", targetUser(p.User.ID), audit.Success))
		return err
	})
	return codes, err
}

// SetPasswordLogin switches password sign-in on or off (step-up required).
// Off needs at least one passkey (AT-F09-02).
func (s *Service) SetPasswordLogin(ctx context.Context, p *Principal, m Meta, enabled bool) error {
	if err := s.RequireStepUp(p); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if !enabled {
			var n int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM user_passkeys WHERE user_id = ?`, p.User.ID).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				return &ValidationError{Field: "password sign-in", Message: "can only be switched off with at least one passkey"}
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_login = ?, updated_ms = ? WHERE id = ?`, boolInt(enabled), s.nowMS(), p.User.ID); err != nil {
			return err
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "auth.password_login", targetUser(p.User.ID), audit.Success), "enabled", boolString(enabled)))
		return err
	})
}

// MFAPolicy maps roles to "MFA required".
type MFAPolicy map[authz.Role]bool

// GetMFAPolicy returns the policy for every role.
func (s *Service) GetMFAPolicy(ctx context.Context) (MFAPolicy, error) {
	pol := MFAPolicy{}
	for _, r := range authz.Roles() {
		req, err := s.mfaRequired(ctx, s.db, r)
		if err != nil {
			return nil, err
		}
		pol[r] = req
	}
	return pol, nil
}

// SetMFAPolicy stores the policy (AT-F09-05). Step-up is required; removing a
// requirement is audited as a downgrade.
func (s *Service) SetMFAPolicy(ctx context.Context, p *Principal, m Meta, pol MFAPolicy) error {
	if err := s.RequireStepUp(p); err != nil {
		return err
	}
	old, err := s.GetMFAPolicy(ctx)
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		var downgraded, upgraded []string
		for _, r := range authz.Roles() {
			want := pol[r]
			if want == old[r] {
				continue
			}
			if want {
				upgraded = append(upgraded, string(r))
			} else {
				downgraded = append(downgraded, string(r))
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO mfa_policy (role, required) VALUES (?, ?) ON CONFLICT (role) DO UPDATE SET required = excluded.required`,
				string(r), boolInt(want)); err != nil {
				return err
			}
		}
		if len(downgraded)+len(upgraded) == 0 {
			return nil
		}
		_, err := audit.Append(ctx, tx, s.now(), withDetails(actorEvent(p, m, "auth.mfa_policy", "mfa-policy", audit.Success),
			"required_added", strings.Join(upgraded, ","), "required_removed", strings.Join(downgraded, ","),
			"downgrade", boolString(len(downgraded) > 0)))
		return err
	})
}

// ResetMFA removes all second factors of another user and turns password
// sign-in back on (lost device). Step-up and the M2 management rules apply.
func (s *Service) ResetMFA(ctx context.Context, p *Principal, m Meta, userID int64) error {
	if err := s.RequireStepUp(p); err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		target, err := s.getUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if err := s.checkManage(ctx, tx, p, target, nil, true, false); err != nil {
			s.recordDenial(ctx, p, m, "auth.mfa_reset", targetUser(userID), err)
			return err
		}
		for _, q := range []string{`DELETE FROM user_totp WHERE user_id = ?`, `DELETE FROM user_recovery_codes WHERE user_id = ?`,
			`DELETE FROM user_passkeys WHERE user_id = ?`, `DELETE FROM sessions WHERE user_id = ?`} {
			if _, err := tx.ExecContext(ctx, q, userID); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET password_login = 1, updated_ms = ? WHERE id = ?`, s.nowMS(), userID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.now(), actorEvent(p, m, "auth.mfa_reset", targetUser(userID), audit.Success))
		return err
	})
}

// dbtx is *sql.DB or *sql.Tx.
type dbtx interface {
	QueryRowContext(ctx context.Context, q string, args ...any) *sql.Row
	ExecContext(ctx context.Context, q string, args ...any) (sql.Result, error)
}

type serviceKey struct{}

// CheckStepUp reports ErrStepUpRequired unless the request's session
// authenticated strongly within StepUpWindow. Handlers of other modules call
// it before destructive or security-relevant actions (AT-F09-04).
func CheckStepUp(ctx context.Context) error {
	s, _ := ctx.Value(serviceKey{}).(*Service)
	p, _ := FromContext(ctx)
	if s == nil {
		return ErrStepUpRequired
	}
	return s.RequireStepUp(p)
}
