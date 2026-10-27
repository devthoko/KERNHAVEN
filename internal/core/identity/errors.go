package identity

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrInvalidCredentials is returned for unknown users, wrong passwords,
	// disabled and locked accounts alike (no account enumeration).
	ErrInvalidCredentials = errors.New("invalid credentials")
	// ErrUnauthenticated means no valid session.
	ErrUnauthenticated = errors.New("authentication required")
	// ErrForbidden means the principal lacks a permission or management right.
	ErrForbidden = errors.New("forbidden")
	// ErrNotFound means the target does not exist or is not visible.
	ErrNotFound = errors.New("not found")
	// ErrConflict means a uniqueness constraint (username) would be violated.
	ErrConflict = errors.New("conflict")
	// ErrLastOwner protects the last enabled owner.
	ErrLastOwner = errors.New("the last enabled owner cannot be demoted, disabled or deleted")
	// ErrSelf protects against users locking themselves out.
	ErrSelf = errors.New("you cannot change your own role, disable or delete yourself")
	// ErrSetupClosed means a user already exists.
	ErrSetupClosed = errors.New("setup has already been completed")
	// ErrInvalidSetupToken covers wrong and expired setup tokens.
	ErrInvalidSetupToken = errors.New("invalid or expired setup token")
)

// RateLimitError is returned when a client exceeds the attempt rate.
type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("too many attempts, retry after %s", e.RetryAfter.Round(time.Second))
}

// ValidationError reports an invalid input field.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string { return e.Field + " " + e.Message }
