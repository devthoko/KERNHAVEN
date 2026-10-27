package identity

import (
	"context"
	"database/sql"
	"errors"
	"net/http"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// Preferences are per-user UI settings stored server-side so they follow the
// user across devices (AT-F01-03).
type Preferences struct {
	Theme string `json:"theme"` // system | light | dark
}

// DefaultPreferences apply until a user saves their own.
var DefaultPreferences = Preferences{Theme: "system"}

func (p Preferences) validate() error {
	switch p.Theme {
	case "system", "light", "dark":
		return nil
	}
	return &ValidationError{Field: "theme", Message: "must be one of system, light, dark"}
}

// GetPreferences returns the preferences of user id.
func (s *Service) GetPreferences(ctx context.Context, id int64) (Preferences, error) {
	p := DefaultPreferences
	err := s.db.QueryRowContext(ctx, `SELECT theme FROM user_preferences WHERE user_id = ?`, id).Scan(&p.Theme)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultPreferences, nil
	}
	return p, err
}

// SetPreferences stores the preferences of user id.
func (s *Service) SetPreferences(ctx context.Context, id int64, p Preferences) (Preferences, error) {
	if err := p.validate(); err != nil {
		return Preferences{}, err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO user_preferences (user_id, theme, updated_ms) VALUES (?, ?, ?)
		ON CONFLICT (user_id) DO UPDATE SET theme = excluded.theme, updated_ms = excluded.updated_ms`,
		id, p.Theme, s.nowMS())
	return p, err
}

func (s *Service) registerPreferences(rt *httpserver.Router) {
	self := httpserver.RequirePermission(string(authz.SelfManage))
	rt.HandleFunc("GET /api/v1/auth/preferences", self, func(w http.ResponseWriter, r *http.Request) {
		p, err := s.GetPreferences(r.Context(), principal(r).User.ID)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, p)
	})
	rt.HandleFunc("PUT /api/v1/auth/preferences", self, func(w http.ResponseWriter, r *http.Request) {
		var in Preferences
		if httpserver.DecodeJSON(w, r, &in) != nil {
			return
		}
		p, err := s.SetPreferences(r.Context(), principal(r).User.ID, in)
		if err != nil {
			writeErr(w, r, err)
			return
		}
		httpserver.WriteJSON(w, http.StatusOK, p)
	})
}
