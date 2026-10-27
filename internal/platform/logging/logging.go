// Package logging builds the structured JSON logger used by all components.
package logging

import (
	"fmt"
	"io"
	"log/slog"
)

// New returns a JSON logger writing to w at the given level
// ("debug", "info", "warn", "error").
func New(w io.Writer, level string) (*slog.Logger, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l})), nil
}
