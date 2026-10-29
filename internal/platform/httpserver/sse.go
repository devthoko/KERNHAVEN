package httpserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SSE writes a server-sent event stream (M6b). Each write extends the
// server's write deadline, so a stream lives as long as it delivers.
type SSE struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

// StartSSE sends the stream's headers.
func StartSSE(w http.ResponseWriter) (*SSE, error) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Accel-Buffering", "no")
	s := &SSE{w: w, rc: http.NewResponseController(w)}
	_ = s.rc.SetWriteDeadline(time.Now().Add(time.Minute))
	w.WriteHeader(http.StatusOK)
	return s, s.rc.Flush()
}

// Event sends one event with JSON data.
func (s *SSE) Event(name string, data any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return s.write(fmt.Sprintf("event: %s\ndata: %s\n\n", name, b))
}

// Comment sends a keep-alive comment.
func (s *SSE) Comment(text string) error {
	return s.write(": " + strings.ReplaceAll(text, "\n", " ") + "\n\n")
}

func (s *SSE) write(text string) error {
	_ = s.rc.SetWriteDeadline(time.Now().Add(time.Minute))
	if _, err := s.w.Write([]byte(text)); err != nil {
		return err
	}
	return s.rc.Flush()
}
