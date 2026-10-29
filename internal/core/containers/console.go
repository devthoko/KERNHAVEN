package containers

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/identity"
	"github.com/devthoko/KERNHAVEN/internal/platform/httpserver"
)

// Console limits (AT-F02-07, ADR-0031).
const (
	ConsoleIdle     = 15 * time.Minute
	ConsolePerUser  = 2
	ConsoleTotal    = 8
	maxInput        = 4 << 10
	consoleBacklog  = 256 << 10 // output kept for a reconnecting browser
	maxFollowStream = 30 * time.Minute
)

// consoleSession is one shell in a container, owned by one user's session.
type consoleSession struct {
	id        string
	userID    int64
	sessionID string
	user      string
	container string
	shell     string
	started   time.Time

	input  *io.PipeWriter
	cancel context.CancelFunc

	mu       sync.Mutex
	backlog  []byte
	notify   chan struct{} // closed and replaced on new output
	lastUsed time.Time
	done     bool
	exitCode *int
	reason   string
	bytesIn  int64
	bytesOut int64
}

func (c *consoleSession) append(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytesOut += int64(len(data))
	c.backlog = append(c.backlog, data...)
	if over := len(c.backlog) - consoleBacklog; over > 0 {
		c.backlog = c.backlog[over:]
	}
	close(c.notify)
	c.notify = make(chan struct{})
}

func (c *consoleSession) finish(code *int, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.done, c.exitCode, c.reason = true, code, reason
	close(c.notify)
	c.notify = make(chan struct{})
}

// consoles tracks the open sessions.
type consoles struct {
	mu   sync.Mutex
	list map[string]*consoleSession
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ErrConsoleLimit means too many consoles are open.
var ErrConsoleLimit = errors.New("too many consoles are open")

func (s *Service) consoleFor(r *http.Request) (*consoleSession, bool) {
	p, ok := identity.FromContext(r.Context())
	if !ok {
		return nil, false
	}
	s.cons.mu.Lock()
	defer s.cons.mu.Unlock()
	c := s.cons.list[r.PathValue("sid")]
	// Only the browser session that opened a console can use it.
	if c == nil || c.userID != p.User.ID || c.sessionID != p.Session.ID {
		return nil, false
	}
	return c, true
}

func (s *Service) openConsole(w http.ResponseWriter, r *http.Request) {
	q := s.req(w, r)
	if err := identity.CheckStepUp(r.Context()); err != nil {
		httpserver.WriteError(w, r, http.StatusForbidden, "step_up_required", err.Error())
		return
	}
	var in struct {
		Shell string `json:"shell"`
	}
	if !decode(w, r, &in) {
		return
	}
	if s.agent == nil {
		httpserver.WriteError(w, r, http.StatusServiceUnavailable, "agent_unavailable", "no host agent is configured")
		return
	}
	id := r.PathValue("id")
	if in.Shell != "sh" && in.Shell != "bash" {
		httpserver.WriteError(w, r, http.StatusUnprocessableEntity, "validation_failed", "shell must be sh or bash")
		return
	}
	s.cons.mu.Lock()
	mine := 0
	for _, c := range s.cons.list {
		if c.userID == q.p.User.ID {
			mine++
		}
	}
	if mine >= ConsolePerUser || len(s.cons.list) >= ConsoleTotal {
		s.cons.mu.Unlock()
		q.record("container.console_open", "container:"+id, ErrConsoleLimit, "shell", in.Shell)
		httpserver.WriteError(w, r, http.StatusTooManyRequests, "too_many_consoles", ErrConsoleLimit.Error())
		return
	}
	c := &consoleSession{id: newID(), userID: q.p.User.ID, sessionID: q.p.Session.ID, user: q.actor(), container: id, shell: in.Shell, started: time.Now(), lastUsed: time.Now(), notify: make(chan struct{})}
	s.cons.list[c.id] = c // reserves the slot
	s.cons.mu.Unlock()
	release := func() {
		s.cons.mu.Lock()
		delete(s.cons.list, c.id)
		s.cons.mu.Unlock()
	}

	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background()) // outlives this request
	c.input, c.cancel = pw, cancel
	// A refusal before the handler (an invalid grant) is answered while
	// the body is still open; do not wait for it forever.
	guard := time.AfterFunc(30*time.Second, cancel)
	stream, err := s.agent.DoStream(ctx, agentclient.Call{Op: agentproto.OpContainersExec, Params: agentproto.ExecStart{ID: id, Shell: in.Shell}, Actor: q.actor(), RequestID: q.m.RequestID}, pr)
	guard.Stop()
	if err != nil {
		cancel()
		release()
		q.record("container.console_open", "container:"+id, err, "shell", in.Shell)
		writeAgentError(w, r, err)
		return
	}
	// The first line is the exec ID, or a refusal.
	sc := bufio.NewScanner(stream.Body)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	var first agentproto.StreamChunk
	if !sc.Scan() || json.Unmarshal(sc.Bytes(), &first) != nil || first.Exec == "" {
		stream.Body.Close()
		cancel()
		release()
		err := &agentclient.Error{Status: http.StatusBadRequest, Code: first.Code, Message: first.Error}
		if first.Code == "" {
			err = &agentclient.Error{Status: http.StatusBadGateway, Code: agentproto.CodeInternal, Message: "the console could not be started"}
		}
		q.record("container.console_open", "container:"+id, err, "shell", in.Shell)
		writeAgentError(w, r, err)
		return
	}
	q.record("container.console_open", "container:"+id, nil, "shell", in.Shell, "console", c.id)
	go s.runConsole(c, stream, sc, release)
	httpserver.WriteJSON(w, http.StatusCreated, map[string]any{"console": c.id, "idle_timeout_seconds": int(ConsoleIdle.Seconds())})
}

// runConsole copies the agent's output into the session until the shell
// ends, the user closes it or it is idle too long; then it records the
// session's metadata (never its content).
func (s *Service) runConsole(c *consoleSession, stream *agentclient.Stream, sc *bufio.Scanner, release func()) {
	defer release()
	defer stream.Body.Close()
	idle := time.NewTicker(time.Minute)
	defer idle.Stop()
	go func() {
		for range idle.C {
			c.mu.Lock()
			stale := !c.done && time.Since(c.lastUsed) > ConsoleIdle
			c.mu.Unlock()
			if stale {
				c.finish(nil, "idle")
				c.cancel()
				return
			}
			c.mu.Lock()
			done := c.done
			c.mu.Unlock()
			if done {
				return
			}
		}
	}()
	var code *int
	reason := "closed"
	for sc.Scan() {
		var ch agentproto.StreamChunk
		if json.Unmarshal(sc.Bytes(), &ch) != nil {
			continue
		}
		if ch.End {
			code = ch.ExitCode
			if ch.Error != "" {
				reason = ch.Error
			} else {
				reason = "exited"
			}
			break
		}
		if len(ch.Data) > 0 {
			c.append(ch.Data)
		}
	}
	c.finish(code, reason)
	c.cancel()
	_ = c.input.Close()
	c.mu.Lock()
	reason, in, out := c.reason, c.bytesIn, c.bytesOut
	c.mu.Unlock()
	exit := ""
	if code != nil {
		exit = fmt.Sprint(*code)
	}
	_ = s.audit.Record(context.Background(), audit.Event{Actor: c.user, ActorID: c.userID, Action: "container.console_close", Target: "container:" + c.container, Result: audit.Success,
		Details: map[string]string{"console": c.id, "shell": c.shell, "duration_seconds": fmt.Sprint(int(time.Since(c.started).Seconds())), "reason": reason, "exit_code": exit,
			"bytes_in": fmt.Sprint(in), "bytes_out": fmt.Sprint(out)}})
}

func (s *Service) registerConsole(rt *httpserver.Router) {
	execPerm := httpserver.RequirePermission(string(authz.ContainersExec))
	rt.HandleFunc("POST /api/v1/containers/{id}/console", execPerm, s.openConsole)
	rt.HandleFunc("GET /api/v1/consoles/{sid}/stream", execPerm, func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.consoleFor(r)
		if !ok {
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "no such console")
			return
		}
		sse, err := httpserver.StartSSE(w)
		if err != nil {
			return
		}
		sent := 0
		beat := time.NewTicker(25 * time.Second)
		defer beat.Stop()
		for {
			c.mu.Lock()
			// The backlog is trimmed from the front; send what is new.
			total := int(c.bytesOut)
			start := len(c.backlog) - (total - sent)
			if start < 0 {
				start = 0
			}
			chunk := append([]byte(nil), c.backlog[start:]...)
			sent = total
			done, code, reason, wait := c.done, c.exitCode, c.reason, c.notify
			c.mu.Unlock()
			if len(chunk) > 0 && sse.Event("output", map[string]string{"text": string(chunk)}) != nil {
				return
			}
			if done {
				_ = sse.Event("end", map[string]any{"exit_code": code, "reason": reason})
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-beat.C:
				if sse.Comment("keep-alive") != nil {
					return
				}
			case <-wait:
			}
		}
	})
	rt.HandleFunc("POST /api/v1/consoles/{sid}/input", execPerm, func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.consoleFor(r)
		if !ok {
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "no such console")
			return
		}
		var in struct {
			Text string `json:"text"`
		}
		if !decode(w, r, &in) {
			return
		}
		if len(in.Text) > maxInput {
			httpserver.WriteError(w, r, http.StatusRequestEntityTooLarge, "too_large", "input is limited to 4 KiB per request")
			return
		}
		c.mu.Lock()
		done := c.done
		c.lastUsed = time.Now()
		c.bytesIn += int64(len(in.Text))
		c.mu.Unlock()
		if done {
			httpserver.WriteError(w, r, http.StatusConflict, "console_ended", "the console has ended")
			return
		}
		if _, err := io.WriteString(c.input, in.Text); err != nil {
			httpserver.WriteError(w, r, http.StatusConflict, "console_ended", "the console has ended")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	rt.HandleFunc("DELETE /api/v1/consoles/{sid}", execPerm, func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.consoleFor(r)
		if !ok {
			httpserver.WriteError(w, r, http.StatusNotFound, "not_found", "no such console")
			return
		}
		c.finish(nil, "closed by the user")
		_ = c.input.Close() // the shell sees end of input and exits
		go func() {
			time.Sleep(5 * time.Second)
			c.cancel() // a shell ignoring end of input is stopped
		}()
		w.WriteHeader(http.StatusNoContent)
	})
	// AT-F01-05/M6b: the log of a container as it is written.
	rt.HandleFunc("GET /api/v1/containers/{id}/logs/stream", httpserver.RequirePermission(string(authz.ContainersOperate)), func(w http.ResponseWriter, r *http.Request) {
		q := s.req(w, r)
		if s.agent == nil {
			httpserver.WriteError(w, r, http.StatusServiceUnavailable, "agent_unavailable", "no host agent is configured")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), maxFollowStream)
		defer cancel()
		stream, err := s.agent.DoStream(ctx, agentclient.Call{Op: agentproto.OpContainersLogsFollow, Params: agentproto.LogsFollow{ID: r.PathValue("id"), Tail: 200}, Actor: q.actor(), RequestID: q.m.RequestID}, nil)
		if err != nil {
			writeAgentError(w, r, err)
			return
		}
		defer stream.Body.Close()
		sse, err := httpserver.StartSSE(w)
		if err != nil {
			return
		}
		sc := bufio.NewScanner(stream.Body)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			var ch agentproto.StreamChunk
			if json.Unmarshal(sc.Bytes(), &ch) != nil {
				continue
			}
			if ch.End {
				_ = sse.Event("end", map[string]string{"error": ch.Error})
				return
			}
			if sse.Event("log", map[string]string{"stream": ch.Stream, "text": string(ch.Data)}) != nil {
				return
			}
		}
		_ = sse.Event("end", map[string]string{})
	})
}
