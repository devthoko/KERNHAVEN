package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agent/docker"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// ExecStream is an attached exec instance.
type ExecStream interface {
	io.Writer
	CloseStdin() error
	Frames(emit func(docker.Frame) error) error
	ExitCode(ctx context.Context) (int, error)
	Close() error
}

// Streamer is the part of the Docker client behind log follow and the exec
// console (M6b).
type Streamer interface {
	FollowLogs(ctx context.Context, ref string, tail int, emit func(docker.Frame) error) error
	ExecStream(ctx context.Context, ref string, cmd []string) (ExecStream, string, error)
	PidMode(ctx context.Context, ref string) (string, error)
}

// DockerStreamer adapts the Docker client to Streamer.
type DockerStreamer struct{ *docker.Client }

// ExecStream starts an exec instance.
func (d DockerStreamer) ExecStream(ctx context.Context, ref string, cmd []string) (ExecStream, string, error) {
	s, err := d.Exec(ctx, ref, cmd)
	if err != nil {
		return nil, "", err
	}
	return s, s.ID, nil
}

// Limits of the streams.
const (
	MaxFollow     = 30 * time.Minute
	MaxExec       = time.Hour
	maxFollowTail = 1000
)

// shells are the only programs the console starts; the user types into
// them, the API never names a command (ADR-0031).
var shells = map[string][]string{"sh": {"/bin/sh", "-i"}, "bash": {"/bin/bash", "-i"}}

// ndjson writes one JSON line and flushes it.
type ndjson struct {
	w  http.ResponseWriter
	rc *http.ResponseController
}

func (n ndjson) send(v any) error {
	b, _ := json.Marshal(v)
	if _, err := n.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return n.rc.Flush()
}

func startNDJSON(w http.ResponseWriter) ndjson {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	n := ndjson{w: w, rc: http.NewResponseController(w)}
	_ = n.rc.Flush()
	return n
}

// checkExec refuses containers where a shell would reach the host: not
// managed by Kernhaven, privileged, sharing the host's PIDs or holding the
// Docker socket.
func checkExec(ctx context.Context, d Docker, s Streamer, id string) error {
	det, err := d.Inspect(ctx, id)
	if err != nil {
		return err
	}
	if det.Labels[LabelManaged] != "true" {
		return invalid("the console is available for containers Kernhaven manages")
	}
	if !det.Running {
		return fmt.Errorf("%w: the container is not running", docker.ErrConflict)
	}
	if det.Privileged {
		return invalid("the console is not available for privileged containers")
	}
	for _, m := range det.Mounts {
		if strings.HasSuffix(m.Source, "docker.sock") || strings.HasSuffix(m.Destination, "docker.sock") {
			return invalid("the console is not available for containers holding the Docker socket")
		}
	}
	if pm, err := s.PidMode(ctx, id); err != nil {
		return err
	} else if pm == "host" {
		return invalid("the console is not available for containers sharing the host's processes")
	}
	return nil
}

func containerStreamOperations(d Docker) map[string]streamHandler {
	s, ok := d.(Streamer)
	if dc, isClient := d.(*docker.Client); isClient {
		s, ok = DockerStreamer{dc}, true
	}
	if !ok {
		return map[string]streamHandler{}
	}
	return map[string]streamHandler{
		agentproto.OpContainersLogsFollow: func(ctx context.Context, raw json.RawMessage, _ io.Reader, w http.ResponseWriter) error {
			p, err := decode[agentproto.LogsFollow](raw)
			if err != nil {
				return err
			}
			if err := validRef(p.ID); err != nil {
				return err
			}
			if p.Tail < 0 || p.Tail > maxFollowTail {
				return invalid("tail must be 0..%d", maxFollowTail)
			}
			if _, err := d.Inspect(ctx, p.ID); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(ctx, MaxFollow)
			defer cancel()
			out := startNDJSON(w)
			err = s.FollowLogs(ctx, p.ID, p.Tail, func(f docker.Frame) error {
				return out.send(agentproto.StreamChunk{Stream: f.Stream, Data: f.Data})
			})
			_ = out.send(agentproto.StreamChunk{End: true, Error: errString(err)})
			return nil
		},
		agentproto.OpContainersExec: func(ctx context.Context, raw json.RawMessage, body io.Reader, w http.ResponseWriter) error {
			// The response starts at once: the Core sends terminal input in
			// the request body and must not wait on a refusal sent before the
			// body ends. Refusals are the first and only line.
			rc := http.NewResponseController(w)
			if err := rc.EnableFullDuplex(); err != nil {
				return err
			}
			out := startNDJSON(w)
			refuse := func(err error) error {
				code, _ := errorCode(err)
				_ = out.send(agentproto.StreamChunk{End: true, Error: err.Error(), Code: code})
				return nil
			}
			p, err := decode[agentproto.ExecStart](raw)
			if err != nil {
				return refuse(err)
			}
			if err := validRef(p.ID); err != nil {
				return refuse(err)
			}
			cmd, ok := shells[p.Shell]
			if !ok {
				return refuse(invalid("shell must be sh or bash"))
			}
			if err := checkExec(ctx, d, s, p.ID); err != nil {
				return refuse(err)
			}
			ctx, cancel := context.WithTimeout(ctx, MaxExec)
			defer cancel()
			sess, execID, err := s.ExecStream(ctx, p.ID, cmd)
			if err != nil {
				return refuse(err)
			}
			defer sess.Close()
			_ = out.send(agentproto.StreamChunk{Exec: execID})
			go func() {
				_, _ = io.Copy(sess, body) // the request body is the terminal input
				_ = sess.CloseStdin()
			}()
			var outBytes int64
			err = sess.Frames(func(f docker.Frame) error {
				outBytes += int64(len(f.Data))
				return out.send(agentproto.StreamChunk{Stream: f.Stream, Data: f.Data})
			})
			code := -1
			if c, cerr := sess.ExitCode(context.WithoutCancel(ctx)); cerr == nil {
				code = c
			}
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				err = errors.New("the session reached its time limit")
			}
			_ = out.send(agentproto.StreamChunk{End: true, ExitCode: &code, Error: errString(err), Bytes: outBytes})
			return nil
		},
	}
}
