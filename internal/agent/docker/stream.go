package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Frame is one chunk of a container's output (M6b).
type Frame struct {
	Stream string // stdout or stderr
	Data   []byte
}

// readFrames splits Docker's multiplexed stream (8-byte headers) into frames.
func readFrames(r io.Reader, emit func(Frame) error) error {
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(r, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := binary.BigEndian.Uint32(hdr[4:])
		if n > 1<<20 {
			return fmt.Errorf("frame of %d bytes", n)
		}
		data := make([]byte, n)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}
		stream := "stdout"
		if hdr[0] == 2 {
			stream = "stderr"
		}
		if err := emit(Frame{Stream: stream, Data: data}); err != nil {
			return err
		}
	}
}

// FollowLogs streams a container's log until ctx ends or the container
// stops. Containers with a TTY have no multiplexing; all goes to stdout.
func (c *Client) FollowLogs(ctx context.Context, ref string, tail int, emit func(Frame) error) error {
	p, err := c.prefix(ctx)
	if err != nil {
		return err
	}
	var meta struct {
		Config struct {
			Tty bool `json:"Tty"`
		} `json:"Config"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(ref)+"/json", nil, 0, &meta); err != nil {
		return err
	}
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "follow": {"1"}, "tail": {strconv.Itoa(tail)}, "timestamps": {"0"}}
	req, err := c.newRequest(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(ref)+"/logs", q, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, err := c.decode(resp, nil)
		return err
	}
	if meta.Config.Tty {
		buf := make([]byte, 32<<10)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				if eerr := emit(Frame{Stream: "stdout", Data: bytes.Clone(buf[:n])}); eerr != nil {
					return eerr
				}
			}
			if err != nil {
				if errors.Is(err, io.EOF) || ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
	err = readFrames(resp.Body, emit)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

// ExecSession is a running exec instance attached over a hijacked
// connection.
type ExecSession struct {
	ID   string
	conn net.Conn
	br   *bufio.Reader
	c    *Client
}

// Exec creates an exec instance running cmd (no TTY, stdin attached) and
// attaches to it. The caller writes stdin with Write, reads output with
// Frames and calls Close.
func (c *Client) Exec(ctx context.Context, ref string, cmd []string) (*ExecSession, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return nil, err
	}
	var created struct {
		ID string `json:"Id"`
	}
	body := map[string]any{"AttachStdin": true, "AttachStdout": true, "AttachStderr": true, "Tty": false, "Cmd": cmd}
	if _, err := c.doBody(ctx, http.MethodPost, p+"/containers/"+url.PathEscape(ref)+"/exec", nil, 0, body, &created); err != nil {
		return nil, err
	}
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	start, _ := json.Marshal(map[string]any{"Detach": false, "Tty": false})
	req := fmt.Sprintf("POST %s/exec/%s/start HTTP/1.1\r\nHost: docker\r\nContent-Type: application/json\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Length: %d\r\n\r\n%s",
		p, url.PathEscape(created.ID), len(start), start)
	_ = conn.SetDeadline(time.Now().Add(c.timeout))
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		defer conn.Close()
		_, err := c.decode(resp, nil)
		if err == nil {
			err = fmt.Errorf("%w: exec start answered %d", ErrUnavailable, resp.StatusCode)
		}
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return &ExecSession{ID: created.ID, conn: conn, br: br, c: c}, nil
}

func (c *Client) dial(ctx context.Context) (net.Conn, error) {
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr.DialContext == nil {
		return nil, errors.New("no dialer")
	}
	return tr.DialContext(ctx, "unix", "docker")
}

// Write sends stdin.
func (s *ExecSession) Write(p []byte) (int, error) { return s.conn.Write(p) }

// CloseStdin signals end of input.
func (s *ExecSession) CloseStdin() error {
	if cw, ok := s.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// Frames reads output until the process ends.
func (s *ExecSession) Frames(emit func(Frame) error) error { return readFrames(s.br, emit) }

// Close ends the attachment.
func (s *ExecSession) Close() error { return s.conn.Close() }

// ExitCode returns the process's exit code once it has ended (-1 while it
// runs).
func (s *ExecSession) ExitCode(ctx context.Context) (int, error) {
	p, err := s.c.prefix(ctx)
	if err != nil {
		return -1, err
	}
	var st struct {
		Running  bool `json:"Running"`
		ExitCode int  `json:"ExitCode"`
	}
	if _, err := s.c.do(ctx, http.MethodGet, p+"/exec/"+url.PathEscape(s.ID)+"/json", nil, 0, &st); err != nil {
		return -1, err
	}
	if st.Running {
		return -1, nil
	}
	return st.ExitCode, nil
}

// PidMode reads the container's PID namespace mode (exec into a container
// sharing the host's PIDs would reach host processes).
func (c *Client) PidMode(ctx context.Context, ref string) (string, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return "", err
	}
	var raw struct {
		HostConfig struct {
			PidMode string `json:"PidMode"`
		} `json:"HostConfig"`
	}
	if _, err := c.do(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(ref)+"/json", nil, 0, &raw); err != nil {
		return "", err
	}
	return strings.ToLower(raw.HostConfig.PidMode), nil
}
