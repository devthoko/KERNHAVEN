package docker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// ArchiveGet returns a tar stream of path inside the container (M16). The
// container need not be running; the caller closes the stream.
func (c *Client) ArchiveGet(ctx context.Context, ref, path string) (io.ReadCloser, error) {
	p, err := c.prefix(ctx)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, http.MethodGet, p+"/containers/"+url.PathEscape(ref)+"/archive", url.Values{"path": {path}}, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		_, err := c.decode(resp, nil)
		return nil, err
	}
	return resp.Body, nil
}

// ArchivePut extracts the tar stream r at path inside the container. The
// owners recorded in the archive are kept (mapped by the daemon's user
// namespace); copyUIDGID would instead give every file to the container's
// user.
func (c *Client) ArchivePut(ctx context.Context, ref, path string, r io.Reader) error {
	p, err := c.prefix(ctx)
	if err != nil {
		return err
	}
	q := url.Values{"path": {path}, "noOverwriteDirNonDir": {"true"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://docker"+p+"/containers/"+url.PathEscape(ref)+"/archive?"+q.Encode(), r)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-tar")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	_, err = c.decode(resp, nil)
	return err
}
