package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// LockFile is held by the running Core inside the data directory, so an
// offline restore cannot replace the database under it (M16).
const LockFile = "core.lock"

// ErrLocked means another process (a running Core) holds the data directory.
var ErrLocked = errors.New("the data directory is in use by a running kernhaven-core")

// LockDir takes the exclusive lock of the data directory. The lock ends
// with the process or when release is called.
func LockDir(dir string) (release func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, LockFile), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock %s: %w", dir, err)
	}
	return func() { f.Close() }, nil
}
