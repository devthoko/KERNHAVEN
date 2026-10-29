// Package upgrade installs signed releases with a database snapshot taken
// first and an automatic rollback when the new version does not become
// healthy (M18, AT-F15-01..03, ADR-0032).
package upgrade

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/release"
)

// System performs the host operations; the real one runs dpkg/apt and
// systemctl with fixed arguments.
type System interface {
	InstalledVersion(ctx context.Context) (string, error)
	// Compare returns <0, 0 or >0 like dpkg --compare-versions.
	Compare(ctx context.Context, a, b string) (int, error)
	Install(ctx context.Context, deb string, downgrade bool) error
	Stop(ctx context.Context, unit string) error
	Start(ctx context.Context, unit string) error
	// Healthy waits until the Core reports ready and runs version.
	Healthy(ctx context.Context, version string, timeout time.Duration) error
}

// Core unit and files of the platform snapshot.
const (
	CoreUnit = "kernhaven-core.service"
	keep     = 3 // snapshots and old packages kept
)

var snapshotFiles = []string{"kernhaven.db", "kernhaven.db-wal", "kernhaven.db-shm", "secrets.key"}

// Upgrader applies and rolls back releases.
type Upgrader struct {
	Sys           System
	DataDir       string // /var/lib/kernhaven
	StateDir      string // /var/lib/kernhaven-upgrade
	KeysDir       string // /etc/kernhaven/release-keys
	Arch          string
	HealthTimeout time.Duration
	Out           io.Writer
	Now           func() time.Time
}

// State is what the upgrader remembers.
type State struct {
	Current  string    `json:"current"`
	Previous string    `json:"previous,omitempty"`
	Snapshot string    `json:"snapshot,omitempty"` // taken before Current was installed
	Updated  time.Time `json:"updated"`
	History  []string  `json:"history"`
}

// ErrRolledBack means the new version failed and the previous one runs again.
var ErrRolledBack = errors.New("the upgrade failed and was rolled back")

func (u *Upgrader) logf(format string, a ...any) {
	if u.Out != nil {
		fmt.Fprintf(u.Out, format+"\n", a...)
	}
}

func (u *Upgrader) now() time.Time {
	if u.Now != nil {
		return u.Now()
	}
	return time.Now()
}

func (u *Upgrader) packagePath(version string) string {
	return filepath.Join(u.StateDir, "packages", fmt.Sprintf("kernhaven_%s_%s.deb", version, u.Arch))
}

// LoadState reads the state file (empty state if none).
func (u *Upgrader) LoadState() (State, error) {
	var s State
	b, err := os.ReadFile(filepath.Join(u.StateDir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func (u *Upgrader) saveState(s State) error {
	s.Updated = u.now()
	b, _ := json.MarshalIndent(s, "", "  ")
	tmp := filepath.Join(u.StateDir, "state.json.tmp")
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(u.StateDir, "state.json"))
}

// copyFile copies src to dst keeping mode and owner (the upgrader runs as
// root; the Core's files belong to its user).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, fi.Mode().Perm())
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			err = os.Lchown(tmp, int(st.Uid), int(st.Gid))
			if errors.Is(err, os.ErrPermission) && os.Geteuid() != 0 {
				err = nil // tests run unprivileged; owners stay as they are
			}
		}
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		_ = os.Remove(tmp)
	}
	return err
}

// snapshot copies the database and the secret key while the Core is stopped.
func (u *Upgrader) snapshot(from, to string) (string, error) {
	dir := filepath.Join(u.StateDir, "snapshots", u.now().UTC().Format("20060102T150405Z")+"-"+from+"-to-"+to)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, f := range snapshotFiles {
		src := filepath.Join(u.DataDir, f)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := copyFile(src, filepath.Join(dir, f)); err != nil {
			return "", fmt.Errorf("snapshot %s: %w", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "kernhaven.db")); err != nil {
		return "", fmt.Errorf("snapshot: no database in %s", u.DataDir)
	}
	return dir, nil
}

// restore puts a snapshot back (Core stopped).
func (u *Upgrader) restore(dir string) error {
	for _, f := range snapshotFiles {
		_ = os.Remove(filepath.Join(u.DataDir, f))
	}
	for _, f := range snapshotFiles {
		src := filepath.Join(dir, f)
		if _, err := os.Stat(src); errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err := copyFile(src, filepath.Join(u.DataDir, f)); err != nil {
			return fmt.Errorf("restore %s: %w", f, err)
		}
	}
	return nil
}

// Apply installs the signed release in dir.
func (u *Upgrader) Apply(ctx context.Context, dir string, allowDowngrade bool) error {
	keys, err := release.LoadKeys(u.KeysDir)
	if err != nil {
		return err
	}
	rel, err := release.Open(dir, keys)
	if err != nil {
		return err
	}
	deb, version, err := rel.Package(u.Arch)
	if err != nil {
		return err
	}
	u.logf("verified release %s (%s)", version, rel.Comment)
	current, err := u.Sys.InstalledVersion(ctx)
	if err != nil {
		return err
	}
	cmp, err := u.Sys.Compare(ctx, version, current)
	if err != nil {
		return err
	}
	if cmp == 0 {
		return fmt.Errorf("version %s is already installed", version)
	}
	if cmp < 0 && !allowDowngrade {
		return fmt.Errorf("version %s is older than the installed %s (use rollback, or allow a downgrade)", version, current)
	}
	prev := u.packagePath(current)
	if _, err := os.Stat(prev); err != nil {
		return fmt.Errorf("the installed package %s is not in %s; without it a failed upgrade could not be rolled back (reinstall it with install.sh first)", current, filepath.Dir(prev))
	}
	st, err := u.LoadState()
	if err != nil {
		return err
	}

	u.logf("stopping the Core and taking a snapshot of the database")
	if err := u.Sys.Stop(ctx, CoreUnit); err != nil {
		return err
	}
	snap, err := u.snapshot(current, version)
	if err != nil {
		_ = u.Sys.Start(ctx, CoreUnit)
		return err
	}
	u.logf("snapshot in %s; installing %s", snap, version)
	ierr := u.Sys.Install(ctx, deb, cmp < 0)
	if ierr == nil {
		ierr = u.Sys.Healthy(ctx, version, u.HealthTimeout)
	}
	if ierr != nil {
		u.logf("version %s failed: %v — rolling back to %s", version, ierr, current)
		if err := u.rollbackTo(ctx, current, snap); err != nil {
			return fmt.Errorf("upgrade failed (%v) and the rollback failed too: %w", ierr, err)
		}
		return fmt.Errorf("%w: %v", ErrRolledBack, ierr)
	}
	if err := copyFile(deb, u.packagePath(version)); err != nil {
		return err
	}
	st.Previous, st.Current, st.Snapshot = current, version, snap
	st.History = append(st.History, fmt.Sprintf("%s %s → %s", u.now().UTC().Format(time.RFC3339), current, version))
	if err := u.saveState(st); err != nil {
		return err
	}
	u.prune(st)
	u.logf("version %s is installed and healthy", version)
	return nil
}

// rollbackTo installs the cached package of version and restores snap.
func (u *Upgrader) rollbackTo(ctx context.Context, version, snap string) error {
	if err := u.Sys.Stop(ctx, CoreUnit); err != nil {
		return err
	}
	if err := u.Sys.Install(ctx, u.packagePath(version), true); err != nil {
		return err
	}
	// The package's scripts may have started the Core on the new files.
	if err := u.Sys.Stop(ctx, CoreUnit); err != nil {
		return err
	}
	if err := u.restore(snap); err != nil {
		return err
	}
	if err := u.Sys.Start(ctx, CoreUnit); err != nil {
		return err
	}
	return u.Sys.Healthy(ctx, version, u.HealthTimeout)
}

// Rollback returns to the version before the last upgrade, with the
// database as it was then (changes made since are lost).
func (u *Upgrader) Rollback(ctx context.Context) error {
	st, err := u.LoadState()
	if err != nil {
		return err
	}
	if st.Previous == "" || st.Snapshot == "" {
		return errors.New("there is no upgrade to roll back")
	}
	current, err := u.Sys.InstalledVersion(ctx)
	if err != nil {
		return err
	}
	if current != st.Current {
		return fmt.Errorf("the installed version %s is not the one the upgrader installed (%s)", current, st.Current)
	}
	u.logf("rolling back from %s to %s with the snapshot %s", current, st.Previous, st.Snapshot)
	if err := u.rollbackTo(ctx, st.Previous, st.Snapshot); err != nil {
		return err
	}
	st.History = append(st.History, fmt.Sprintf("%s rollback %s → %s", u.now().UTC().Format(time.RFC3339), current, st.Previous))
	st.Current, st.Previous, st.Snapshot = st.Previous, "", ""
	return u.saveState(st)
}

// prune keeps the newest snapshots and the packages of the current and
// previous versions.
func (u *Upgrader) prune(st State) {
	snaps, _ := filepath.Glob(filepath.Join(u.StateDir, "snapshots", "*"))
	sort.Strings(snaps)
	for i := 0; i < len(snaps)-keep; i++ {
		if snaps[i] != st.Snapshot {
			_ = os.RemoveAll(snaps[i])
		}
	}
	pkgs, _ := filepath.Glob(filepath.Join(u.StateDir, "packages", "*.deb"))
	for _, p := range pkgs {
		v, _, ok := release.ParsePackageName(filepath.Base(p))
		if ok && v != st.Current && v != st.Previous {
			_ = os.Remove(p)
		}
	}
}

// CachePackage stores the package of a fresh install, so the first
// upgrade can be rolled back (called by install.sh after verification).
func (u *Upgrader) CachePackage(deb string) error {
	v, arch, ok := release.ParsePackageName(filepath.Base(deb))
	if !ok || arch != u.Arch {
		return fmt.Errorf("%s is not a kernhaven package for %s", filepath.Base(deb), u.Arch)
	}
	if err := os.MkdirAll(filepath.Join(u.StateDir, "packages"), 0o700); err != nil {
		return err
	}
	if err := copyFile(deb, u.packagePath(v)); err != nil {
		return err
	}
	st, err := u.LoadState()
	if err != nil {
		return err
	}
	if st.Current != v {
		if st.Current != "" {
			st.History = append(st.History, fmt.Sprintf("%s installed %s over %s", u.now().UTC().Format(time.RFC3339), v, st.Current))
		}
		st.Current, st.Previous, st.Snapshot = v, "", ""
	}
	return u.saveState(st)
}

// validVersion is used by the real System before passing versions to dpkg.
func validVersion(v string) bool {
	_, _, ok := release.ParsePackageName("kernhaven_" + v + "_amd64.deb")
	return ok && !strings.HasPrefix(v, "-")
}
