package backup

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/platform/netguard"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
	"github.com/devthoko/KERNHAVEN/internal/platform/store"
)

// TargetFile describes a target for `kernhaven-core restore` on a fresh
// host. For SFTP it may carry a private key file of the administrator,
// because the Core's own key is inside the backup.
type TargetFile struct {
	Kind           string          `json:"kind"`
	Config         json.RawMessage `json:"config"`
	Secret         TargetSecret    `json:"secret"`
	PrivateKeyFile string          `json:"private_key_file,omitempty"`
}

// RestoreOptions configure an offline platform restore (AT-F14-05).
type RestoreOptions struct {
	DataDir    string
	LocalRoots []string
	Guard      netguard.Guard
	Target     TargetFile
	Passphrase string
	Snapshot   string // ID or "latest"
	List       bool
	Replace    bool // replace a database that already has users
	SkipVerify bool
	Out        io.Writer
	Now        func() time.Time
}

// ReadTargetFile parses a target description strictly.
func ReadTargetFile(path string) (TargetFile, error) {
	var t TargetFile
	b, err := os.ReadFile(path)
	if err != nil {
		return t, err
	}
	if err := strictJSON(b, &t); err != nil {
		return t, err
	}
	return t, nil
}

func (o RestoreOptions) openTarget(ctx context.Context) (Target, error) {
	s := &Service{cfg: Config{LocalRoots: o.LocalRoots, Guard: o.Guard}}
	if o.Target.Kind == TargetSFTP && o.Target.Secret.Password == "" {
		cfg, err := s.normalizeConfig(TargetSFTP, o.Target.Config)
		if err != nil {
			return nil, err
		}
		var c SFTPConfig
		_ = json.Unmarshal(cfg, &c)
		if o.Target.PrivateKeyFile == "" {
			return nil, errors.New("an SFTP target needs a password or private_key_file")
		}
		pem, err := os.ReadFile(o.Target.PrivateKeyFile)
		if err != nil {
			return nil, err
		}
		return OpenSFTP(ctx, o.Guard, c, SFTPAuth{PEM: pem})
	}
	return s.openTarget(ctx, o.Target.Kind, o.Target.Config, o.Target.Secret)
}

func (o RestoreOptions) printf(format string, a ...any) {
	if o.Out != nil {
		fmt.Fprintf(o.Out, format, a...)
	}
}

// RestorePlatform restores the database and the secret key of a platform
// snapshot into DataDir while the Core is stopped (the caller holds the
// data directory lock). The restored Core then brings back the stacks'
// volumes and redeploys them on its first start.
func RestorePlatform(ctx context.Context, o RestoreOptions) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	t, err := o.openTarget(ctx)
	if err != nil {
		return err
	}
	defer t.Close()
	r, err := OpenRepo(ctx, t, o.Passphrase)
	if err != nil {
		return err
	}
	list, err := r.ListSnapshots(ctx)
	if err != nil {
		return err
	}
	var chosen *Manifest
	for i := len(list.Complete) - 1; i >= 0; i-- {
		id := list.Complete[i]
		m, err := r.ReadManifest(ctx, id)
		if err != nil {
			o.printf("%s  unreadable: %v\n", id, err)
			continue
		}
		if o.List {
			o.printf("%s  %s  plan=%q platform=%t stacks=%s size=%d\n", id, time.UnixMilli(m.CreatedMS).UTC().Format(time.RFC3339), m.Plan, m.Platform, strings.Join(manifestStacks(m), ","), m.Size())
			continue
		}
		if chosen == nil && m.Platform && (o.Snapshot == "latest" || o.Snapshot == id) {
			chosen = &m
		}
	}
	if o.List {
		return nil
	}
	if chosen == nil {
		return fmt.Errorf("no platform snapshot %q in repository %s", o.Snapshot, r.Header.ID)
	}
	m := *chosen
	dbPath := filepath.Join(o.DataDir, store.FileName)
	if !o.Replace {
		if users, err := countUsers(ctx, dbPath); err != nil {
			return err
		} else if users > 0 {
			return fmt.Errorf("%s already has %d users; pass -replace to replace this installation", dbPath, users)
		}
	}
	if !o.SkipVerify {
		o.printf("verifying snapshot %s (%d objects, %d bytes)...\n", m.ID, len(m.Objects), m.Size())
		if _, err := VerifySnapshot(ctx, r, m.ID); err != nil {
			return fmt.Errorf("snapshot %s failed verification: %w", m.ID, err)
		}
	}
	tmpDB := dbPath + ".restoring"
	tmpKey := filepath.Join(o.DataDir, secretbox.KeyFile+".restoring")
	cleanup := func() {
		for _, p := range []string{tmpDB, tmpDB + "-wal", tmpDB + "-shm", tmpKey} {
			_ = os.Remove(p)
		}
	}
	cleanup()
	defer cleanup()
	var haveDB, haveKey bool
	for _, e := range m.Objects {
		var dst string
		switch e.Kind {
		case KindDatabase:
			dst, haveDB = tmpDB, true
		case KindSecrets:
			dst, haveKey = tmpKey, true
		case KindConfig:
			dst = filepath.Join(o.DataDir, "core.toml.from-"+m.ID)
		default:
			continue
		}
		if err := writeObjectFile(ctx, r, m.ID, e, dst); err != nil {
			return err
		}
	}
	if !haveDB || !haveKey {
		return fmt.Errorf("snapshot %s lacks the database or the secret key", m.ID)
	}
	if err := prepareRestoredDB(ctx, o, r, m, tmpDB, tmpKey); err != nil {
		return err
	}
	// Keep what was there, then move the restored files into place.
	stamp := o.Now().UTC().Format("20060102T150405Z")
	keyPath := filepath.Join(o.DataDir, secretbox.KeyFile)
	for _, p := range []string{dbPath, keyPath} {
		if _, err := os.Stat(p); err == nil {
			if err := os.Rename(p, p+".before-restore-"+stamp); err != nil {
				return err
			}
		}
	}
	for _, p := range []string{dbPath + "-wal", dbPath + "-shm"} {
		_ = os.Remove(p)
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		return err
	}
	if err := os.Rename(tmpDB, dbPath); err != nil {
		return err
	}
	if d, err := os.Open(o.DataDir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	o.printf("restored the platform from snapshot %s (%s, host %s, Kernhaven %s).\n", m.ID, time.UnixMilli(m.CreatedMS).UTC().Format(time.RFC3339), m.Host, m.Kernhaven)
	o.printf("start kernhaven-core: it restores the volumes of %d stacks and redeploys them; all sessions were signed out.\n", len(m.Stacks))
	return nil
}

func countUsers(ctx context.Context, path string) (int, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	db, err := store.Open(ctx, path)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var n int
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, err
}

func writeObjectFile(ctx context.Context, r *Repo, snapshot string, e ObjectEntry, dst string) error {
	rc, err := r.OpenObject(ctx, snapshot, e)
	if err != nil {
		return err
	}
	defer rc.Close()
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(f, rc)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("%s: %w", e.Kind, err)
	}
	return nil
}

// prepareRestoredDB migrates the restored database to this version, signs
// everyone out, cancels unfinished jobs of the old host, points the
// repository at the target used now and records the pending stack restore.
func prepareRestoredDB(ctx context.Context, o RestoreOptions, r *Repo, m Manifest, path, keyPath string) error {
	db, err := store.Open(ctx, path)
	if err != nil {
		return fmt.Errorf("restored database: %w", err)
	}
	defer db.Close()
	box, err := secretbox.Open(keyPath)
	if err != nil {
		return err
	}
	s := &Service{cfg: Config{LocalRoots: o.LocalRoots, Guard: o.Guard}}
	cfg, err := s.normalizeConfig(o.Target.Kind, o.Target.Config)
	if err != nil {
		return err
	}
	sealedSecret, err := sealSecret(box, r.Header.ID, o.Target.Secret)
	if err != nil {
		return err
	}
	now := o.Now()
	err = withTx(ctx, db, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions`); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE jobs SET state = 'cancelled', outcome = 'cancelled', error = 'interrupted by a platform restore', finished_ms = ?, updated_ms = ?
			WHERE state IN ('queued', 'running', 'compensating')`, now.UnixMilli(), now.UnixMilli()); err != nil {
			return err
		}
		var id int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM backup_repos WHERE repo_id = ?`, r.Header.ID).Scan(&id)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			sealedKey, err := box.Seal(string(r.Key()), keyContext(r.Header.ID))
			if err != nil {
				return err
			}
			res, err := tx.ExecContext(ctx, `INSERT INTO backup_repos (name, kind, config, secret, repo_id, data_key, verify_schedule, created_ms, updated_ms) VALUES (?, ?, ?, ?, ?, ?, '@weekly', ?, ?)`,
				"restored-"+r.Header.ID[:8], o.Target.Kind, string(cfg), sealedSecret, r.Header.ID, sealedKey, now.UnixMilli(), now.UnixMilli())
			if err != nil {
				return err
			}
			id, _ = res.LastInsertId()
		case err != nil:
			return err
		default:
			if _, err := tx.ExecContext(ctx, `UPDATE backup_repos SET kind = ?, config = ?, secret = ?, updated_ms = ? WHERE id = ?`, o.Target.Kind, string(cfg), sealedSecret, now.UnixMilli(), id); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_restore_pending (id, repo, snapshot, created_ms) VALUES (1, ?, ?, ?)
			ON CONFLICT (id) DO UPDATE SET repo = excluded.repo, snapshot = excluded.snapshot, created_ms = excluded.created_ms`, id, m.ID, now.UnixMilli()); err != nil {
			return err
		}
		host, _ := os.Hostname()
		_, err = audit.Append(ctx, tx, now, audit.Event{Actor: "system", Action: "backup.restore_platform_offline", Target: "backup-repo:" + r.Header.ID, Result: audit.Success,
			Details: map[string]string{"snapshot": m.ID, "from_host": m.Host, "to_host": host}})
		return err
	})
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}
