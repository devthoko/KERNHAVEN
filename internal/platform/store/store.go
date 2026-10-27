// Package store opens the SQLite database and applies schema migrations.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver (ADR-0009)
)

//go:embed migrations/*.sql
var embedded embed.FS

// FileName is the Core database file inside the data directory.
const FileName = "kernhaven.db"

// ErrIntegrity is returned when SQLite reports a corrupt database.
var ErrIntegrity = errors.New("database integrity check failed")

// Open opens the database at path with the pragmas required by ADR-0004,
// verifies its integrity and applies all embedded migrations.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	ms, err := LoadMigrations(embedded)
	if err != nil {
		return nil, err
	}
	return open(ctx, path, ms)
}

func open(ctx context.Context, path string, ms []Migration) (*sql.DB, error) {
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	if err := checkIntegrity(ctx, db); err != nil {
		db.Close()
		return nil, err
	}
	if err := Migrate(ctx, db, ms); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// dsn builds a SQLite URI. Pragmas are applied by the driver on every new
// connection; _txlock=immediate makes write transactions take the write lock
// up front, avoiding lock-upgrade deadlocks.
func dsn(path string) string {
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(FULL)")
	q.Add("_pragma", "foreign_keys(ON)")
	q.Set("_txlock", "immediate")
	u := url.URL{Scheme: "file", Path: path, RawQuery: q.Encode()}
	return u.String()
}

func checkIntegrity(ctx context.Context, db *sql.DB) error {
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&res); err != nil {
		return fmt.Errorf("%w: %v", ErrIntegrity, err)
	}
	if res != "ok" {
		return fmt.Errorf("%w: %s", ErrIntegrity, res)
	}
	return nil
}

// EnsureInstance returns the instance ID, creating it on first start.
func EnsureInstance(ctx context.Context, db *sql.DB) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO instance (id, instance_id, created_at) VALUES (1, ?, ?) ON CONFLICT (id) DO NOTHING`,
		hex.EncodeToString(b), time.Now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return "", fmt.Errorf("create instance id: %w", err)
	}
	var id string
	if err := db.QueryRowContext(ctx, `SELECT instance_id FROM instance WHERE id = 1`).Scan(&id); err != nil {
		return "", fmt.Errorf("read instance id: %w", err)
	}
	return id, nil
}
