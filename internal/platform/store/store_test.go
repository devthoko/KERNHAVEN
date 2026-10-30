package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func mig(v int, name, sql string) Migration {
	sum := sha256.Sum256([]byte(sql))
	return Migration{Version: v, Name: name, SQL: sql, Checksum: hex.EncodeToString(sum[:])}
}

func dbPath(t *testing.T) string { return filepath.Join(t.TempDir(), FileName) }

func tableExists(t *testing.T, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func appliedVersions(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM schema_migrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// AT-F00-02: fresh database is migrated to the latest version.
func TestOpenFreshDatabaseAppliesEmbeddedMigrations(t *testing.T) {
	ctx := context.Background()
	db, err := Open(ctx, dbPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !tableExists(t, db, "instance") {
		t.Fatal("instance table missing")
	}
	ms, _ := LoadMigrations(embedded)
	if got := appliedVersions(t, db); got != len(ms) {
		t.Fatalf("applied %d migrations, want %d", got, len(ms))
	}
}

func TestOpenSetsRequiredPragmas(t *testing.T) {
	db, err := Open(context.Background(), dbPath(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1) // inspect the same pooled connection repeatedly
	checks := map[string]string{
		"journal_mode": "wal",
		"synchronous":  "2", // FULL
		"foreign_keys": "1",
		"busy_timeout": "5000",
	}
	for pragma, want := range checks {
		var got string
		if err := db.QueryRow("PRAGMA " + pragma).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("PRAGMA %s = %s, want %s", pragma, got, want)
		}
	}
}

// AT-F00-02: reopening is idempotent and keeps data.
func TestReopenIsIdempotentAndInstanceIDStable(t *testing.T) {
	ctx := context.Background()
	p := dbPath(t)
	db, err := Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	id1, err := EnsureInstance(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if len(id1) != 32 {
		t.Fatalf("instance id %q", id1)
	}
	db.Close()

	db, err = Open(ctx, p)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db.Close()
	id2, err := EnsureInstance(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if id1 != id2 {
		t.Fatalf("instance id changed: %s -> %s", id1, id2)
	}
}

// AT-F00-02: a modified, already applied migration aborts startup.
func TestChecksumMismatchAborts(t *testing.T) {
	ctx := context.Background()
	p := dbPath(t)
	db, err := open(ctx, p, []Migration{mig(1, "a", "CREATE TABLE a (x INTEGER);")})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = open(ctx, p, []Migration{mig(1, "a", "CREATE TABLE a (x INTEGER, y INTEGER);")})
	if !errors.Is(err, ErrChecksumMismatch) {
		t.Fatalf("err = %v, want ErrChecksumMismatch", err)
	}
}

// AT-F00-02: a database with unknown (newer) migrations aborts startup.
func TestDatabaseNewerThanBinaryAborts(t *testing.T) {
	ctx := context.Background()
	p := dbPath(t)
	db, err := open(ctx, p, []Migration{
		mig(1, "a", "CREATE TABLE a (x INTEGER);"),
		mig(2, "b", "CREATE TABLE b (x INTEGER);"),
	})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, err = open(ctx, p, []Migration{mig(1, "a", "CREATE TABLE a (x INTEGER);")})
	if !errors.Is(err, ErrDatabaseNewer) {
		t.Fatalf("err = %v, want ErrDatabaseNewer", err)
	}
}

// AT-F00-02: a failing migration leaves the database at the previous version.
func TestFailingMigrationRollsBack(t *testing.T) {
	ctx := context.Background()
	p := dbPath(t)
	m1 := mig(1, "a", "CREATE TABLE a (x INTEGER);")
	db, err := open(ctx, p, []Migration{m1})
	if err != nil {
		t.Fatal(err)
	}
	db.Close()

	// Second statement fails after the first succeeded inside the same migration.
	bad := mig(2, "b", "CREATE TABLE b (x INTEGER); INSERT INTO missing VALUES (1);")
	_, err = open(ctx, p, []Migration{m1, bad})
	if err == nil || !strings.Contains(err.Error(), "apply migration 0002_b") {
		t.Fatalf("err = %v", err)
	}

	db, err = open(ctx, p, []Migration{m1})
	if err != nil {
		t.Fatalf("reopen at previous version: %v", err)
	}
	defer db.Close()
	if tableExists(t, db, "b") {
		t.Fatal("partial migration was not rolled back")
	}
	if got := appliedVersions(t, db); got != 1 {
		t.Fatalf("applied versions = %d, want 1", got)
	}
}

func TestMultiStatementMigrationApplied(t *testing.T) {
	db, err := open(context.Background(), dbPath(t), []Migration{
		mig(1, "multi", "CREATE TABLE a (x INTEGER); CREATE TABLE b (y INTEGER);"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !tableExists(t, db, "a") || !tableExists(t, db, "b") {
		t.Fatal("not all statements executed")
	}
}

func TestCorruptDatabaseRejected(t *testing.T) {
	p := dbPath(t)
	garbage := []byte(strings.Repeat("this is not a sqlite database ", 200))
	if err := os.WriteFile(p, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(context.Background(), p)
	if !errors.Is(err, ErrIntegrity) {
		t.Fatalf("err = %v, want ErrIntegrity", err)
	}
}

func TestLoadMigrationsValidation(t *testing.T) {
	cases := map[string]fstest.MapFS{
		"bad name": {"migrations/1_init.sql": {Data: []byte("SELECT 1;")}},
		"gap":      {"migrations/0001_a.sql": {Data: []byte("")}, "migrations/0003_c.sql": {Data: []byte("")}},
		"no start": {"migrations/0002_b.sql": {Data: []byte("")}},
		"missing":  {},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadMigrations(fsys); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestEmbeddedMigrationsLoad(t *testing.T) {
	ms, err := LoadMigrations(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || ms[0].Version != 1 || ms[0].Checksum == "" {
		t.Fatalf("unexpected migrations: %+v", ms)
	}
}

// ADR-0036: migration 0016 rebuilds the backup tables to allow SMB targets.
// An upgraded database keeps its repositories, plans and snapshots, and the
// foreign keys still hold.
func TestBackupSMBMigrationKeepsData(t *testing.T) {
	ctx := context.Background()
	ms, err := LoadMigrations(embedded)
	if err != nil {
		t.Fatal(err)
	}
	p := dbPath(t)
	db, err := open(ctx, p, ms[:15])
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO backup_repos (id, name, kind, config, repo_id, data_key, verify_schedule, created_ms, updated_ms) VALUES (7, 'nas', 'sftp', '{}', 'r1', x'00', 'weekly', 1, 1)`,
		`INSERT INTO backup_plans (id, name, repo, schedule, platform, stacks, quiesce, retention, enabled, created_ms, updated_ms) VALUES (3, 'nightly', 7, 'daily', 1, '[]', 0, '{}', 1, 1, 1)`,
		`INSERT INTO backup_snapshots (repo, id, plan, created_ms, size, objects, platform, stacks) VALUES (7, 's1', 3, 1, 10, 2, 1, '[]')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	db, err = open(ctx, p, ms)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var repo, plan, snap int
	if err := db.QueryRow(`SELECT (SELECT count(*) FROM backup_repos WHERE id = 7 AND name = 'nas'), (SELECT count(*) FROM backup_plans WHERE repo = 7),
		(SELECT count(*) FROM backup_snapshots WHERE repo = 7 AND plan = 3)`).Scan(&repo, &plan, &snap); err != nil || repo != 1 || plan != 1 || snap != 1 {
		t.Fatalf("rows after migration: %d %d %d %v", repo, plan, snap, err)
	}
	rows, err := db.Query(`PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatal("foreign key violations after migration")
	}
	rows.Close()
	for _, tbl := range []string{"backup_repos_new", "backup_plans_new", "backup_snapshots_new"} {
		if tableExists(t, db, tbl) {
			t.Fatalf("%s left behind", tbl)
		}
	}
	if _, err := db.Exec(`INSERT INTO backup_repos (name, kind, config, repo_id, data_key, verify_schedule, created_ms, updated_ms) VALUES ('share', 'smb', '{}', 'r2', x'00', 'weekly', 1, 1)`); err != nil {
		t.Fatalf("smb refused: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO backup_repos (name, kind, config, repo_id, data_key, verify_schedule, created_ms, updated_ms) VALUES ('x', 'ftp', '{}', 'r3', x'00', 'weekly', 1, 1)`); err == nil {
		t.Fatal("unknown kind accepted")
	}
	// The plan still protects its repository; removing the plan cascades nothing else.
	if _, err := db.Exec(`DELETE FROM backup_repos WHERE id = 7`); err == nil {
		t.Fatal("repository with a plan was deleted")
	}
	if _, err := db.Exec(`DELETE FROM backup_plans WHERE id = 3`); err != nil {
		t.Fatal(err)
	}
	// Snapshots still go with their repository.
	if _, err := db.Exec(`DELETE FROM backup_repos WHERE id = 7`); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM backup_snapshots`).Scan(&snap); err != nil || snap != 0 {
		t.Fatalf("snapshots after repository removal: %d %v", snap, err)
	}
}
