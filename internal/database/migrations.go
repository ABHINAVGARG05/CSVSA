// Package database provides SQLite persistence for CSVSA scan results.
//
// This package implements a versioned migration system that manages schema
// evolution over time. Each migration is idempotent and can be applied
// safely multiple times.
//
// Design Philosophy:
// - Pure Go SQLite (no CGO) via modernc.org/sqlite
// - Versioned migrations for schema evolution
// - Interface-based design for testability
// - Transactions for data integrity
package database

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"
)

// Migration represents a single database schema migration.
type Migration struct {
	Version     int
	Description string
	Up          string
	Down        string
}

// migrations defines all database schema migrations in order.
var migrations = []Migration{
	{
		Version:     1,
		Description: "Create schema version tracking table",
		Up: `
			CREATE TABLE IF NOT EXISTS schema_migrations (
				version INTEGER PRIMARY KEY,
				description TEXT NOT NULL,
				applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			);
		`,
		Down: `DROP TABLE IF EXISTS schema_migrations;`,
	},
	{
		Version:     2,
		Description: "Create images table",
		Up: `
			CREATE TABLE IF NOT EXISTS images (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				name TEXT NOT NULL,
				category TEXT NOT NULL DEFAULT 'uncategorized',
				scan_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			);
			CREATE INDEX IF NOT EXISTS idx_images_name ON images(name);
			CREATE INDEX IF NOT EXISTS idx_images_category ON images(category);
		`,
		Down: `DROP TABLE IF EXISTS images;`,
	},
	{
		Version:     3,
		Description: "Create vulnerabilities table",
		Up: `
			CREATE TABLE IF NOT EXISTS vulnerabilities (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				cve_id TEXT NOT NULL,
				package TEXT NOT NULL,
				version TEXT NOT NULL,
				severity TEXT NOT NULL,
				fixed_version TEXT,
				title TEXT,
				description TEXT,
				UNIQUE(cve_id, package, version)
			);
			CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);
			CREATE INDEX IF NOT EXISTS idx_vuln_severity ON vulnerabilities(severity);
		`,
		Down: `DROP TABLE IF EXISTS vulnerabilities;`,
	},
	{
		Version:     4,
		Description: "Create scanner_findings table",
		Up: `
			CREATE TABLE IF NOT EXISTS scanner_findings (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				image_id INTEGER NOT NULL,
				vulnerability_id INTEGER NOT NULL,
				scanner_name TEXT NOT NULL,
				consensus_type TEXT NOT NULL CHECK(consensus_type IN ('consensus', 'partial', 'unique')),
				found_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
				FOREIGN KEY (image_id) REFERENCES images(id) ON DELETE CASCADE,
				FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE,
				UNIQUE(image_id, vulnerability_id, scanner_name)
			);
			CREATE INDEX IF NOT EXISTS idx_findings_image ON scanner_findings(image_id);
			CREATE INDEX IF NOT EXISTS idx_findings_consensus ON scanner_findings(consensus_type);
		`,
		Down: `DROP TABLE IF EXISTS scanner_findings;`,
	},
	{
		Version:     5,
		Description: "Create epss_scores table",
		Up: `
			CREATE TABLE IF NOT EXISTS epss_scores (
				cve_id TEXT PRIMARY KEY,
				epss_score REAL NOT NULL CHECK(epss_score >= 0 AND epss_score <= 1),
				percentile REAL NOT NULL CHECK(percentile >= 0 AND percentile <= 100),
				fetched_date DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
			);
		`,
		Down: `DROP TABLE IF EXISTS epss_scores;`,
	},
}

// Migrator handles database schema migrations.
type Migrator struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewMigrator creates a new Migrator instance.
func NewMigrator(db *sql.DB, logger *slog.Logger) *Migrator {
	if logger == nil {
		logger = slog.Default()
	}
	return &Migrator{db: db, logger: logger}
}

// Migrate applies all pending migrations.
func (m *Migrator) Migrate(ctx context.Context) error {
	m.logger.Info("starting database migration")

	currentVersion, err := m.getCurrentVersion(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current version: %w", err)
	}

	m.logger.Info("current schema version", slog.Int("version", currentVersion))

	applied := 0
	for _, migration := range migrations {
		if migration.Version <= currentVersion {
			continue
		}

		if err := m.applyMigration(ctx, migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", migration.Version, err)
		}
		applied++
	}

	if applied > 0 {
		m.logger.Info("migrations completed", slog.Int("applied", applied))
	} else {
		m.logger.Info("database schema is up to date")
	}

	return nil
}

func (m *Migrator) getCurrentVersion(ctx context.Context) (int, error) {
	var tableName string
	err := m.db.QueryRowContext(ctx,
		"SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'",
	).Scan(&tableName)

	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}

	var version int
	err = m.db.QueryRowContext(ctx,
		"SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
	).Scan(&version)

	return version, err
}

func (m *Migrator) applyMigration(ctx context.Context, migration Migration) error {
	m.logger.Info("applying migration",
		slog.Int("version", migration.Version),
		slog.String("description", migration.Description),
	)

	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if _, err = tx.ExecContext(ctx, migration.Up); err != nil {
		return fmt.Errorf("execute migration: %w", err)
	}

	if migration.Version > 1 {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
			migration.Version, migration.Description, time.Now().UTC(),
		)
		if err != nil {
			return fmt.Errorf("record migration: %w", err)
		}
	}

	return tx.Commit()
}
