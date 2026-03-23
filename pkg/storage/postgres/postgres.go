// Package postgres implements the storage.Store interface using PostgreSQL
// via the standard database/sql package. The actual driver (e.g. lib/pq) is
// expected to be imported by the application main package.
package postgres

import (
	"database/sql"
	"fmt"
)

// PostgresStore wraps a *sql.DB connection to PostgreSQL and implements
// the storage.Store interface.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens a connection to PostgreSQL using the given DSN,
// verifies connectivity, and runs auto-migrations to ensure the required
// tables and indexes exist.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}

	store := &PostgresStore{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("postgres: migrate: %w", err)
	}

	return store, nil
}

// Close closes the underlying database connection.
func (s *PostgresStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// DB returns the underlying *sql.DB for advanced use cases.
func (s *PostgresStore) DB() *sql.DB {
	return s.db
}

// migrate runs CREATE TABLE IF NOT EXISTS and CREATE INDEX IF NOT EXISTS
// statements to ensure the schema is up to date.
func (s *PostgresStore) migrate() error {
	migrations := []string{
		// --- events table ---
		`CREATE TABLE IF NOT EXISTS events (
			id              TEXT PRIMARY KEY,
			timestamp       TIMESTAMPTZ NOT NULL,
			source          TEXT NOT NULL DEFAULT '',
			severity        TEXT NOT NULL DEFAULT 'info',
			actor_id        TEXT NOT NULL DEFAULT '',
			actor_name      TEXT NOT NULL DEFAULT '',
			actor_namespace TEXT NOT NULL DEFAULT '',
			provider        TEXT NOT NULL DEFAULT '',
			model           TEXT NOT NULL DEFAULT '',
			decision        TEXT NOT NULL DEFAULT '',
			blocked         BOOLEAN NOT NULL DEFAULT FALSE,
			rule_triggered  TEXT NOT NULL DEFAULT '',
			latency_ms      INT NOT NULL DEFAULT 0,
			cost_usd        REAL NOT NULL DEFAULT 0,
			session_id      TEXT NOT NULL DEFAULT '',
			raw_json        JSONB,
			created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		// --- events indexes ---
		`CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_events_severity ON events (severity)`,
		`CREATE INDEX IF NOT EXISTS idx_events_actor_id ON events (actor_id)`,

		// --- policies table ---
		`CREATE TABLE IF NOT EXISTS policies (
			name       TEXT PRIMARY KEY,
			namespace  TEXT NOT NULL DEFAULT '',
			spec       JSONB,
			mode       TEXT NOT NULL DEFAULT 'enforce',
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,

		// --- services table ---
		`CREATE TABLE IF NOT EXISTS services (
			id               TEXT PRIMARY KEY,
			name             TEXT NOT NULL DEFAULT '',
			namespace        TEXT NOT NULL DEFAULT '',
			providers        JSONB,
			risk_score       REAL NOT NULL DEFAULT 0,
			discovered_at    TIMESTAMPTZ,
			last_seen_at     TIMESTAMPTZ,
			gateway_enrolled BOOLEAN NOT NULL DEFAULT FALSE,
			raw_json         JSONB
		)`,

		// --- services indexes ---
		`CREATE INDEX IF NOT EXISTS idx_services_namespace ON services (namespace)`,

		// --- audit_log table ---
		`CREATE TABLE IF NOT EXISTS audit_log (
			id         SERIAL PRIMARY KEY,
			event_type TEXT NOT NULL DEFAULT '',
			actor      TEXT NOT NULL DEFAULT '',
			details    JSONB,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`,
	}

	for _, stmt := range migrations {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec migration: %w\nSQL: %s", err, stmt)
		}
	}

	return nil
}
