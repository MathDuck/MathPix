-- Migration 001: create maintenance_runs table
-- Idempotent: uses IF NOT EXISTS
CREATE TABLE IF NOT EXISTS maintenance_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT,
  items INTEGER,
  meta TEXT
);

-- Indexes (optional performance)
CREATE INDEX IF NOT EXISTS idx_maintenance_runs_task ON maintenance_runs(task);
CREATE INDEX IF NOT EXISTS idx_maintenance_runs_started ON maintenance_runs(started_at);
