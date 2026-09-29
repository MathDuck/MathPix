-- Migration 014: compteur d'appels API par utilisateur
-- Incrémenté à chaque requête authentifiée par token API (Bearer).
-- NOTE: SQLite n'autorise pas IF NOT EXISTS sur ADD COLUMN.
-- Si la colonne existe déjà (base initialisée via schema.sql), cette migration peut échouer.

ALTER TABLE users_stats ADD COLUMN api_calls INTEGER NOT NULL DEFAULT 0;
