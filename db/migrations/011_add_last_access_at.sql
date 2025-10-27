-- Migration 011: ajout de last_access_at sur images + index
-- NOTE: SQLite n'autorise pas IF NOT EXISTS sur ADD COLUMN.
-- Cette migration ajoute la colonne sur les bases qui ne l'ont pas encore.
-- Si la colonne existe déjà (ex: base initialisée via schema.sql), cette migration peut échouer.
-- Appliquez-la d'abord sur les environnements sans la colonne (prod),
-- ou supprimez/neutralisez localement si vous avez déjà le schéma.

-- Ajoute la colonne (nullable)
ALTER TABLE images ADD COLUMN last_access_at INTEGER;

-- Index (idempotent si la colonne existe)
CREATE INDEX IF NOT EXISTS idx_images_last_access ON images(last_access_at);
