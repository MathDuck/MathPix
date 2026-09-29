-- Migration 012: compteur de vues par image
-- NOTE: SQLite n'autorise pas IF NOT EXISTS sur ADD COLUMN.
-- Cette migration ajoute la colonne sur les bases qui ne l'ont pas encore.
-- Si la colonne existe déjà (ex: base initialisée via schema.sql), cette migration peut échouer.
-- Appliquez-la d'abord sur les environnements sans la colonne (prod),
-- ou neutralisez localement si vous avez déjà le schéma.

-- Ajoute la colonne (compteur de lectures réelles, hors no_track)
ALTER TABLE images ADD COLUMN views INTEGER NOT NULL DEFAULT 0;

-- Index (idempotent si la colonne existe)
CREATE INDEX IF NOT EXISTS idx_images_views ON images(views);
