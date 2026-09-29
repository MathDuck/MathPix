-- Migration 013: colonne via_api sur images
-- Évite le N+1 (une requête audit_logs par image) dans les listes admin.
-- NOTE: SQLite n'autorise pas IF NOT EXISTS sur ADD COLUMN.
-- Si la colonne existe déjà (base initialisée via schema.sql), cette migration peut échouer.

ALTER TABLE images ADD COLUMN via_api INTEGER NOT NULL DEFAULT 0;

-- Backfill depuis les audit_logs d'upload existants
UPDATE images SET via_api = 1
WHERE id IN (
  SELECT DISTINCT json_extract(a.meta, '$.id')
  FROM audit_logs a
  WHERE a.type = 'upload'
    AND json_extract(a.meta, '$.via_api') = 1
    AND json_extract(a.meta, '$.id') IS NOT NULL
);
