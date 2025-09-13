-- Migration 008: ajout colonne original_name sur images
-- Idempotent: ajoute la colonne si elle n'existe pas
ALTER TABLE images ADD COLUMN original_name TEXT;
