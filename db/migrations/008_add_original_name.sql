-- Colonne original_name déjà dans schema.sql -> neutralisée.
-- Pour ancienne base sans la colonne, dé-commentez:
ALTER TABLE images ADD COLUMN original_name TEXT;
