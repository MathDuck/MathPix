-- Migration 001 (neutralisée pour compat avec schema.sql qui inclut déjà username)
-- Colonne username déjà présente dans schema.sql actuel.
-- Si vous partez d'une DB AVANT cette colonne, dé-commentez la ligne suivante:
-- ALTER TABLE users ADD COLUMN username TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
