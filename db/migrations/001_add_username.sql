-- Ajout colonne username (nullable) + index unique si pas déjà présent
ALTER TABLE users ADD COLUMN username TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username);
