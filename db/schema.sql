-- Users
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  username TEXT UNIQUE,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  disabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  avatar_key TEXT,
  last_avatar_change_at INTEGER,
  email_verified INTEGER NOT NULL DEFAULT 0
);

-- Sessions (72h TTL enforced at read)
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Images
CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY,
  owner_id TEXT,
  key TEXT NOT NULL,
  ext TEXT NOT NULL,
  content_type TEXT NOT NULL,
  original_name TEXT, -- nom de fichier source (sanitisé, longueur limitée)
  size INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  ip TEXT NOT NULL,
  last_access_at INTEGER, -- mis à jour à chaque lecture /i/:id.ext
  auto_delete_at INTEGER,
  FOREIGN KEY (owner_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_images_owner ON images(owner_id);
CREATE INDEX IF NOT EXISTS idx_images_owner_created ON images(owner_id, created_at);
CREATE INDEX IF NOT EXISTS idx_images_created ON images(created_at);
CREATE INDEX IF NOT EXISTS idx_images_ip ON images(ip);
CREATE INDEX IF NOT EXISTS idx_images_autodel ON images(auto_delete_at);
CREATE INDEX IF NOT EXISTS idx_images_last_access ON images(last_access_at);

-- IP blocks
CREATE TABLE IF NOT EXISTS ip_blocks (
  ip TEXT PRIMARY KEY,
  score INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);

-- Audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  type TEXT NOT NULL,
  user_id TEXT,
  ip TEXT,
  meta TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_logs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_logs(type);

-- Password resets
CREATE TABLE IF NOT EXISTS password_resets (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

-- Email change flow
CREATE TABLE IF NOT EXISTS email_change_requests (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  new_email TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);

-- API tokens (hashés)
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  token_plain TEXT, -- stockage optionnel du token en clair (sécurité: accès restreint)
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);

-- Captcha challenges (éphémères)
CREATE TABLE IF NOT EXISTS captcha_challenges (
  token TEXT PRIMARY KEY,
  answer_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

-- User aggregate stats (optionnel, recalcul périodique ou incrémental)
CREATE TABLE IF NOT EXISTS users_stats (
  user_id TEXT PRIMARY KEY,
  images_total INTEGER NOT NULL DEFAULT 0,
  images_today INTEGER NOT NULL DEFAULT 0,
  last_upload_at INTEGER,
  bytes_total INTEGER NOT NULL DEFAULT 0,
  last_updated_at INTEGER NOT NULL,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
CREATE INDEX IF NOT EXISTS idx_users_last_avatar ON users(last_avatar_change_at);

-- Auth throttle (rate limiting login)
CREATE TABLE IF NOT EXISTS auth_throttle (
  key TEXT PRIMARY KEY,
  fail_count INTEGER NOT NULL DEFAULT 0,
  first_fail_at INTEGER NOT NULL,
  locked_until INTEGER
);

-- Historique des tâches de maintenance (optionnel)
CREATE TABLE IF NOT EXISTS maintenance_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT NOT NULL,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  status TEXT,
  items INTEGER,
  meta TEXT
);

-- Role policies (quotas et paramètres dynamiques)
CREATE TABLE IF NOT EXISTS role_policies (
  role TEXT PRIMARY KEY,
  label TEXT,              -- Label lisible modifiable (NULL = fallback role)
  daily INTEGER,           -- NULL = illimité
  cooldown_sec INTEGER,    -- NULL = aucun cooldown
  auto_delete_sec INTEGER, -- NULL = pas de suppression auto
  updated_at INTEGER NOT NULL
);

-- Seed initial (ignore si déjà présent)
INSERT OR IGNORE INTO role_policies(role,label,daily,cooldown_sec,auto_delete_sec,updated_at) VALUES
  ('anon','Invité',10,60,NULL,strftime('%s','now')),
  ('user','Utilisateur',100,20,31536000,strftime('%s','now')),
  ('vip','VIP',NULL,NULL,NULL,strftime('%s','now')),
  ('admin','Administrateur',NULL,NULL,NULL,strftime('%s','now'));