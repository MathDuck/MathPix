-- Migration 009: create & seed role_policies
CREATE TABLE IF NOT EXISTS role_policies (
  role TEXT PRIMARY KEY,
  daily INTEGER,
  cooldown_sec INTEGER,
  auto_delete_sec INTEGER,
  updated_at INTEGER NOT NULL
);

-- Seed de base (ignore si existe déjà)
INSERT OR IGNORE INTO role_policies(role,daily,cooldown_sec,auto_delete_sec,updated_at) VALUES
  ('anon',10,60,NULL,strftime('%s','now')),
  ('user',100,20,31536000,strftime('%s','now')),
  ('vip',NULL,NULL,NULL,strftime('%s','now')),
  ('admin',NULL,NULL,NULL,strftime('%s','now'));
