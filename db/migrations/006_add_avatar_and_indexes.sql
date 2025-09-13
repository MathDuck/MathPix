-- Migration 006: add last_avatar_change_at column + performance indexes + backfill
-- Run once. If the column already exists you can ignore the first error.

-- 1. Add column (nullable)
ALTER TABLE users ADD COLUMN last_avatar_change_at INTEGER;

-- 2. Indexes (idempotent)
CREATE INDEX IF NOT EXISTS idx_users_last_avatar ON users(last_avatar_change_at);
CREATE INDEX IF NOT EXISTS idx_images_owner_created ON images(owner_id, created_at);
CREATE INDEX IF NOT EXISTS idx_images_created ON images(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_user_created ON audit_logs(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_type ON audit_logs(type);

-- 3. Backfill avatar change timestamp from audit logs
UPDATE users
SET last_avatar_change_at = (
    SELECT MAX(created_at) FROM audit_logs a
    WHERE a.user_id = users.id
      AND a.type IN ('User avatar updated','User avatar removed')
)
WHERE last_avatar_change_at IS NULL;

-- Optional: refresh stats
-- ANALYZE;
